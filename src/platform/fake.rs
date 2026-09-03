use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::capability::{BackendKind, Capabilities};
use crate::config::{DnsConfig, DnsScope, InterfaceSelector};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::{DnsSuffix, NormalizedConfig};
use crate::ownership::ResourceId;
use crate::platform::{ApplyReceipt, Backend, PlatformSnapshot};
use crate::watch::{DnsEvent, WatchCallback, WatchHandle};

/// The fake backend's representation of one resource's DNS state.
///
/// It contains exactly the managed fields, so semantic equality is plain
/// equality. Real backends carry additional unmanaged native state and must
/// define equality over the managed fields only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FakeState {
    /// No DNS configuration present.
    #[default]
    Empty,
    /// A DNS configuration is present.
    Configured {
        /// Nameservers, in preference order.
        nameservers: Vec<IpAddr>,
        /// Search domains.
        search_domains: Vec<DnsSuffix>,
        /// Routing domains.
        routing_domains: Vec<DnsSuffix>,
        /// Default-route flag.
        default_route: Option<bool>,
    },
}

/// Merges a plan onto existing state, preserving `default_route` when the
/// plan leaves it unspecified (`None`).
fn merge_state(current: &FakeState, plan: &NormalizedConfig) -> FakeState {
    let default_route = match plan.default_route {
        Some(value) => Some(value),
        None => match current {
            FakeState::Configured { default_route, .. } => *default_route,
            FakeState::Empty => None,
        },
    };
    let merged = NormalizedConfig {
        nameservers: plan.nameservers.clone(),
        search_domains: plan.search_domains.clone(),
        routing_domains: plan.routing_domains.clone(),
        default_route,
    };
    if merged.nameservers.is_empty()
        && merged.search_domains.is_empty()
        && merged.routing_domains.is_empty()
        && merged.default_route.is_none()
    {
        FakeState::Empty
    } else {
        FakeState::Configured {
            nameservers: merged.nameservers,
            search_domains: merged.search_domains,
            routing_domains: merged.routing_domains,
            default_route: merged.default_route,
        }
    }
}

/// Whether a stored state already expresses a plan, ignoring `default_route`
/// when the plan leaves it unspecified.
fn state_matches(state: &FakeState, plan: &NormalizedConfig) -> bool {
    match state {
        FakeState::Empty => {
            plan.nameservers.is_empty()
                && plan.search_domains.is_empty()
                && plan.routing_domains.is_empty()
                && plan.default_route.is_none()
        }
        FakeState::Configured {
            nameservers,
            search_domains,
            routing_domains,
            default_route,
        } => {
            *nameservers == plan.nameservers
                && *search_domains == plan.search_domains
                && *routing_domains == plan.routing_domains
                && match plan.default_route {
                    Some(wanted) => *default_route == Some(wanted),
                    None => true,
                }
        }
    }
}

impl From<&NormalizedConfig> for FakeState {
    fn from(plan: &NormalizedConfig) -> Self {
        if plan.nameservers.is_empty()
            && plan.search_domains.is_empty()
            && plan.routing_domains.is_empty()
            && plan.default_route.is_none()
        {
            Self::Empty
        } else {
            Self::Configured {
                nameservers: plan.nameservers.clone(),
                search_domains: plan.search_domains.clone(),
                routing_domains: plan.routing_domains.clone(),
                default_route: plan.default_route,
            }
        }
    }
}

impl From<&DnsConfig> for FakeState {
    fn from(config: &DnsConfig) -> Self {
        Self::from(&NormalizedConfig {
            nameservers: config.nameservers().to_vec(),
            search_domains: config.search_domains().to_vec(),
            routing_domains: config.routing_domains().to_vec(),
            default_route: config.default_route(),
        })
    }
}

/// Which backend operation to fail when injecting faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FakeOp {
    /// Fail capture.
    Capture,
    /// Fail apply.
    Apply,
    /// Fail read-back.
    Readback,
    /// Fail restore.
    Restore,
}

struct FakeInner {
    interfaces: Vec<InterfaceInfo>,
    states: BTreeMap<ResourceId, FakeState>,
    failures: Vec<(FakeOp, u32, u32, String)>,
    readback_lie: Option<FakeState>,
}

type WatchSlot = Option<(Arc<AtomicBool>, WatchCallback)>;

/// An in-memory backend modelling an operating system's DNS state.
///
/// It participates fully in the transaction engine: resource resolution,
/// snapshots, apply, read-back, restore, watching, and failure injection.
/// Tests drive it through [`crate::testing::FakeDns`].
pub(crate) struct FakeBackend {
    multi_resource: bool,
    caps: Capabilities,
    inner: Mutex<FakeInner>,
    watch_slot: Arc<Mutex<WatchSlot>>,
}

impl FakeBackend {
    pub(crate) fn new() -> Self {
        Self::with_capabilities(
            Capabilities::new(BackendKind::Fake)
                .with_read(true)
                .with_global_dns(true)
                .with_per_interface_dns(true)
                .with_search_domains(true)
                .with_split_dns(true)
                .with_default_route(true)
                .with_watch(true)
                .with_cache_flush(true),
        )
    }

    pub(crate) fn with_capabilities(caps: Capabilities) -> Self {
        Self::build(caps, false)
    }

    /// Enables split-resource resolution: interface scopes additionally
    /// resolve to one `fake:resolver:<domain>` resource per routing domain,
    /// mirroring the macOS backend shape. Used by the multi-resource engine
    /// tests.
    pub(crate) fn with_multi_resource(caps: Capabilities) -> Self {
        Self::build(caps, true)
    }

    fn build(caps: Capabilities, multi_resource: bool) -> Self {
        let interfaces = vec![
            InterfaceInfo {
                index: 1,
                name: OsString::from("eth0"),
                friendly_name: Some("Ethernet".to_string()),
                guid: None,
                is_up: true,
            },
            InterfaceInfo {
                index: 2,
                name: OsString::from("wlan1"),
                friendly_name: Some("Wi-Fi".to_string()),
                guid: None,
                is_up: true,
            },
        ];
        let mut states = BTreeMap::new();
        states.insert(Self::global_id(), FakeState::Empty);
        for iface in &interfaces {
            states.insert(Self::interface_id(iface.index), FakeState::Empty);
        }
        Self {
            caps,
            inner: Mutex::new(FakeInner {
                interfaces,
                states,
                failures: Vec::new(),
                readback_lie: None,
            }),
            watch_slot: Arc::new(Mutex::new(None)),
            multi_resource,
        }
    }

    pub(crate) fn resolver_id(domain: &str) -> ResourceId {
        ResourceId::new(format!("fake:resolver:{domain}")).expect("statically valid resource id")
    }

    pub(crate) fn global_id() -> ResourceId {
        ResourceId::new("fake:global").expect("statically valid resource id")
    }

    pub(crate) fn interface_id(index: u32) -> ResourceId {
        ResourceId::new(format!("fake:interface:{index}")).expect("statically valid resource id")
    }

    fn lock_inner(&self) -> MutexGuard<'_, FakeInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn external_change(&self, resource: &ResourceId, state: FakeState) {
        self.lock_inner().states.insert(resource.clone(), state);
        self.notify(DnsEvent::ResourceChanged {
            resource: resource.clone(),
        });
    }

    pub(crate) fn external_remove(&self, resource: &ResourceId) -> bool {
        let mut removed = false;
        {
            let mut inner = self.lock_inner();
            if let Some(pos) = inner
                .interfaces
                .iter()
                .position(|i| Self::interface_id(i.index) == *resource)
            {
                inner.interfaces.remove(pos);
                removed = true;
            }
            removed |= inner.states.remove(resource).is_some();
        }
        if removed {
            self.notify(DnsEvent::ResourceRemoved {
                resource: resource.clone(),
            });
        }
        removed
    }

    pub(crate) fn state_of(&self, resource: &ResourceId) -> Option<FakeState> {
        self.lock_inner().states.get(resource).cloned()
    }

    pub(crate) fn inject_failure(&self, op: FakeOp, times: u32, message: impl Into<String>) {
        self.inject_failure_after(op, 0, times, message);
    }

    pub(crate) fn inject_failure_after(
        &self,
        op: FakeOp,
        skip: u32,
        times: u32,
        message: impl Into<String>,
    ) {
        assert!(times > 0);
        self.lock_inner()
            .failures
            .push((op, skip, times, message.into()));
    }

    pub(crate) fn lie_once_on_readback(&self, state: FakeState) {
        self.lock_inner().readback_lie = Some(state);
    }

    pub(crate) fn notify(&self, event: DnsEvent) {
        let slot = self
            .watch_slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some((flag, callback)) = slot
            && !flag.load(Ordering::Acquire)
        {
            callback(&event);
        }
    }

    fn check_failure(&self, op: FakeOp) -> Result<()> {
        let mut inner = self.lock_inner();
        if let Some(pos) = inner.failures.iter().position(|(o, _, _, _)| *o == op) {
            let (_, skip, times, message) = &mut inner.failures[pos];
            if *skip > 0 {
                *skip -= 1;
                return Ok(());
            }
            *times -= 1;
            let message = message.clone();
            let spent = *times == 0;
            if spent {
                inner.failures.remove(pos);
            }
            drop(inner);
            return Err(Error::platform(
                BackendKind::Fake,
                format_args!("injected backend failure: {message}"),
            ));
        }
        Ok(())
    }

    fn snapshot_of(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let state = self
            .lock_inner()
            .states
            .get(resource)
            .cloned()
            .ok_or_else(|| {
                Error::BackendUnavailable(format!(
                    "resource {resource} is not present on this system"
                ))
            })?;
        let data = serde_json::to_value(&state).map_err(|e| {
            Error::platform(
                BackendKind::Fake,
                format_args!("fake state serialization failed: {e}"),
            )
        })?;
        Ok(PlatformSnapshot::new(
            BackendKind::Fake,
            resource.clone(),
            data,
        ))
    }

    fn interpret(&self, snapshot: &PlatformSnapshot) -> Result<FakeState> {
        if snapshot.backend != BackendKind::Fake {
            return Err(Error::platform(
                BackendKind::Fake,
                format_args!(
                    "snapshot belongs to backend {} and cannot be interpreted here",
                    snapshot.backend
                ),
            ));
        }
        serde_json::from_value(snapshot.data.clone()).map_err(|e| {
            Error::platform(
                BackendKind::Fake,
                format_args!("snapshot data cannot be interpreted by this backend: {e}"),
            )
        })
    }
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for FakeBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Fake
    }

    fn capabilities(&self) -> Capabilities {
        self.caps.clone()
    }

    fn resolve_resources(
        &self,
        scope: &DnsScope,
        plan: &NormalizedConfig,
    ) -> Result<Vec<ResourceId>> {
        let mut inner = self.lock_inner();
        let base = match scope {
            DnsScope::Global => return Ok(vec![Self::global_id()]),
            DnsScope::Interface(InterfaceSelector::Default) => {
                let index = inner
                    .interfaces
                    .iter()
                    .map(|i| i.index)
                    .min()
                    .ok_or_else(|| Error::invalid_config("no interfaces are available"))?;
                Self::interface_id(index)
            }
            DnsScope::Interface(InterfaceSelector::Index(index)) => {
                if !inner.interfaces.iter().any(|i| i.index == *index) {
                    return Err(Error::invalid_config(format_args!(
                        "interface with index {index} does not exist"
                    )));
                }
                Self::interface_id(*index)
            }
            DnsScope::Interface(InterfaceSelector::Name(name)) => {
                let iface = inner
                    .interfaces
                    .iter()
                    .find(|i| &i.name == name)
                    .ok_or_else(|| {
                        Error::invalid_config(format_args!(
                            "interface named {name:?} does not exist"
                        ))
                    })?;
                Self::interface_id(iface.index)
            }
        };
        if !self.multi_resource {
            return Ok(vec![base]);
        }
        let mut resources = vec![base];
        for domain in &plan.routing_domains {
            let resolver = Self::resolver_id(domain.as_str());
            inner.states.entry(resolver.clone()).or_default();
            resources.push(resolver);
        }
        if plan.default_route == Some(true) {
            let root = Self::resolver_id(".");
            inner.states.entry(root.clone()).or_default();
            if !resources.contains(&root) {
                resources.push(root);
            }
        }
        Ok(resources)
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        Ok(self.lock_inner().interfaces.clone())
    }

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        self.check_failure(FakeOp::Capture)?;
        self.snapshot_of(resource)
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        self.check_failure(FakeOp::Apply)?;
        {
            let mut inner = self.lock_inner();
            let current = inner.states.get(resource).cloned().ok_or_else(|| {
                Error::BackendUnavailable(format!(
                    "resource {resource} is not present on this system"
                ))
            })?;
            // `None` preserves the current default-route value; only
            // `Some(_)` may change it.
            inner
                .states
                .insert(resource.clone(), merge_state(&current, plan));
        }
        self.notify(DnsEvent::ResourceChanged {
            resource: resource.clone(),
        });
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        self.check_failure(FakeOp::Readback)?;
        let lie = self.lock_inner().readback_lie.take();
        match lie {
            Some(state) => {
                let data = serde_json::to_value(&state).map_err(|e| {
                    Error::platform(
                        BackendKind::Fake,
                        format_args!("fake state serialization failed: {e}"),
                    )
                })?;
                Ok(PlatformSnapshot::new(
                    BackendKind::Fake,
                    resource.clone(),
                    data,
                ))
            }
            None => self.snapshot_of(resource),
        }
    }

    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        self.check_failure(FakeOp::Restore)?;
        if snapshot.resource != *resource {
            return Err(Error::platform(
                BackendKind::Fake,
                format_args!(
                    "snapshot for resource {} cannot be restored onto {resource}",
                    snapshot.resource
                ),
            ));
        }
        let state = self.interpret(snapshot)?;
        {
            let mut inner = self.lock_inner();
            if !inner.states.contains_key(resource) {
                return Err(Error::BackendUnavailable(format!(
                    "resource {resource} is not present on this system"
                )));
            }
            inner.states.insert(resource.clone(), state);
        }
        self.notify(DnsEvent::ResourceChanged {
            resource: resource.clone(),
        });
        Ok(())
    }

    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        match (self.interpret(a), self.interpret(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool {
        match self.interpret(snapshot) {
            Ok(state) => state_matches(&state, plan),
            Err(_) => false,
        }
    }

    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
        let state = self.interpret(snapshot)?;
        let (nameservers, search_domains, routing_domains, default_route) = match state {
            FakeState::Empty => (Vec::new(), Vec::new(), Vec::new(), None),
            FakeState::Configured {
                nameservers,
                search_domains,
                routing_domains,
                default_route,
            } => (nameservers, search_domains, routing_domains, default_route),
        };
        Ok(DnsConfig::from_parts(
            scope.clone(),
            nameservers,
            search_domains,
            routing_domains,
            default_route,
        ))
    }

    fn start_watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        if !self.caps.watch {
            return Err(Error::unsupported(
                BackendKind::Fake,
                "watching is disabled for this fake backend",
            ));
        }
        let flag = Arc::new(AtomicBool::new(false));
        {
            let mut slot = self
                .watch_slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *slot = Some((Arc::clone(&flag), callback));
        }
        let slot = Arc::clone(&self.watch_slot);
        Ok(WatchHandle::new(flag, move || {
            *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }))
    }
}
