use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::capability::{BackendKind, Capabilities, MutationGuard, OwnershipIdentity};
use crate::config::{DnsConfig, DnsScope, InterfaceSelector};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::{DnsSuffix, NormalizedConfig};
use crate::ownership::ResourceId;
use crate::platform::{ApplyReceipt, Backend, MutationAttempt, PlatformSnapshot};
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
    /// Generation bumped on every mutation; snapshots carry the generation
    /// they were captured at for atomic guarded operations.
    generations: BTreeMap<ResourceId, u64>,
    failures: Vec<(FakeOp, u32, u32, String)>,
    readback_lie: Option<FakeState>,
    /// Pending mutate-then-fail applies (see
    /// [`FakeBackend::inject_partial_apply_failure`]).
    partial_apply_failures: u32,
    before_guarded: Option<(ResourceId, FakeState)>,
    after_guarded: Option<(ResourceId, FakeState)>,
    before_nth_guarded: Option<(u32, ResourceId, FakeState)>,
}

/// Wire format of a fake snapshot: the managed state plus the generation
/// the snapshot was captured at.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FakeSnapshotData {
    state: FakeState,
    generation: u64,
}

type WatchEntry = (Arc<AtomicBool>, WatchCallback);

/// An in-memory backend modelling an operating system's DNS state.
///
/// It participates fully in the transaction engine: resource resolution,
/// snapshots, apply, read-back, restore, watching, and failure injection.
/// Tests drive it through [`crate::testing::FakeDns`].
pub(crate) struct FakeBackend {
    multi_resource: bool,
    caps: Capabilities,
    inner: Mutex<FakeInner>,
    watchers: Arc<Mutex<Vec<WatchEntry>>>,
    /// Ownership universe of this simulated OS instance, shared by every
    /// manager built around the same [`crate::testing::FakeDns`].
    namespace: String,
    start_watch_block: Mutex<Option<std::sync::Arc<std::sync::Barrier>>>,
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
                .with_cache_flush(true)
                .with_mutation_guard(MutationGuard::CompareAndMutate)
                .with_ownership_identity(OwnershipIdentity::Durable),
        )
    }

    pub(crate) fn with_capabilities(caps: Capabilities) -> Self {
        Self::build(
            caps.with_mutation_guard(MutationGuard::CompareAndMutate)
                .with_ownership_identity(OwnershipIdentity::Durable),
            false,
        )
    }

    /// Enables split-resource resolution: interface scopes additionally
    /// resolve to one `fake:resolver:<domain>` resource per routing domain,
    /// mirroring the macOS backend shape. Used by the multi-resource engine
    /// tests.
    pub(crate) fn with_multi_resource(caps: Capabilities) -> Self {
        Self::build(
            caps.with_mutation_guard(MutationGuard::CompareAndMutate)
                .with_ownership_identity(OwnershipIdentity::Durable),
            true,
        )
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
            caps: caps.with_mutation_guard(MutationGuard::CompareAndMutate),
            inner: Mutex::new(FakeInner {
                interfaces,
                states,
                generations: BTreeMap::new(),
                failures: Vec::new(),
                readback_lie: None,
                partial_apply_failures: 0,
                before_guarded: None,
                after_guarded: None,
                before_nth_guarded: None,
            }),
            watchers: Arc::new(Mutex::new(Vec::new())),
            multi_resource,
            namespace: format!("osdns:fake:{}", uuid::Uuid::new_v4().simple()),
            start_watch_block: Mutex::new(None),
        }
    }

    pub(crate) fn lock_namespace(&self) -> &str {
        &self.namespace
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
        {
            let mut inner = self.lock_inner();
            inner.states.insert(resource.clone(), state);
            *inner.generations.entry(resource.clone()).or_insert(0) += 1;
        }
        self.notify(DnsEvent::ResourceChanged {
            resource: resource.clone(),
        });
    }

    /// Makes the next `times` applies mutate the resource and then fail,
    /// modelling a backend that partially mutates before returning `Err`.
    pub(crate) fn inject_partial_apply_failure(&self, times: u32) {
        self.lock_inner().partial_apply_failures += times;
    }

    pub(crate) fn inject_external_before_guarded(&self, resource: ResourceId, state: FakeState) {
        self.lock_inner().before_guarded = Some((resource, state));
    }

    pub(crate) fn inject_external_after_guarded_mutation(
        &self,
        resource: ResourceId,
        state: FakeState,
    ) {
        self.lock_inner().after_guarded = Some((resource, state));
    }

    pub(crate) fn inject_external_before_nth_guarded(
        &self,
        skip: u32,
        resource: ResourceId,
        state: FakeState,
    ) {
        self.lock_inner().before_nth_guarded = Some((skip, resource, state));
    }

    /// Blocks the next [`Backend::start_watch`] until the returned release
    /// function is called.
    pub(crate) fn block_next_start_watch(&self) -> impl FnOnce() + Send {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        *self
            .start_watch_block
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(std::sync::Arc::clone(&barrier));
        move || {
            barrier.wait();
        }
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

    pub(crate) fn generation_of(&self, resource: &ResourceId) -> Option<u64> {
        self.lock_inner().generations.get(resource).copied()
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
        let watchers = self
            .watchers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        for (flag, callback) in watchers {
            if !flag.load(Ordering::Acquire) {
                callback(&event);
            }
        }
    }

    fn snapshot_from(inner: &FakeInner, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let state = inner.states.get(resource).cloned().ok_or_else(|| {
            Error::BackendUnavailable(format!("resource {resource} is not present on this system"))
        })?;
        let generation = inner.generations.get(resource).copied().unwrap_or(0);
        let data = serde_json::to_value(&FakeSnapshotData { state, generation }).map_err(|e| {
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

    fn take_adversary(inner: &mut FakeInner, before: bool, resource: &ResourceId) {
        let pending = if before {
            inner.before_guarded.take()
        } else {
            inner.after_guarded.take()
        };
        if let Some((wanted, state)) = pending {
            if wanted == *resource {
                inner.states.insert(resource.clone(), state);
                *inner.generations.entry(resource.clone()).or_insert(0) += 1;
            } else if before {
                inner.before_guarded = Some((wanted, state));
            } else {
                inner.after_guarded = Some((wanted, state));
            }
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
        let inner = self.lock_inner();
        let state = inner.states.get(resource).cloned().ok_or_else(|| {
            Error::BackendUnavailable(format!("resource {resource} is not present on this system"))
        })?;
        let generation = inner.generations.get(resource).copied().unwrap_or(0);
        let data = serde_json::to_value(&FakeSnapshotData { state, generation }).map_err(|e| {
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
        Ok(self.interpret_full(snapshot)?.state)
    }

    fn interpret_full(&self, snapshot: &PlatformSnapshot) -> Result<FakeSnapshotData> {
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
        let partial = {
            let mut inner = self.lock_inner();
            if inner.partial_apply_failures > 0 {
                inner.partial_apply_failures -= 1;
                true
            } else {
                false
            }
        };
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
            *inner.generations.entry(resource.clone()).or_insert(0) += 1;
        }
        self.notify(DnsEvent::ResourceChanged {
            resource: resource.clone(),
        });
        if partial {
            return Err(Error::platform(
                BackendKind::Fake,
                format_args!("injected partial mutation before failure"),
            ));
        }
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        self.check_failure(FakeOp::Readback)?;
        let lie = self.lock_inner().readback_lie.take();
        match lie {
            Some(state) => {
                let generation = self
                    .lock_inner()
                    .generations
                    .get(resource)
                    .copied()
                    .unwrap_or(0);
                let data =
                    serde_json::to_value(&FakeSnapshotData { state, generation }).map_err(|e| {
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
            *inner.generations.entry(resource.clone()).or_insert(0) += 1;
        }
        self.notify(DnsEvent::ResourceChanged {
            resource: resource.clone(),
        });
        Ok(())
    }

    /// Check and mutation happen under one lock acquisition.
    fn apply_guarded(
        &self,
        resource: &ResourceId,
        expected: &PlatformSnapshot,
        plan: &NormalizedConfig,
    ) -> MutationAttempt {
        {
            let mut inner = self.lock_inner();
            if let Some((skip, id, state)) = inner.before_nth_guarded.take() {
                if skip == 0 {
                    inner.states.insert(id.clone(), state);
                    *inner.generations.entry(id).or_insert(0) += 1;
                } else {
                    inner.before_nth_guarded = Some((skip - 1, id, state));
                }
            }
        }
        if let Err(error) = self.check_failure(FakeOp::Apply) {
            return MutationAttempt::Indeterminate {
                error,
                produced: None,
            };
        }
        let expected_full = match self.interpret_full(expected) {
            Ok(full) => full,
            Err(error) => {
                return MutationAttempt::Indeterminate {
                    error,
                    produced: None,
                };
            }
        };
        let (partial, produced) = {
            let mut inner = self.lock_inner();
            Self::take_adversary(&mut inner, true, resource);
            let live_state = match inner.states.get(resource).cloned() {
                Some(state) => state,
                None => {
                    return MutationAttempt::Indeterminate {
                        error: Error::BackendUnavailable(format!(
                            "resource {resource} is not present on this system"
                        )),
                        produced: None,
                    };
                }
            };
            let live_generation = inner.generations.get(resource).copied().unwrap_or(0);
            if live_generation != expected_full.generation || live_state != expected_full.state {
                return MutationAttempt::Rejected {
                    error: Error::ExternalModification {
                        resource: resource.clone(),
                        detail: "the current state changed since ownership was verified"
                            .to_string(),
                    },
                };
            }
            inner
                .states
                .insert(resource.clone(), merge_state(&live_state, plan));
            *inner.generations.entry(resource.clone()).or_insert(0) += 1;
            let produced = match Self::snapshot_from(&inner, resource) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return MutationAttempt::Indeterminate {
                        error,
                        produced: None,
                    };
                }
            };
            let partial = if inner.partial_apply_failures > 0 {
                inner.partial_apply_failures -= 1;
                true
            } else {
                false
            };
            Self::take_adversary(&mut inner, false, resource);
            (partial, produced)
        };
        self.notify(DnsEvent::ResourceChanged {
            resource: resource.clone(),
        });
        if partial {
            MutationAttempt::Indeterminate {
                error: Error::platform(
                    BackendKind::Fake,
                    format_args!("injected partial mutation before failure"),
                ),
                produced: Some(produced),
            }
        } else {
            MutationAttempt::Performed {
                produced: Some(produced),
            }
        }
    }

    fn restore_guarded(
        &self,
        resource: &ResourceId,
        expected: &PlatformSnapshot,
        target: &PlatformSnapshot,
    ) -> MutationAttempt {
        if let Err(error) = self.check_failure(FakeOp::Restore) {
            return MutationAttempt::Indeterminate {
                error,
                produced: None,
            };
        }
        if expected.resource != *resource || target.resource != *resource {
            return MutationAttempt::Indeterminate {
                error: Error::platform(
                    BackendKind::Fake,
                    format_args!("snapshot resource mismatch for {resource}"),
                ),
                produced: None,
            };
        }
        let expected_full = match self.interpret_full(expected) {
            Ok(full) => full,
            Err(error) => {
                return MutationAttempt::Indeterminate {
                    error,
                    produced: None,
                };
            }
        };
        let target_state = match self.interpret(target) {
            Ok(state) => state,
            Err(error) => {
                return MutationAttempt::Indeterminate {
                    error,
                    produced: None,
                };
            }
        };
        let produced = {
            let mut inner = self.lock_inner();
            Self::take_adversary(&mut inner, true, resource);
            if !inner.states.contains_key(resource) {
                return MutationAttempt::Indeterminate {
                    error: Error::BackendUnavailable(format!(
                        "resource {resource} is not present on this system"
                    )),
                    produced: None,
                };
            }
            let live_generation = inner.generations.get(resource).copied().unwrap_or(0);
            let live_state = inner.states.get(resource).cloned().unwrap_or_default();
            if live_generation != expected_full.generation || live_state != expected_full.state {
                return MutationAttempt::Rejected {
                    error: Error::ExternalModification {
                        resource: resource.clone(),
                        detail: "the current state changed since ownership was verified"
                            .to_string(),
                    },
                };
            }
            inner.states.insert(resource.clone(), target_state);
            *inner.generations.entry(resource.clone()).or_insert(0) += 1;
            let produced = match Self::snapshot_from(&inner, resource) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return MutationAttempt::Indeterminate {
                        error,
                        produced: None,
                    };
                }
            };
            Self::take_adversary(&mut inner, false, resource);
            produced
        };
        self.notify(DnsEvent::ResourceChanged {
            resource: resource.clone(),
        });
        MutationAttempt::Performed {
            produced: Some(produced),
        }
    }

    fn proves_current(&self, proof: &PlatformSnapshot, current: &PlatformSnapshot) -> bool {
        match (self.interpret_full(proof), self.interpret_full(current)) {
            (Ok(a), Ok(b)) => a.generation == b.generation && a.state == b.state,
            _ => false,
        }
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
        if let Some(barrier) = self
            .start_watch_block
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            barrier.wait();
        }
        let flag = Arc::new(AtomicBool::new(false));
        {
            let mut watchers = self
                .watchers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            watchers.push((Arc::clone(&flag), callback));
        }
        let watchers = Arc::clone(&self.watchers);
        let cancel_flag = Arc::clone(&flag);
        Ok(WatchHandle::new(flag, move || {
            watchers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .retain(|(existing, _)| !Arc::ptr_eq(existing, &cancel_flag));
        }))
    }
}
