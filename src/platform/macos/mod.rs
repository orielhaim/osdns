//! macOS backend: SystemConfiguration dynamic store for primary DNS and
//! scoped `/etc/resolver/<domain>` files for split DNS.
//!
//! Every resource is journaled and locked separately: the lease owns
//! `macos:service:<service-id>` for the network service backing the scope
//! plus one `macos:resolver:<domain>` resource per routing domain. Scoped
//! resolver files carry a first-line owner marker; a file that exists
//! without our marker is never overwritten - the apply reports
//! [`Error::Conflict`] with [`ConflictReason::ResourceOccupied`] instead.
//! Replacement and deletion remain preflight-only: macOS cannot atomically
//! compare an existing resolver file's identity and rename or unlink its name.
//! A concurrent privileged writer can race the final comparison.
//!
//! The dynamic store changes touch only the runtime (`State:`) copy; the
//! persisted (`Setup:`) copy belongs to the user. Unrelated dictionary
//! fields are captured and preserved.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::capability::{BackendKind, Capabilities};
use crate::config::{DnsConfig, DnsScope, InterfaceSelector};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::{DnsSuffix, NormalizedConfig};
use crate::ownership::ResourceId;
use crate::platform::macos::system_configuration as sc;
use crate::platform::{Backend, MutationAttempt, PlatformSnapshot, SnapshotData};
use crate::watch::{WatchCallback, WatchHandle};

pub(crate) mod resolver_files;
pub(crate) mod system_configuration;
pub(crate) mod watch;

pub(crate) struct MacosBackend {
    owner: String,
    caps: Capabilities,
}

#[derive(Debug, Clone)]
enum ResourceKind {
    Service(String),
    Resolver(String),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct MacosSnapshot {
    pub(crate) service_dns: Option<Vec<u8>>,
    pub(crate) resolver_file: Option<resolver_files::ResolverFile>,
}

impl MacosBackend {
    pub(crate) fn new(owner: &str) -> Self {
        Self {
            owner: owner.to_string(),
            caps: Capabilities::new(BackendKind::MacosSystemConfiguration)
                .with_read(true)
                .with_global_dns(true)
                .with_per_interface_dns(true)
                .with_search_domains(true)
                .with_split_dns(true)
                .with_default_route(true)
                .with_watch(true)
                .with_cache_flush(false)
                .with_resource_binding(crate::ResourceBinding::PreflightOnly),
        }
    }

    fn parse_resource(resource: &ResourceId) -> Result<ResourceKind> {
        if let Some(id) = resource.as_str().strip_prefix("macos:service:") {
            // SystemConfiguration uses uppercase CFUUID strings in its
            // case-sensitive store keys; resource/lock ids are lowercase.
            let id = uuid::Uuid::parse_str(id).map_err(|error| {
                Error::invalid_config(format_args!("invalid macOS service UUID: {error}"))
            })?;
            return Ok(ResourceKind::Service(
                id.hyphenated().to_string().to_ascii_uppercase(),
            ));
        }
        if let Some(domain) = resource.as_str().strip_prefix("macos:resolver:") {
            let suffix = DnsSuffix::parse(domain)?;
            if suffix.is_root() || suffix.as_str() != domain {
                return Err(Error::JournalCorrupt(
                    "invalid scoped resolver resource".to_string(),
                ));
            }
            return Ok(ResourceKind::Resolver(domain.to_string()));
        }
        Err(Error::invalid_config(format_args!(
            "resource {resource} is not a macOS DNS resource"
        )))
    }

    fn resolver_resource(domain: &str) -> ResourceId {
        ResourceId::new(format!("macos:resolver:{domain}")).expect("valid resolver resource")
    }

    fn service_resource(id: &str) -> Result<ResourceId> {
        let id = uuid::Uuid::parse_str(id).map_err(|error| {
            Error::invalid_config(format_args!("invalid macOS service UUID: {error}"))
        })?;
        ResourceId::new(format!("macos:service:{}", id.hyphenated()))
    }

    /// Whether the network-service resource is needed for `plan`.
    ///
    /// Minimal-ownership principle: a split-only configuration (routing
    /// domains without an explicit default route) owns only the scoped
    /// `/etc/resolver/<domain>` resources and leaves the general service DNS
    /// state untouched. The service is owned when there is no split routing
    /// to express, when `default_route` explicitly requests the default
    /// route, or for global scopes (which have no scoped form).
    fn service_needed(scope: &DnsScope, plan: &NormalizedConfig) -> bool {
        match scope {
            DnsScope::Global => true,
            DnsScope::Interface(_) => {
                plan.routing_domains.is_empty() || plan.default_route == Some(true)
            }
        }
    }

    fn resolver_content(&self, plan: &NormalizedConfig) -> Vec<u8> {
        let mut content = resolver_files::marker_for(&self.owner).into_bytes();
        content
            .extend_from_slice(format!("# osdns generation={}\n", uuid::Uuid::new_v4()).as_bytes());
        for ip in &plan.nameservers {
            content.extend_from_slice(format!("nameserver {ip}\n").as_bytes());
        }
        content
    }

    fn to_platform(
        &self,
        resource: &ResourceId,
        snapshot: &MacosSnapshot,
    ) -> Result<PlatformSnapshot> {
        Ok(PlatformSnapshot::new(
            BackendKind::MacosSystemConfiguration,
            resource.clone(),
            SnapshotData::MacosSystemConfiguration(snapshot.clone()),
        ))
    }

    fn parse_snapshot(&self, snapshot: &PlatformSnapshot) -> Result<MacosSnapshot> {
        Self::validate_snapshot(snapshot, &self.owner)?;
        match &snapshot.data {
            SnapshotData::MacosSystemConfiguration(data) => Ok(data.clone()),
            _ => Err(Error::JournalCorrupt(
                "macOS snapshot has the wrong backend data".to_string(),
            )),
        }
    }

    pub(crate) fn validate_snapshot(snapshot: &PlatformSnapshot, owner: &str) -> Result<()> {
        let SnapshotData::MacosSystemConfiguration(data) = &snapshot.data else {
            return Err(Error::JournalCorrupt(
                "macOS snapshot has the wrong backend data".to_string(),
            ));
        };
        match Self::parse_resource(&snapshot.resource)? {
            ResourceKind::Service(_) if data.resolver_file.is_none() => {
                if let Some(bytes) = &data.service_dns {
                    sc::decode(bytes).map_err(|error| Error::JournalCorrupt(error.to_string()))?;
                }
                Ok(())
            }
            ResourceKind::Resolver(_) if data.service_dns.is_none() => {
                if let Some(file) = &data.resolver_file {
                    resolver_files::validate_content(&file.content, owner)?;
                }
                Ok(())
            }
            _ => Err(Error::JournalCorrupt(
                "macOS snapshot kind differs from its resource".to_string(),
            )),
        }
    }
}

fn expected_servers(plan: &NormalizedConfig) -> Vec<String> {
    plan.nameservers.iter().map(|ip| ip.to_string()).collect()
}

fn expected_search(plan: &NormalizedConfig) -> Vec<String> {
    plan.search_domains
        .iter()
        .filter(|suffix| !suffix.is_root())
        .map(|suffix| suffix.to_string())
        .collect()
}

impl Backend for MacosBackend {
    fn apply_bound(
        &self,
        identity: &crate::platform::ResourceIdentity,
        expected: &PlatformSnapshot,
        plan: &NormalizedConfig,
    ) -> MutationAttempt {
        if expected.resource != identity.resource {
            return MutationAttempt::Rejected {
                error: Error::JournalCorrupt(
                    "resolver snapshot names a different resource".to_string(),
                ),
            };
        }
        let Ok(ResourceKind::Resolver(domain)) = Self::parse_resource(&identity.resource) else {
            return crate::platform::apply_bound(self, identity, expected, plan);
        };
        let before = match self.parse_snapshot(expected) {
            Ok(before) => before,
            Err(error) => return MutationAttempt::Rejected { error },
        };
        let content = self.resolver_content(plan);
        match resolver_files::replace(
            &domain,
            before.resolver_file.as_ref(),
            Some(&content),
            &self.owner,
        ) {
            Ok(file) => MutationAttempt::Performed {
                produced: Some(PlatformSnapshot::new(
                    self.kind(),
                    identity.resource.clone(),
                    SnapshotData::MacosSystemConfiguration(MacosSnapshot {
                        service_dns: None,
                        resolver_file: file,
                    }),
                )),
            },
            Err(error) if error.is_external_modification() => MutationAttempt::Rejected { error },
            Err(error) => MutationAttempt::Indeterminate {
                error,
                produced: None,
            },
        }
    }

    fn restore_bound(
        &self,
        identity: &crate::platform::ResourceIdentity,
        expected: &PlatformSnapshot,
        target: &PlatformSnapshot,
    ) -> MutationAttempt {
        let Ok(ResourceKind::Resolver(domain)) = Self::parse_resource(&identity.resource) else {
            return crate::platform::restore_bound(self, identity, expected, target);
        };
        if expected.resource != identity.resource || target.resource != identity.resource {
            return MutationAttempt::Rejected {
                error: Error::JournalCorrupt(
                    "resolver snapshots name different resources".to_string(),
                ),
            };
        }
        let (before, target) = match (self.parse_snapshot(expected), self.parse_snapshot(target)) {
            (Ok(before), Ok(target)) => (before, target),
            (Err(error), _) | (_, Err(error)) => return MutationAttempt::Rejected { error },
        };
        let content = target
            .resolver_file
            .as_ref()
            .map(|file| file.content.as_slice());
        match resolver_files::replace(&domain, before.resolver_file.as_ref(), content, &self.owner)
        {
            Ok(file) => MutationAttempt::Performed {
                produced: Some(PlatformSnapshot::new(
                    self.kind(),
                    identity.resource.clone(),
                    SnapshotData::MacosSystemConfiguration(MacosSnapshot {
                        service_dns: None,
                        resolver_file: file,
                    }),
                )),
            },
            Err(error) if error.is_external_modification() => MutationAttempt::Rejected { error },
            Err(error) => MutationAttempt::Indeterminate {
                error,
                produced: None,
            },
        }
    }

    fn owns_current(&self, claimed: &PlatformSnapshot, current: &PlatformSnapshot) -> bool {
        if claimed.resource != current.resource {
            return false;
        }
        if matches!(
            Self::parse_resource(&claimed.resource),
            Ok(ResourceKind::Resolver(_))
        ) {
            match (self.parse_snapshot(claimed), self.parse_snapshot(current)) {
                (Ok(claimed), Ok(current)) => claimed.resolver_file == current.resolver_file,
                _ => false,
            }
        } else {
            self.equivalent(claimed, current)
        }
    }

    fn proves_current(&self, claimed: &PlatformSnapshot, current: &PlatformSnapshot) -> bool {
        matches!(
            Self::parse_resource(&claimed.resource),
            Ok(ResourceKind::Resolver(_))
        ) && self.owns_current(claimed, current)
    }
    fn kind(&self) -> BackendKind {
        BackendKind::MacosSystemConfiguration
    }

    fn capabilities(&self) -> Capabilities {
        self.caps.clone()
    }

    fn resolve_resources(
        &self,
        scope: &DnsScope,
        plan: &NormalizedConfig,
    ) -> Result<Vec<ResourceId>> {
        if plan.routing_domains.iter().any(|domain| domain.is_root()) {
            return Err(Error::unsupported(
                BackendKind::MacosSystemConfiguration,
                "the root routing domain is not representable as a scoped resolver file; configure default_route instead",
            ));
        }
        let store = sc::store()?;
        let service = match scope {
            DnsScope::Global | DnsScope::Interface(InterfaceSelector::Default) => {
                sc::primary_service_id(&store)?
            }
            DnsScope::Interface(InterfaceSelector::Name(name)) => {
                sc::service_for_interface_name(&store, name.to_string_lossy().as_ref())?
            }
            DnsScope::Interface(InterfaceSelector::Index(_)) => {
                return Err(Error::invalid_config(
                    "index selectors are not supported on macOS; use Default or Name",
                ));
            }
        };
        let mut resources = Vec::new();
        if Self::service_needed(scope, plan) {
            resources.push(Self::service_resource(&service)?);
        }
        for domain in &plan.routing_domains {
            resources.push(Self::resolver_resource(domain.as_str()));
        }
        if resources.is_empty() {
            return Err(Error::invalid_config(
                "the configuration resolves to no macOS resources",
            ));
        }
        Ok(resources)
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        let store = sc::store()?;
        let mut out = Vec::new();
        for id in sc::service_ids(&store)? {
            let name = sc::service_interface_name(&store, &id).unwrap_or_else(|| id.clone());
            out.push(InterfaceInfo {
                index: 0,
                name: name.clone().into(),
                friendly_name: Some(name),
                guid: Some(id),
                is_up: true,
            });
        }
        Ok(out)
    }

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let kind = Self::parse_resource(resource)?;
        let snapshot = match kind {
            ResourceKind::Service(id) => {
                let store = sc::store()?;
                MacosSnapshot {
                    service_dns: sc::read_service_dns(&store, &id)?,
                    resolver_file: None,
                }
            }
            ResourceKind::Resolver(domain) => {
                let file = resolver_files::read(&domain)?;
                if let Some(file) = &file {
                    resolver_files::validate_content(&file.content, &self.owner).map_err(
                        |error| Error::Conflict {
                            resource: resource.clone(),
                            reason: crate::ConflictReason::ResourceOccupied {
                                detail: error.to_string(),
                            },
                        },
                    )?;
                }
                MacosSnapshot {
                    service_dns: None,
                    resolver_file: file,
                }
            }
        };
        self.to_platform(resource, &snapshot)
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<()> {
        let kind = Self::parse_resource(resource)?;
        match kind {
            ResourceKind::Service(id) => {
                let store = sc::store()?;
                sc::write_service_dns(
                    &store,
                    &id,
                    &expected_servers(plan),
                    &expected_search(plan),
                )?;
            }
            ResourceKind::Resolver(_) => {
                return Err(Error::unsupported(
                    self.kind(),
                    "resolver mutations require the bound operation",
                ));
            }
        }
        Ok(())
    }

    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        if resource != &snapshot.resource {
            return Err(Error::JournalCorrupt(
                "restore snapshot names a different resource".to_string(),
            ));
        }
        let kind = Self::parse_resource(resource)?;
        let before = self.parse_snapshot(snapshot)?;
        match kind {
            ResourceKind::Service(id) => {
                let store = sc::store()?;
                sc::restore_service_dns(&store, &id, before.service_dns.as_deref())?;
            }
            ResourceKind::Resolver(_) => {
                return Err(Error::unsupported(
                    self.kind(),
                    "resolver restoration requires the bound operation",
                ));
            }
        }
        Ok(())
    }

    fn validate_plan(&self, scope: &DnsScope, plan: &NormalizedConfig) -> Result<()> {
        if plan.routing_domains.iter().any(|domain| domain.is_root()) {
            return Err(Error::unsupported(
                BackendKind::MacosSystemConfiguration,
                "the root routing domain is not representable as a scoped resolver file; configure default_route instead",
            ));
        }
        if plan.default_route == Some(false) && plan.routing_domains.is_empty() {
            return Err(Error::unsupported(
                BackendKind::MacosSystemConfiguration,
                "default_route(false) requires at least one scoped routing domain on macOS",
            ));
        }
        // Search domains live in the service DNS state, which implies the
        // default route. A split-only lease (routing without the service)
        // cannot faithfully carry them.
        if !plan.routing_domains.is_empty()
            && !plan.search_domains.is_empty()
            && !Self::service_needed(scope, plan)
        {
            return Err(Error::unsupported(
                BackendKind::MacosSystemConfiguration,
                "search domains require the service DNS state; set default_route(true) or drop search domains for a split-only configuration",
            ));
        }
        Ok(())
    }

    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        match (self.parse_snapshot(a), self.parse_snapshot(b)) {
            (Ok(x), Ok(y)) => {
                x.resolver_file.as_ref().map(|file| &file.content)
                    == y.resolver_file.as_ref().map(|file| &file.content)
                    && sc::equivalent(x.service_dns.as_deref(), y.service_dns.as_deref())
            }
            _ => false,
        }
    }

    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool {
        let Ok(current) = self.parse_snapshot(snapshot) else {
            return false;
        };
        let Ok(kind) = Self::parse_resource(&snapshot.resource) else {
            return false;
        };
        match kind {
            ResourceKind::Service(_) => {
                let Some(entries) = current.service_dns.clone() else {
                    return false;
                };
                sc::string_list(&entries, "ServerAddresses") == Some(expected_servers(plan))
                    && sc::string_list(&entries, "SearchDomains") == Some(expected_search(plan))
            }
            ResourceKind::Resolver(_) => current.resolver_file.as_ref().is_some_and(|file| {
                file.content
                    .starts_with(resolver_files::marker_for(&self.owner).as_bytes())
                    && crate::platform::text_config::parse_resolv_conf_content(&file.content)
                        .is_ok_and(|(servers, search)| {
                            servers == plan.nameservers && search.is_empty()
                        })
            }),
        }
    }

    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
        let snapshot = self.parse_snapshot(snapshot)?;
        let (nameservers, search) = match snapshot.service_dns {
            Some(entries) => (
                sc::string_list(&entries, "ServerAddresses")
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|entry| entry.parse().ok())
                    .collect(),
                sc::string_list(&entries, "SearchDomains")
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|entry| DnsSuffix::parse(&entry).ok())
                    .collect(),
            ),
            _ => (Vec::new(), Vec::new()),
        };
        Ok(DnsConfig::from_parts(
            scope.clone(),
            nameservers,
            search,
            Vec::new(),
            None,
        ))
    }

    fn start_watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let store_cancel = watch::start_store_watch(flag.clone(), callback.clone())?;
        let resolver_cancel = match watch::start_resolver_watch(flag.clone(), callback) {
            Ok(cancel) => cancel,
            Err(error) => {
                store_cancel();
                return Err(error);
            }
        };
        let cancels: Vec<Box<dyn FnOnce() + Send>> = vec![store_cancel, resolver_cancel];
        Ok(WatchHandle::new(flag, move || {
            for cancel in cancels {
                cancel();
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InterfaceSelector;

    fn plan(routing: &[&str], default_route: Option<bool>, search: &[&str]) -> NormalizedConfig {
        NormalizedConfig {
            nameservers: vec!["100.64.0.53".parse().unwrap()],
            search_domains: search
                .iter()
                .map(|s| DnsSuffix::parse(s).unwrap())
                .collect(),
            routing_domains: routing
                .iter()
                .map(|s| DnsSuffix::parse(s).unwrap())
                .collect(),
            default_route,
        }
    }

    fn iface_scope() -> DnsScope {
        DnsScope::Interface(InterfaceSelector::Default)
    }

    #[test]
    fn split_only_config_needs_no_service_resource() {
        // corp.example -> 100.64.0.53, everything else unchanged: only the
        // scoped resolver is owned.
        assert!(!MacosBackend::service_needed(
            &iface_scope(),
            &plan(&["corp.example"], None, &[])
        ));
        assert!(!MacosBackend::service_needed(
            &iface_scope(),
            &plan(&["corp.example"], Some(false), &[])
        ));
    }

    #[test]
    fn default_route_or_plain_config_needs_service() {
        assert!(MacosBackend::service_needed(
            &iface_scope(),
            &plan(&[], None, &[])
        ));
        assert!(MacosBackend::service_needed(
            &iface_scope(),
            &plan(&["corp.example"], Some(true), &[])
        ));
        assert!(MacosBackend::service_needed(
            &DnsScope::Global,
            &plan(&[], None, &[])
        ));
    }

    #[test]
    fn default_route_false_without_scoped_routing_is_rejected() {
        let backend = MacosBackend::new("io.test");
        assert!(
            backend
                .validate_plan(&iface_scope(), &plan(&[], Some(false), &[]))
                .is_err()
        );
        assert!(
            backend
                .validate_plan(&iface_scope(), &plan(&["corp.example"], Some(false), &[]),)
                .is_ok()
        );
    }

    #[test]
    fn service_uuid_roundtrips_between_resource_and_store_keys() {
        let native = "6F903813-67A3-45A2-B708-3211308208BC";
        let resource = MacosBackend::service_resource(native).unwrap();
        assert_eq!(
            resource.as_str(),
            "macos:service:6f903813-67a3-45a2-b708-3211308208bc"
        );
        assert_eq!(
            resource,
            MacosBackend::service_resource(&native.to_ascii_lowercase()).unwrap()
        );
        let ResourceKind::Service(restored) = MacosBackend::parse_resource(&resource).unwrap()
        else {
            panic!("expected service resource");
        };
        assert_eq!(restored, native);
    }
}
