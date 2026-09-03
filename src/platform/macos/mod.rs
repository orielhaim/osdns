//! macOS backend: SystemConfiguration dynamic store for primary DNS and
//! scoped `/etc/resolver/<domain>` files for split DNS.
//!
//! Every resource is journaled and locked separately: the lease owns
//! `macos:service:<service-id>` for the network service backing the scope
//! plus one `macos:resolver:<domain>` resource per routing domain. Scoped
//! resolver files carry a first-line owner marker; a file that exists
//! without our marker is never overwritten - the apply reports
//! [`Error::Conflict`] with [`ConflictReason::ResourceOccupied`] instead.
//! This makes multi-instance cleanup races impossible: a lease can only ever
//! delete the exact files it created, never "everything that looks like
//! ours".
//!
//! The dynamic store changes touch only the runtime (`State:`) copy; the
//! persisted (`Setup:`) copy belongs to the user. Unrelated dictionary
//! fields are captured and preserved.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::capability::{BackendKind, Capabilities};
use crate::config::{DnsConfig, DnsScope, InterfaceSelector};
use crate::error::{ConflictReason, Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::{DnsSuffix, NormalizedConfig};
use crate::ownership::ResourceId;
use crate::platform::macos::system_configuration as sc;
use crate::platform::{ApplyReceipt, Backend, PlatformSnapshot};
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
    pub(crate) service_dns: Option<sc::ScValue>,
    pub(crate) resolver_content: Option<Vec<u8>>,
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
                .with_cache_flush(false),
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
        let data = serde_json::to_value(snapshot).map_err(|e| {
            Error::platform(BackendKind::MacosSystemConfiguration, format_args!("{e}"))
        })?;
        Ok(PlatformSnapshot::new(
            BackendKind::MacosSystemConfiguration,
            resource.clone(),
            data,
        ))
    }

    fn parse_snapshot(&self, snapshot: &PlatformSnapshot) -> Result<MacosSnapshot> {
        serde_json::from_value(snapshot.data.clone()).map_err(|e| {
            Error::platform(
                BackendKind::MacosSystemConfiguration,
                format_args!("snapshot data cannot be interpreted: {e}"),
            )
        })
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

fn dict_string_list(entries: &[(String, sc::ScValue)], key: &str) -> Option<Vec<String>> {
    for (existing, value) in entries {
        if existing == key
            && let sc::ScValue::Array(items) = value
        {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    sc::ScValue::String(text) => out.push(text.clone()),
                    _ => return None,
                }
            }
            return Some(out);
        }
    }
    None
}

impl Backend for MacosBackend {
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
                    resolver_content: None,
                }
            }
            ResourceKind::Resolver(domain) => MacosSnapshot {
                service_dns: None,
                resolver_content: resolver_files::read(&domain)?,
            },
        };
        self.to_platform(resource, &snapshot)
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
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
            ResourceKind::Resolver(domain) => {
                if let Some(detail) = resolver_files::foreign_claim(&domain, &self.owner)? {
                    return Err(Error::Conflict {
                        resource: resource.clone(),
                        reason: ConflictReason::ResourceOccupied { detail },
                    });
                }
                let content = self.resolver_content(plan);
                resolver_files::write(&domain, &content)?;
            }
        }
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        self.capture(resource)
    }

    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        let kind = Self::parse_resource(resource)?;
        let before = self.parse_snapshot(snapshot)?;
        match kind {
            ResourceKind::Service(id) => {
                let store = sc::store()?;
                match before.service_dns {
                    Some(dict) => sc::rewrite_service_dns(&store, &id, dict)?,
                    None => sc::remove_service_dns(&store, &id)?,
                }
            }
            ResourceKind::Resolver(domain) => match before.resolver_content {
                Some(content) => resolver_files::write(&domain, &content)?,
                None => resolver_files::delete(&domain)?,
            },
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
            (Ok(x), Ok(y)) => x == y,
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
                let Some(sc::ScValue::Dictionary(entries)) = current.service_dns.clone() else {
                    return false;
                };
                dict_string_list(&entries, "ServerAddresses") == Some(expected_servers(plan))
                    && dict_string_list(&entries, "SearchDomains") == Some(expected_search(plan))
            }
            ResourceKind::Resolver(_) => {
                current.resolver_content.as_deref() == Some(self.resolver_content(plan).as_slice())
            }
        }
    }

    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
        let snapshot = self.parse_snapshot(snapshot)?;
        let (nameservers, search) = match snapshot.service_dns {
            Some(sc::ScValue::Dictionary(entries)) => (
                dict_string_list(&entries, "ServerAddresses")
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|entry| entry.parse().ok())
                    .collect(),
                dict_string_list(&entries, "SearchDomains")
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
        let resolver_cancel = watch::start_resolver_watch(flag.clone(), callback)?;
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
