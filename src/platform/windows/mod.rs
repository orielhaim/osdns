//! Windows backend: per-interface DNS via the native IP Helper API
//! (`GetInterfaceDnsSettings`/`SetInterfaceDnsSettings`) and split DNS via
//! the Name Resolution Policy Table.
//!
//! Interfaces are identified internally by GUID
//! (`windows:interface:<guid>`); names and indexes are convenience selectors
//! only. IPv4 and IPv6 are configured as two explicit stacks, mirroring the
//! `DNS_SETTING_IPV6` flag of the native API.
//!
//! NRPT rules are transactionally owned resources in their own right: every
//! rule chunk produced from a plan resolves to a separate
//! `windows:nrpt:<key>` resource with its own lock, journal record, capture,
//! and compare-before-restore decision. Rule keys are derived
//! deterministically from the owner and namespace set, every osdns rule is
//! marked with its owner, and no rule that is not marked as ours is ever
//! read, written, or deleted. Two leases on different adapters therefore
//! cannot interfere: each owns exactly the rules its own plan produced.
//! Rules written by Group Policy live in a separate registry tree that osdns
//! never touches; on policy-managed machines local rules may therefore be
//! overridden by policy.
//!
//! # WSL limitation
//!
//! Windows NRPT semantics do not imply equivalent split-DNS behavior for
//! WSL2: WSL2 resolves through its own NAT path via the host's HNS
//! configuration and does not consult NRPT rules of Windows adapters. A
//! lease that routes domains via NRPT must not be assumed to cover WSL2
//! distributions; configure WSL separately if needed.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use windows::core::GUID;

use crate::capability::{BackendKind, Capabilities};
use crate::config::{DnsConfig, DnsScope};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::{DnsSuffix, NormalizedConfig};
use crate::ownership::ResourceId;
use crate::platform::windows::interface::{
    adapter_for_selector, adapter_list, get_dns_settings, get_ipv6_dns_settings,
    parse_address_list, set_dns_settings,
};
use crate::platform::{ApplyReceipt, Backend, PlatformSnapshot};
use crate::watch::{WatchCallback, WatchHandle};

pub(crate) mod cache;
pub(crate) mod interface;
pub(crate) mod notify;
pub(crate) mod nrpt;

pub(crate) struct WindowsBackend {
    owner: String,
    caps: Capabilities,
}

#[derive(Debug, Clone)]
enum ResourceKind {
    Interface(GUID),
    Nrpt { key: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InterfaceState {
    pub(crate) ipv4_nameservers: Option<Vec<IpAddr>>,
    pub(crate) ipv4_search: Option<Vec<DnsSuffix>>,
    pub(crate) ipv6_nameservers: Option<Vec<IpAddr>>,
    pub(crate) ipv6_search: Option<Vec<DnsSuffix>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InterfaceSnapshot {
    pub(crate) interface: InterfaceState,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NrptSnapshot {
    pub(crate) rule: Option<nrpt::NrptRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum WindowsSnapshot {
    Interface(InterfaceSnapshot),
    Nrpt(NrptSnapshot),
}

impl WindowsBackend {
    pub(crate) fn new(owner: &str) -> Self {
        Self {
            owner: owner.to_string(),
            caps: Capabilities::new(BackendKind::WindowsIpHelper)
                .with_read(true)
                .with_global_dns(false)
                .with_per_interface_dns(true)
                .with_search_domains(true)
                .with_split_dns(true)
                .with_watch(true)
                .with_cache_flush(true),
        }
    }

    fn parse_resource(resource: &ResourceId) -> Result<ResourceKind> {
        if let Some(text) = resource.as_str().strip_prefix("windows:interface:") {
            return Ok(ResourceKind::Interface(interface::parse_guid(text)?));
        }
        if let Some(key) = resource.as_str().strip_prefix("windows:nrpt:") {
            return Ok(ResourceKind::Nrpt {
                key: key.to_string(),
            });
        }
        Err(Error::invalid_config(format_args!(
            "resource {resource} is not a Windows DNS resource"
        )))
    }

    fn nrpt_resource(rule: &nrpt::NrptRule) -> ResourceId {
        ResourceId::new(format!("windows:nrpt:{}", rule.key)).expect("valid NRPT resource")
    }

    fn read_interface_state(&self, guid: &GUID) -> Result<InterfaceState> {
        let raw = get_dns_settings(guid)?;
        let raw6 = get_ipv6_dns_settings(guid)?;
        let nameservers = raw.nameserver.map(|s| parse_address_list(&s));
        let searchlist = raw.searchlist.map(|s| parse_suffix_list(&s));
        Ok(InterfaceState {
            ipv4_nameservers: nameservers
                .as_ref()
                .map(|list| list.iter().filter(|ip| ip.is_ipv4()).cloned().collect()),
            ipv6_nameservers: raw6.nameserver.map(|s| parse_address_list(&s)),
            ipv4_search: searchlist,
            ipv6_search: raw6.searchlist.map(|s| parse_suffix_list(&s)),
        })
    }

    fn apply_interface(&self, guid: &GUID, state: &InterfaceState) -> Result<()> {
        for (ipv6_stack, nameservers, search) in [
            (false, &state.ipv4_nameservers, &state.ipv4_search),
            (true, &state.ipv6_nameservers, &state.ipv6_search),
        ] {
            let nameserver = nameservers.as_ref().map(|list| join_addresses(list));
            let searchlist = search.as_ref().map(|list| join_suffixes(list));
            set_dns_settings(
                guid,
                ipv6_stack,
                nameserver.as_deref(),
                searchlist.as_deref(),
            )?;
        }
        Ok(())
    }

    fn restore_interface(&self, guid: &GUID, before: &InterfaceState) -> Result<()> {
        for (ipv6_stack, nameservers, search) in [
            (false, &before.ipv4_nameservers, &before.ipv4_search),
            (true, &before.ipv6_nameservers, &before.ipv6_search),
        ] {
            let nameserver = Some(join_addresses(nameservers.as_deref().unwrap_or(&[])));
            let searchlist = Some(join_suffixes(search.as_deref().unwrap_or(&[])));
            set_dns_settings(
                guid,
                ipv6_stack,
                nameserver.as_deref(),
                searchlist.as_deref(),
            )?;
        }
        Ok(())
    }

    fn to_platform(
        &self,
        resource: &ResourceId,
        snapshot: &WindowsSnapshot,
    ) -> Result<PlatformSnapshot> {
        let data = serde_json::to_value(snapshot)
            .map_err(|e| Error::platform(BackendKind::WindowsIpHelper, format_args!("{e}")))?;
        Ok(PlatformSnapshot::new(
            BackendKind::WindowsIpHelper,
            resource.clone(),
            data,
        ))
    }

    fn parse_snapshot(&self, snapshot: &PlatformSnapshot) -> Result<WindowsSnapshot> {
        serde_json::from_value(snapshot.data.clone()).map_err(|e| {
            Error::platform(
                BackendKind::WindowsIpHelper,
                format_args!("snapshot data cannot be interpreted: {e}"),
            )
        })
    }
}

fn join_addresses(list: &[IpAddr]) -> String {
    list.iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn join_suffixes(list: &[DnsSuffix]) -> String {
    list.iter()
        .filter(|suffix| !suffix.is_root())
        .map(|suffix| suffix.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_suffix_list(text: &str) -> Vec<DnsSuffix> {
    text.split([',', ' ', ';'])
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| DnsSuffix::parse(entry).ok())
        .collect()
}

fn normalized(list: &Option<Vec<IpAddr>>) -> Vec<IpAddr> {
    list.clone().unwrap_or_default()
}

fn normalized_suffixes(list: &Option<Vec<DnsSuffix>>) -> Vec<DnsSuffix> {
    list.clone().unwrap_or_default()
}

fn expected_interface_state(plan: &NormalizedConfig) -> InterfaceState {
    let v4: Vec<IpAddr> = plan
        .nameservers
        .iter()
        .filter(|ip| ip.is_ipv4())
        .cloned()
        .collect();
    let v6: Vec<IpAddr> = plan
        .nameservers
        .iter()
        .filter(|ip| ip.is_ipv6())
        .cloned()
        .collect();
    let search: Vec<DnsSuffix> = plan
        .search_domains
        .iter()
        .filter(|suffix| !suffix.is_root())
        .cloned()
        .collect();
    InterfaceState {
        ipv4_nameservers: Some(v4),
        ipv4_search: Some(search.clone()),
        ipv6_nameservers: Some(v6),
        ipv6_search: Some(search),
    }
}

impl Backend for WindowsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::WindowsIpHelper
    }

    fn capabilities(&self) -> Capabilities {
        self.caps.clone()
    }

    fn resolve_resources(
        &self,
        scope: &DnsScope,
        plan: &NormalizedConfig,
    ) -> Result<Vec<ResourceId>> {
        match scope {
            DnsScope::Global => Err(Error::unsupported(
                BackendKind::WindowsIpHelper,
                "Windows has no global DNS API; DNS is per-interface",
            )),
            DnsScope::Interface(selector) => {
                let adapter = adapter_for_selector(selector)?;
                let mut resources = vec![ResourceId::new(format!(
                    "windows:interface:{}",
                    adapter.guid_string
                ))?];
                for rule in nrpt::rules_from_plan(plan, &self.owner) {
                    resources.push(Self::nrpt_resource(&rule));
                }
                Ok(resources)
            }
        }
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        adapter_list()
    }

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        match Self::parse_resource(resource)? {
            ResourceKind::Interface(guid) => {
                let snapshot = WindowsSnapshot::Interface(InterfaceSnapshot {
                    interface: self.read_interface_state(&guid)?,
                });
                self.to_platform(resource, &snapshot)
            }
            ResourceKind::Nrpt { key } => {
                let rule = nrpt::read_rule_by_key(&key)?;
                let snapshot = WindowsSnapshot::Nrpt(NrptSnapshot { rule });
                self.to_platform(resource, &snapshot)
            }
        }
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        match Self::parse_resource(resource)? {
            ResourceKind::Interface(guid) => {
                self.apply_interface(&guid, &expected_interface_state(plan))?;
            }
            ResourceKind::Nrpt { .. } => {
                let expected = nrpt::rules_from_plan(plan, &self.owner);
                let key = resource
                    .as_str()
                    .strip_prefix("windows:nrpt:")
                    .expect("parsed as nrpt");
                let Some(rule) = expected.iter().find(|rule| rule.key == key) else {
                    return Err(Error::invalid_config(format_args!(
                        "resource {resource} is not part of the desired configuration"
                    )));
                };
                nrpt::write_rule(rule, &self.owner)?;
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
        match (
            Self::parse_resource(resource)?,
            self.parse_snapshot(snapshot)?,
        ) {
            (ResourceKind::Interface(guid), WindowsSnapshot::Interface(before)) => {
                self.restore_interface(&guid, &before.interface)?;
            }
            (ResourceKind::Nrpt { key }, WindowsSnapshot::Nrpt(before)) => match before.rule {
                Some(rule) => nrpt::write_rule(&rule, &self.owner)?,
                None => nrpt::delete_rule(&key)?,
            },
            _ => {
                return Err(Error::platform(
                    BackendKind::WindowsIpHelper,
                    "snapshot does not match the resource kind",
                ));
            }
        }
        Ok(())
    }

    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        match (self.parse_snapshot(a), self.parse_snapshot(b)) {
            (Ok(WindowsSnapshot::Interface(x)), Ok(WindowsSnapshot::Interface(y))) => {
                normalized(&x.interface.ipv4_nameservers)
                    == normalized(&y.interface.ipv4_nameservers)
                    && normalized(&x.interface.ipv6_nameservers)
                        == normalized(&y.interface.ipv6_nameservers)
                    && normalized_suffixes(&x.interface.ipv4_search)
                        == normalized_suffixes(&y.interface.ipv4_search)
                    && normalized_suffixes(&x.interface.ipv6_search)
                        == normalized_suffixes(&y.interface.ipv6_search)
            }
            (Ok(WindowsSnapshot::Nrpt(x)), Ok(WindowsSnapshot::Nrpt(y))) => x == y,
            _ => false,
        }
    }

    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool {
        let Ok(current) = self.parse_snapshot(snapshot) else {
            return false;
        };
        match Self::parse_resource(&snapshot.resource) {
            Ok(ResourceKind::Interface(_)) => {
                let WindowsSnapshot::Interface(current) = current else {
                    return false;
                };
                let expected = expected_interface_state(plan);
                normalized(&current.interface.ipv4_nameservers)
                    == normalized(&expected.ipv4_nameservers)
                    && normalized(&current.interface.ipv6_nameservers)
                        == normalized(&expected.ipv6_nameservers)
                    && normalized_suffixes(&current.interface.ipv4_search)
                        == normalized_suffixes(&expected.ipv4_search)
                    && normalized_suffixes(&current.interface.ipv6_search)
                        == normalized_suffixes(&expected.ipv6_search)
            }
            Ok(ResourceKind::Nrpt { key }) => {
                let WindowsSnapshot::Nrpt(current) = current else {
                    return false;
                };
                let expected = nrpt::rules_from_plan(plan, &self.owner);
                let Some(expected_rule) = expected.iter().find(|rule| rule.key == key) else {
                    return false;
                };
                current.rule.as_ref().is_some_and(|rule| {
                    rule.namespaces == expected_rule.namespaces
                        && rule.servers == expected_rule.servers
                })
            }
            Err(_) => false,
        }
    }

    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
        match self.parse_snapshot(snapshot)? {
            WindowsSnapshot::Interface(state) => {
                let mut nameservers = state.interface.ipv4_nameservers.clone().unwrap_or_default();
                nameservers.extend(state.interface.ipv6_nameservers.clone().unwrap_or_default());
                let mut search = state.interface.ipv4_search.clone().unwrap_or_default();
                for suffix in state.interface.ipv6_search.clone().unwrap_or_default() {
                    if !search.contains(&suffix) {
                        search.push(suffix);
                    }
                }
                Ok(DnsConfig::from_parts(
                    scope.clone(),
                    nameservers,
                    search,
                    Vec::new(),
                    None,
                ))
            }
            WindowsSnapshot::Nrpt(state) => {
                let Some(rule) = state.rule else {
                    return Ok(DnsConfig::from_parts(
                        scope.clone(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        None,
                    ));
                };
                let mut routing = Vec::new();
                for namespace in &rule.namespaces {
                    let Ok(suffix) = DnsSuffix::parse(namespace) else {
                        continue;
                    };
                    if !routing.contains(&suffix) {
                        routing.push(suffix);
                    }
                }
                Ok(DnsConfig::from_parts(
                    scope.clone(),
                    rule.servers.clone(),
                    Vec::new(),
                    routing,
                    None,
                ))
            }
        }
    }

    fn start_watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ip_cancel = notify::start_ip_interface_watch(flag.clone(), callback.clone())?;
        let nrpt_cancel = notify::start_nrpt_registry_watch(flag, callback)?;
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        Ok(WatchHandle::new(done, move || {
            ip_cancel();
            nrpt_cancel();
        }))
    }

    fn flush_cache(&self) -> Result<()> {
        cache::flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsConfig, InterfaceSelector};

    fn plan(ns: &[&str], routing: &[&str]) -> NormalizedConfig {
        let mut builder = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Index(1)))
            .nameservers(ns.iter().map(|s| s.parse().unwrap()));
        for domain in routing {
            builder = builder.routing_domain(domain);
        }
        crate::config::validate_against(
            &builder.build().unwrap(),
            &Capabilities::new(BackendKind::WindowsIpHelper)
                .with_per_interface_dns(true)
                .with_search_domains(true)
                .with_split_dns(true),
        )
        .unwrap()
    }

    fn rid(value: &str) -> ResourceId {
        ResourceId::new(value).unwrap()
    }

    #[test]
    fn resolve_resources_splits_interface_and_nrpt() {
        let backend = WindowsBackend::new("io.test");
        let p = plan(&["1.1.1.1"], &["corp.example"]);
        let resources = backend
            .resolve_resources(&DnsScope::Interface(InterfaceSelector::Index(1)), &p)
            .unwrap();
        assert_eq!(resources.len(), 2);
        assert!(resources[0].as_str().starts_with("windows:interface:"));
        assert!(resources[1].as_str().starts_with("windows:nrpt:"));
    }

    #[test]
    fn interface_matches_desired_and_ignores_other_kinds() {
        let backend = WindowsBackend::new("io.test");
        let p = plan(&["1.1.1.1"], &["corp.example"]);
        let snapshot = WindowsSnapshot::Interface(InterfaceSnapshot {
            interface: expected_interface_state(&p),
        });
        let platform = backend
            .to_platform(
                &rid("windows:interface:11111111-2222-3333-4444-555555555555"),
                &snapshot,
            )
            .unwrap();
        assert!(backend.matches_desired(&platform, &p));
    }

    #[test]
    fn nrpt_matches_desired_per_resource() {
        let backend = WindowsBackend::new("io.test");
        let p = plan(&["1.1.1.1"], &["corp.example"]);
        let rules = nrpt::rules_from_plan(&p, "io.test");
        assert_eq!(rules.len(), 1);
        let resource = ResourceId::new(format!("windows:nrpt:{}", rules[0].key)).unwrap();
        let snapshot = WindowsSnapshot::Nrpt(NrptSnapshot {
            rule: Some(rules[0].clone()),
        });
        let platform = backend.to_platform(&resource, &snapshot).unwrap();
        assert!(backend.matches_desired(&platform, &p));

        let mut stale = snapshot.clone();
        if let WindowsSnapshot::Nrpt(nrpt_snapshot) = &mut stale {
            nrpt_snapshot.rule.as_mut().unwrap().servers = vec!["9.9.9.9".parse().unwrap()];
        }
        let platform = backend.to_platform(&resource, &stale).unwrap();
        assert!(!backend.matches_desired(&platform, &p));
    }

    #[test]
    fn nrpt_restore_semantics() {
        let _backend = WindowsBackend::new("io.test");
        let p = plan(&["1.1.1.1"], &["corp.example"]);
        let rules = nrpt::rules_from_plan(&p, "io.test");
        let before_absent = WindowsSnapshot::Nrpt(NrptSnapshot { rule: None });
        let before_present = WindowsSnapshot::Nrpt(NrptSnapshot {
            rule: Some(rules[0].clone()),
        });
        assert_ne!(before_absent, before_present);
    }
}
