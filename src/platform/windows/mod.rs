//! Windows backend: per-interface DNS via the native IP Helper API
//! (`GetInterfaceDnsSettings`/`SetInterfaceDnsSettings`) and split DNS via
//! the Name Resolution Policy Table.
//!
//! Interfaces are identified internally by GUID
//! (`windows:interface:<guid>`); names and indexes are convenience selectors
//! only. IPv4 and IPv6 are configured as two explicit stacks, mirroring the
//! `DNS_SETTING_IPV6` flag of the native API.
//!
//! NRPT rules are additive and independently owned: rule keys are derived
//! deterministically from the owner and namespace set, every osdns rule is
//! marked with its owner, and no rule that is not marked as ours is ever
//! read, written, or deleted. Rules written by Group Policy live in a
//! separate registry tree that osdns never touches; on policy-managed
//! machines local rules may therefore be overridden by policy.
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
    adapter_for_selector, adapter_list, get_dns_settings, parse_address_list, set_dns_settings,
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

    fn guid_of(resource: &ResourceId) -> Result<GUID> {
        let text = resource
            .as_str()
            .strip_prefix("windows:interface:")
            .ok_or_else(|| {
                Error::invalid_config(format_args!(
                    "resource {resource} is not a Windows interface"
                ))
            })?;
        crate::platform::windows::interface::parse_guid(text)
    }

    fn read_interface_state(&self, guid: &GUID) -> Result<InterfaceState> {
        let raw = get_dns_settings(guid)?;
        let nameservers = raw.nameserver.map(|s| parse_address_list(&s));
        let searchlist = raw.searchlist.map(|s| parse_suffix_list(&s));
        Ok(InterfaceState {
            ipv4_nameservers: nameservers
                .as_ref()
                .map(|list| list.iter().filter(|ip| ip.is_ipv4()).cloned().collect()),
            ipv6_nameservers: nameservers
                .as_ref()
                .map(|list| list.iter().filter(|ip| ip.is_ipv6()).cloned().collect()),
            ipv4_search: searchlist.clone(),
            ipv6_search: searchlist,
        })
    }

    fn capture_state(&self, guid: &GUID) -> Result<WindowsSnapshot> {
        Ok(WindowsSnapshot {
            interface: self.read_interface_state(guid)?,
            rules: nrpt::read_owned_rules(&self.owner)?,
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InterfaceState {
    pub(crate) ipv4_nameservers: Option<Vec<IpAddr>>,
    pub(crate) ipv4_search: Option<Vec<DnsSuffix>>,
    pub(crate) ipv6_nameservers: Option<Vec<IpAddr>>,
    pub(crate) ipv6_search: Option<Vec<DnsSuffix>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WindowsSnapshot {
    pub(crate) interface: InterfaceState,
    pub(crate) rules: Vec<nrpt::NrptRule>,
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
        _plan: &NormalizedConfig,
    ) -> Result<Vec<ResourceId>> {
        match scope {
            DnsScope::Global => Err(Error::unsupported(
                BackendKind::WindowsIpHelper,
                "Windows has no global DNS API; DNS is per-interface",
            )),
            DnsScope::Interface(selector) => {
                let adapter = adapter_for_selector(selector)?;
                ResourceId::new(format!("windows:interface:{}", adapter.guid_string))
                    .map(|id| vec![id])
            }
        }
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        adapter_list()
    }

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let guid = Self::guid_of(resource)?;
        let snapshot = self.capture_state(&guid)?;
        self.to_platform(resource, &snapshot)
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        let guid = Self::guid_of(resource)?;
        for rule in nrpt::rules_from_plan(plan, &self.owner) {
            nrpt::write_rule(&rule, &self.owner)?;
        }
        self.apply_interface(&guid, &expected_interface_state(plan))?;
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let guid = Self::guid_of(resource)?;
        let snapshot = self.capture_state(&guid)?;
        self.to_platform(resource, &snapshot)
    }

    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        let guid = Self::guid_of(resource)?;
        let before = self.parse_snapshot(snapshot)?;
        let current = self.capture_state(&guid)?;
        for rule in &current.rules {
            if !before.rules.iter().any(|r| r.key == rule.key) {
                nrpt::delete_rule(&rule.key)?;
            }
        }
        for rule in &before.rules {
            if current.rules.iter().any(|r| r.key == rule.key) {
                nrpt::write_rule(rule, &self.owner)?;
            }
        }
        self.restore_interface(&guid, &before.interface)?;
        Ok(())
    }

    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        match (self.parse_snapshot(a), self.parse_snapshot(b)) {
            (Ok(x), Ok(y)) => {
                let rules_sorted = |mut rules: Vec<nrpt::NrptRule>| {
                    rules.sort_by(|a, b| a.key.cmp(&b.key));
                    rules
                };
                normalized(&x.interface.ipv4_nameservers)
                    == normalized(&y.interface.ipv4_nameservers)
                    && normalized(&x.interface.ipv6_nameservers)
                        == normalized(&y.interface.ipv6_nameservers)
                    && normalized_suffixes(&x.interface.ipv4_search)
                        == normalized_suffixes(&y.interface.ipv4_search)
                    && normalized_suffixes(&x.interface.ipv6_search)
                        == normalized_suffixes(&y.interface.ipv6_search)
                    && rules_sorted(x.rules) == rules_sorted(y.rules)
            }
            _ => false,
        }
    }

    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool {
        let Ok(current) = self.parse_snapshot(snapshot) else {
            return false;
        };
        let expected = expected_interface_state(plan);
        let interface_matches = normalized(&current.interface.ipv4_nameservers)
            == normalized(&expected.ipv4_nameservers)
            && normalized(&current.interface.ipv6_nameservers)
                == normalized(&expected.ipv6_nameservers)
            && normalized_suffixes(&current.interface.ipv4_search)
                == normalized_suffixes(&expected.ipv4_search)
            && normalized_suffixes(&current.interface.ipv6_search)
                == normalized_suffixes(&expected.ipv6_search);
        if !interface_matches {
            return false;
        }
        for rule in nrpt::rules_from_plan(plan, &self.owner) {
            let Some(found) = current.rules.iter().find(|r| r.key == rule.key) else {
                return false;
            };
            if found.namespaces != rule.namespaces || found.servers != rule.servers {
                return false;
            }
        }
        true
    }

    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
        let snapshot = self.parse_snapshot(snapshot)?;
        let mut nameservers = snapshot
            .interface
            .ipv4_nameservers
            .clone()
            .unwrap_or_default();
        nameservers.extend(
            snapshot
                .interface
                .ipv6_nameservers
                .clone()
                .unwrap_or_default(),
        );
        let mut search = snapshot.interface.ipv4_search.clone().unwrap_or_default();
        for suffix in snapshot.interface.ipv6_search.clone().unwrap_or_default() {
            if !search.contains(&suffix) {
                search.push(suffix);
            }
        }
        let mut routing = Vec::new();
        for rule in &snapshot.rules {
            for namespace in &rule.namespaces {
                let Ok(suffix) = DnsSuffix::parse(namespace) else {
                    continue;
                };
                if !routing.contains(&suffix) {
                    routing.push(suffix);
                }
            }
        }
        Ok(DnsConfig::from_parts(
            scope.clone(),
            nameservers,
            search,
            routing,
            None,
        ))
    }

    fn start_watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ip_cancel =
            super::windows::notify::start_ip_interface_watch(flag.clone(), callback.clone())?;
        let nrpt_cancel = super::windows::notify::start_nrpt_registry_watch(flag, callback)?;
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
    use crate::config::DnsConfig;

    fn plan(
        ns: &[&str],
        search: &[&str],
        routing: &[&str],
        default_route: Option<bool>,
    ) -> NormalizedConfig {
        let mut builder = DnsConfig::builder(DnsScope::Interface(
            crate::config::InterfaceSelector::Index(1),
        ))
        .nameservers(ns.iter().map(|s| s.parse().unwrap()));
        for domain in search {
            builder = builder.search_domain(domain);
        }
        for domain in routing {
            builder = builder.routing_domain(domain);
        }
        if let Some(flag) = default_route {
            builder = builder.default_route(flag);
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

    #[test]
    fn expected_interface_state_splits_families() {
        let p = plan(
            &["1.1.1.1", "2606:4700:4700::1111"],
            &["corp.example"],
            &[],
            None,
        );
        let expected = expected_interface_state(&p);
        assert_eq!(
            expected.ipv4_nameservers,
            Some(vec!["1.1.1.1".parse().unwrap()])
        );
        assert_eq!(
            expected.ipv6_nameservers,
            Some(vec!["2606:4700:4700::1111".parse().unwrap()])
        );
        let search = vec![DnsSuffix::parse("corp.example").unwrap()];
        assert_eq!(expected.ipv4_search, Some(search.clone()));
        assert_eq!(expected.ipv6_search, Some(search));
    }

    #[test]
    fn normalized_treats_absent_and_empty_alike() {
        assert_eq!(normalized(&None), Vec::<IpAddr>::new());
        assert_eq!(normalized(&Some(vec![])), Vec::<IpAddr>::new());
        assert_eq!(normalized_suffixes(&None), Vec::<DnsSuffix>::new());
    }

    #[test]
    fn matches_desired_ignores_foreign_marker_rules() {
        let backend = WindowsBackend::new("io.test");
        let p = plan(&["1.1.1.1"], &["corp.example"], &["corp.example"], None);
        let expected_rules = nrpt::rules_from_plan(&p, "io.test");
        let mut snapshot = WindowsSnapshot {
            interface: expected_interface_state(&p),
            rules: expected_rules.clone(),
        };
        assert!(
            backend.matches_desired(
                &backend
                    .to_platform(
                        &ResourceId::new("windows:interface:12345678-9abc-def0-1122-334455667788")
                            .unwrap(),
                        &snapshot
                    )
                    .unwrap(),
                &p,
            )
        );

        snapshot.rules.push(nrpt::NrptRule {
            key: "00000000-0000-0000-0000-000000000000".to_string(),
            namespaces: vec![".other.example".to_string()],
            servers: vec!["9.9.9.9".parse().unwrap()],
        });
        assert!(
            backend.matches_desired(
                &backend
                    .to_platform(
                        &ResourceId::new("windows:interface:12345678-9abc-def0-1122-334455667788")
                            .unwrap(),
                        &snapshot
                    )
                    .unwrap(),
                &p,
            ),
            "rules owned by other leases must not affect verification"
        );
    }

    #[test]
    fn matches_desired_fails_when_rule_content_differs() {
        let backend = WindowsBackend::new("io.test");
        let p = plan(&["1.1.1.1"], &[], &["corp.example"], None);
        let mut rules = nrpt::rules_from_plan(&p, "io.test");
        rules[0].servers = vec!["9.9.9.9".parse().unwrap()];
        let snapshot = WindowsSnapshot {
            interface: expected_interface_state(&p),
            rules,
        };
        assert!(
            !backend.matches_desired(
                &backend
                    .to_platform(
                        &ResourceId::new("windows:interface:12345678-9abc-def0-1122-334455667788")
                            .unwrap(),
                        &snapshot
                    )
                    .unwrap(),
                &p,
            )
        );
    }

    #[test]
    fn snapshot_roundtrips_through_json() {
        let backend = WindowsBackend::new("io.test");
        let p = plan(&["1.1.1.1"], &["corp.example"], &["corp.example"], None);
        let snapshot = WindowsSnapshot {
            interface: expected_interface_state(&p),
            rules: nrpt::rules_from_plan(&p, "io.test"),
        };
        let platform = backend
            .to_platform(
                &ResourceId::new("windows:interface:12345678-9abc-def0-1122-334455667788").unwrap(),
                &snapshot,
            )
            .unwrap();
        let parsed = backend.parse_snapshot(&platform).unwrap();
        assert_eq!(snapshot, parsed);
    }
}
