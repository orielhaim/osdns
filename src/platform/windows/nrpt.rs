//! Name Resolution Policy Table (NRPT) rules in the Windows registry.
//!
//! Rules are additive and independently owned: osdns only ever creates,
//! reads, updates, and deletes registry keys whose GUID is derived
//! deterministically from the owner and the namespace set, and whose
//! `Comment` value marks them as osdns-owned. Rules created by other
//! applications, by administrators, or by Group Policy are never touched.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use windows::core::GUID;
use windows_registry::LOCAL_MACHINE;

use crate::capability::BackendKind;
use crate::error::{Error, Result};

pub(super) const NRPT_BASE: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
const MAX_NAMESPACES_PER_RULE: usize = 50;
const CONFIG_OPTIONS_OVERRIDE: u32 = 0x8;
const MARKER_PREFIX: &str = "osdns owner=";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NrptRule {
    pub(crate) key: String,
    pub(crate) namespaces: Vec<String>,
    pub(crate) servers: Vec<IpAddr>,
}

pub(crate) fn marker_for(owner: &str) -> String {
    format!("{MARKER_PREFIX}{owner}")
}

const RULE_KEY_NAMESPACE: u128 = 0x6f73_646e_7372_7074_5f6e_7370_0000_0001;

fn rule_key(owner: &str, namespaces: &[String]) -> GUID {
    let seed_namespace = uuid::Uuid::from_u128(RULE_KEY_NAMESPACE);
    let name = format!("osdns-nrpt\x00{owner}\x00{}", namespaces.join("\u{1f}"));
    GUID::from_u128(uuid::Uuid::new_v5(&seed_namespace, name.as_bytes()).as_u128())
}

fn key_to_string(key: &GUID) -> String {
    crate::platform::windows::interface::guid_to_string(key)
}

/// Splits routing domains into NRPT-conformant namespace chunks.
///
/// The root domain maps to the single `.` namespace. Regular domains get
/// their leading-dot form so the rule covers the domain itself and every
/// subdomain.
pub(crate) fn namespaces_from_plan(plan: &crate::normalize::NormalizedConfig) -> Vec<Vec<String>> {
    let mut namespaces: Vec<String> = Vec::new();
    if plan.default_route == Some(true) {
        namespaces.push(".".to_string());
    }
    for domain in &plan.routing_domains {
        let entry = if domain.is_root() {
            ".".to_string()
        } else {
            format!(".{}", domain.as_str())
        };
        if !namespaces.contains(&entry) {
            namespaces.push(entry);
        }
    }
    namespaces
        .chunks(MAX_NAMESPACES_PER_RULE)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// The rules this plan must own, with deterministic registry keys.
pub(crate) fn rules_from_plan(
    plan: &crate::normalize::NormalizedConfig,
    owner: &str,
) -> Vec<NrptRule> {
    namespaces_from_plan(plan)
        .into_iter()
        .map(|chunk| {
            let key = rule_key(owner, &chunk);
            NrptRule {
                key: key_to_string(&key),
                namespaces: chunk,
                servers: plan.nameservers.clone(),
            }
        })
        .collect()
}

pub(crate) fn write_rule(rule: &NrptRule, owner: &str) -> Result<()> {
    let dnskey = LOCAL_MACHINE
        .create(format!(r"{NRPT_BASE}\{}", rule.key))
        .map_err(registry_error)?;
    dnskey.set_u32("Version", 1).map_err(registry_error)?;
    dnskey
        .set_u32("ConfigOptions", CONFIG_OPTIONS_OVERRIDE)
        .map_err(registry_error)?;
    let namespace_refs: Vec<&str> = rule.namespaces.iter().map(|s| s.as_str()).collect();
    dnskey
        .set_multi_string("Name", &namespace_refs)
        .map_err(registry_error)?;
    let servers = rule
        .servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(";");
    dnskey
        .set_string("GenericDNSServers", servers)
        .map_err(registry_error)?;
    dnskey
        .set_string("DisplayName", "osdns")
        .map_err(registry_error)?;
    dnskey
        .set_string("Comment", marker_for(owner))
        .map_err(registry_error)?;
    Ok(())
}

pub(crate) fn delete_rule(key: &str) -> Result<()> {
    let base = match LOCAL_MACHINE
        .options()
        .read()
        .write()
        .access(0x0001_0000)
        .open(NRPT_BASE)
    {
        Ok(base) => base,
        Err(error) if error.code() == windows::core::HRESULT::from_win32(2) => return Ok(()),
        Err(error) => return Err(registry_error(error)),
    };
    match base.remove_tree(key) {
        Ok(()) => Ok(()),
        Err(error) if error.code() == windows::core::HRESULT::from_win32(2) => Ok(()),
        Err(error) => Err(registry_error(error)),
    }
}

fn registry_error<E: std::fmt::Display>(error: E) -> Error {
    let text = error.to_string();
    let lowered = text.to_ascii_lowercase();
    if lowered.contains("denied") || lowered.contains("os error 5") {
        return Error::RequiresPrivilege(format!(
            "NRPT registry operation requires administrator privileges: {text}"
        ));
    }
    Error::Platform {
        backend: BackendKind::WindowsIpHelper,
        message: format!("NRPT registry error: {text}"),
    }
}

/// Reads one rule by its registry key regardless of marker, so a captured
/// `before` rule can be restored even if the marker changed.
pub(crate) fn read_rule_by_key(key: &str) -> Result<Option<NrptRule>> {
    let base = match LOCAL_MACHINE.open(NRPT_BASE) {
        Ok(base) => base,
        Err(error) if error.code() == windows::core::HRESULT::from_win32(2) => return Ok(None),
        Err(error) => return Err(registry_error(error)),
    };
    let rule_key = match base.open(key) {
        Ok(rule_key) => rule_key,
        Err(error) if error.code() == windows::core::HRESULT::from_win32(2) => return Ok(None),
        Err(error) => return Err(registry_error(error)),
    };
    let namespaces = rule_key.get_multi_string("Name").unwrap_or_default();
    if namespaces.is_empty() {
        return Ok(None);
    }
    let servers = rule_key
        .get_string("GenericDNSServers")
        .unwrap_or_default()
        .split([';', ','])
        .filter_map(|entry| entry.trim().parse::<IpAddr>().ok())
        .collect();
    Ok(Some(NrptRule {
        key: key.to_string(),
        namespaces,
        servers,
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::{DnsSuffix, NormalizedConfig};

    fn plan(ns: &[&str], routing: &[&str]) -> NormalizedConfig {
        NormalizedConfig {
            nameservers: ns.iter().map(|s| s.parse().unwrap()).collect(),
            search_domains: vec![],
            routing_domains: routing
                .iter()
                .map(|s| DnsSuffix::parse(s).unwrap())
                .collect(),
            default_route: None,
        }
    }

    #[test]
    fn namespaces_use_leading_dot_form() {
        let p = plan(&["1.1.1.1"], &["corp.example", "."]);
        let chunks = namespaces_from_plan(&p);
        assert_eq!(
            chunks,
            vec![vec![".corp.example".to_string(), ".".to_string()]]
        );
    }

    #[test]
    fn default_route_implies_root_namespace() {
        let mut p = plan(&["1.1.1.1"], &[]);
        p.default_route = Some(true);
        assert_eq!(namespaces_from_plan(&p), vec![vec![".".to_string()]]);
        p.default_route = Some(false);
        assert!(namespaces_from_plan(&p).is_empty());
        p.default_route = None;
        assert!(namespaces_from_plan(&p).is_empty());
    }

    #[test]
    fn rule_keys_are_deterministic_per_owner_and_namespaces() {
        let p = plan(&["1.1.1.1"], &["corp.example"]);
        let first = rules_from_plan(&p, "io.test.a");
        let again = rules_from_plan(&p, "io.test.a");
        assert_eq!(first, again);

        let other_owner = rules_from_plan(&p, "io.test.b");
        assert_ne!(first[0].key, other_owner[0].key);

        let p2 = plan(&["1.1.1.1"], &["other.example"]);
        let different = rules_from_plan(&p2, "io.test.a");
        assert_ne!(first[0].key, different[0].key);
    }

    #[test]
    fn servers_come_from_the_plan() {
        let p = plan(&["1.1.1.1", "8.8.8.8"], &["corp.example"]);
        let rules = rules_from_plan(&p, "io.test");
        assert_eq!(
            rules[0].servers,
            vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "8.8.8.8".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn marker_includes_owner() {
        assert_eq!(marker_for("io.tunnet.agent"), "osdns owner=io.tunnet.agent");
    }
}
