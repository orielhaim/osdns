//! Name Resolution Policy Table (NRPT) rules in the Windows registry.
//!
//! Rules are additive and independently owned: osdns only ever creates,
//! reads, updates, and deletes registry keys whose GUID is derived
//! deterministically from the owner and the namespace set, and whose
//! `Comment` value marks them as osdns-owned. Rules created by other
//! applications, by administrators, or by Group Policy are never touched.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use windows_registry::Key;

use crate::capability::BackendKind;
use crate::error::{ConflictReason, Error, Result};
use crate::ownership::ResourceId;
use crate::platform::windows::error::{map_error, registry_not_found};
use crate::platform::windows::ffi::{GUID, create_hklm, open_hklm};
use crate::platform::windows::interface::{guid_from_u128, guid_to_string};

pub(super) const NRPT_BASE: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
const MAX_NAMESPACES_PER_RULE: usize = 50;
const CONFIG_OPTIONS_OVERRIDE: u32 = 0x8;
const MARKER_PREFIX: &str = "osdns owner=";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NrptRule {
    pub(crate) key: String,
    pub(crate) version: u32,
    pub(crate) config_options: u32,
    pub(crate) namespaces: Vec<String>,
    pub(crate) servers: Vec<IpAddr>,
    pub(crate) display_name: String,
    pub(crate) comment: String,
}

pub(crate) fn marker_for(owner: &str) -> String {
    format!("{MARKER_PREFIX}{owner}")
}

const RULE_KEY_NAMESPACE: u128 = 0x6f73_646e_7372_7074_5f6e_7370_0000_0001;

fn rule_key(owner: &str, namespaces: &[String]) -> GUID {
    let seed_namespace = uuid::Uuid::from_u128(RULE_KEY_NAMESPACE);
    let name = format!("osdns-nrpt\x00{owner}\x00{}", namespaces.join("\u{1f}"));
    guid_from_u128(uuid::Uuid::new_v5(&seed_namespace, name.as_bytes()).as_u128())
}

fn open_nrpt_base(write: bool) -> windows_registry::Result<Key> {
    open_hklm(NRPT_BASE, write)
}

fn create_rule_key(key: &str) -> windows_registry::Result<Key> {
    create_hklm(&format!(r"{NRPT_BASE}\{key}"))
}

/// Splits routing domains into NRPT-conformant namespace chunks.
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
                key: guid_to_string(&key),
                version: 1,
                config_options: CONFIG_OPTIONS_OVERRIDE,
                namespaces: chunk,
                servers: plan.nameservers.clone(),
                display_name: "osdns".to_string(),
                comment: marker_for(owner),
            }
        })
        .collect()
}

pub(crate) fn write_rule(rule: &NrptRule, owner: &str, resource: &ResourceId) -> Result<()> {
    reject_foreign_rule(&rule.key, owner, resource)?;
    let dnskey = create_rule_key(&rule.key).map_err(|e| map_error(e, "NRPT create"))?;
    write_rule_values(&dnskey, rule)
}

fn write_rule_values(dnskey: &Key, rule: &NrptRule) -> Result<()> {
    dnskey
        .set_u32("Version", rule.version)
        .map_err(|e| map_error(e, "NRPT set Version"))?;
    dnskey
        .set_u32("ConfigOptions", rule.config_options)
        .map_err(|e| map_error(e, "NRPT set ConfigOptions"))?;
    let namespace_refs: Vec<&str> = rule.namespaces.iter().map(|s| s.as_str()).collect();
    dnskey
        .set_multi_string("Name", &namespace_refs)
        .map_err(|e| map_error(e, "NRPT set Name"))?;
    let servers = rule
        .servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(";");
    dnskey
        .set_string("GenericDNSServers", servers)
        .map_err(|e| map_error(e, "NRPT set GenericDNSServers"))?;
    dnskey
        .set_string("DisplayName", &rule.display_name)
        .map_err(|e| map_error(e, "NRPT set DisplayName"))?;
    dnskey
        .set_string("Comment", &rule.comment)
        .map_err(|e| map_error(e, "NRPT set Comment"))?;
    Ok(())
}

pub(crate) fn delete_rule(key: &str, owner: &str, resource: &ResourceId) -> Result<()> {
    reject_foreign_rule(key, owner, resource)?;
    let base = match open_nrpt_base(true) {
        Ok(base) => base,
        Err(error) if registry_not_found(&error) => return Ok(()),
        Err(error) => return Err(map_error(error, "NRPT open for delete")),
    };
    match base.remove_tree(key) {
        Ok(()) => Ok(()),
        Err(error) if registry_not_found(&error) => Ok(()),
        Err(error) => Err(map_error(error, "NRPT delete")),
    }
}

pub(crate) fn read_owned_rule_by_key(
    key: &str,
    owner: &str,
    resource: &ResourceId,
) -> Result<Option<NrptRule>> {
    let base = match open_nrpt_base(false) {
        Ok(base) => base,
        Err(error) if registry_not_found(&error) => return Ok(None),
        Err(error) => return Err(map_error(error, "NRPT open")),
    };
    let rule_key = match base.open(key) {
        Ok(rule_key) => rule_key,
        Err(error) if registry_not_found(&error) => return Ok(None),
        Err(error) => return Err(map_error(error, "NRPT open rule")),
    };
    let comment = read_marker(&rule_key, resource)?;
    verify_marker(&comment, owner, resource)?;
    read_rule_values(&rule_key, key, comment).map(Some)
}

fn reject_foreign_rule(key: &str, owner: &str, resource: &ResourceId) -> Result<()> {
    let base = match open_nrpt_base(false) {
        Ok(base) => base,
        Err(error) if registry_not_found(&error) => return Ok(()),
        Err(error) => return Err(map_error(error, "NRPT open")),
    };
    let rule_key = match base.open(key) {
        Ok(rule_key) => rule_key,
        Err(error) if registry_not_found(&error) => return Ok(()),
        Err(error) => return Err(map_error(error, "NRPT open rule")),
    };
    let marker = read_marker(&rule_key, resource)?;
    verify_marker(&marker, owner, resource)
}

fn read_marker(rule_key: &Key, resource: &ResourceId) -> Result<String> {
    match rule_key.get_string("Comment") {
        Ok(marker) => Ok(marker),
        Err(error) if registry_not_found(&error) => Err(occupied(resource, "<missing>")),
        Err(error) => Err(map_error(error, "NRPT read Comment")),
    }
}

fn verify_marker(marker: &str, owner: &str, resource: &ResourceId) -> Result<()> {
    (marker == marker_for(owner))
        .then_some(())
        .ok_or_else(|| occupied(resource, marker))
}

fn occupied(resource: &ResourceId, marker: &str) -> Error {
    Error::Conflict {
        resource: resource.clone(),
        reason: ConflictReason::ResourceOccupied {
            detail: format!("NRPT rule is not owned by this osdns owner (marker {marker:?})"),
        },
    }
}

fn read_rule_values(rule_key: &Key, key: &str, comment: String) -> Result<NrptRule> {
    // windows-registry 0.100 strictly parses REG_MULTI_SZ (double-NUL, UTF-16).
    // Malformed values are errors, not absence.
    let namespaces = rule_key
        .get_multi_string("Name")
        .map_err(|e| map_error(e, "NRPT read Name"))?;
    if namespaces.is_empty() {
        return Err(Error::platform(
            BackendKind::WindowsIpHelper,
            "owned NRPT rule has no namespaces",
        ));
    }
    let raw_servers = rule_key
        .get_string("GenericDNSServers")
        .map_err(|e| map_error(e, "NRPT read GenericDNSServers"))?;
    let servers = raw_servers
        .split([';', ','])
        .map(|entry| entry.trim().parse::<IpAddr>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::platform(BackendKind::WindowsIpHelper, error))?;
    if servers.is_empty() {
        return Err(Error::platform(
            BackendKind::WindowsIpHelper,
            "owned NRPT rule has no DNS servers",
        ));
    }
    Ok(NrptRule {
        key: key.to_string(),
        version: rule_key
            .get_u32("Version")
            .map_err(|e| map_error(e, "NRPT read Version"))?,
        config_options: rule_key
            .get_u32("ConfigOptions")
            .map_err(|e| map_error(e, "NRPT read ConfigOptions"))?,
        namespaces,
        servers,
        display_name: rule_key
            .get_string("DisplayName")
            .map_err(|e| map_error(e, "NRPT read DisplayName"))?,
        comment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::{DnsSuffix, NormalizedConfig};
    use windows_registry::{CURRENT_USER, Type};

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

    fn volatile_key(path: &str) -> Key {
        CURRENT_USER
            .options()
            .read()
            .write()
            .create()
            .volatile()
            .open(path)
            .unwrap()
    }

    #[test]
    fn native_registry_rule_roundtrip() {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let key = volatile_key(&path);
        let rule =
            rules_from_plan(&plan(&["127.0.0.1", "::1"], &["matrix.test"]), "io.test").remove(0);
        let result = std::panic::catch_unwind(|| {
            write_rule_values(&key, &rule).unwrap();
            assert_eq!(
                read_rule_values(&key, &rule.key, marker_for("io.test")).unwrap(),
                rule
            );
        });
        drop(key);
        CURRENT_USER.remove_tree(&path).unwrap();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn multi_sz_malformed_terminator_is_error_not_absence() {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let key = volatile_key(&path);
        // Single trailing NUL only — invalid for a non-empty REG_MULTI_SZ list.
        let bytes: Vec<u8> = "a\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        key.set_bytes("Name", Type::MultiString, &bytes).unwrap();
        let error = key.get_multi_string("Name").unwrap_err();
        drop(key);
        CURRENT_USER.remove_tree(&path).unwrap();
        // Must not look like "value missing".
        assert!(!registry_not_found(&error));
    }

    #[test]
    fn multi_sz_malformed_utf16_is_error() {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let key = volatile_key(&path);
        // Odd-length / unpaired surrogate payload with double-NUL terminator shape.
        let bytes = vec![0x00, 0xD8, 0x00, 0x00, 0x00, 0x00];
        key.set_bytes("Name", Type::MultiString, &bytes).unwrap();
        let error = key.get_multi_string("Name").unwrap_err();
        drop(key);
        CURRENT_USER.remove_tree(&path).unwrap();
        assert!(!registry_not_found(&error));
    }

    #[test]
    fn missing_marker_is_rejected_as_occupied() {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let key = volatile_key(&path);
        let resource = ResourceId::new("windows:nrpt:test").unwrap();
        let error = read_marker(&key, &resource).unwrap_err();
        drop(key);
        CURRENT_USER.remove_tree(&path).unwrap();
        assert!(matches!(
            error,
            Error::Conflict {
                reason: ConflictReason::ResourceOccupied { .. },
                ..
            }
        ));
    }

    #[test]
    fn wrong_owner_marker_is_occupied() {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let key = volatile_key(&path);
        let rule = rules_from_plan(&plan(&["1.1.1.1"], &["corp.example"]), "io.owner").remove(0);
        write_rule_values(&key, &rule).unwrap();
        let resource = ResourceId::new("windows:nrpt:test").unwrap();
        let marker = read_marker(&key, &resource).unwrap();
        let error = verify_marker(&marker, "io.other", &resource).unwrap_err();
        drop(key);
        CURRENT_USER.remove_tree(&path).unwrap();
        assert!(matches!(
            error,
            Error::Conflict {
                reason: ConflictReason::ResourceOccupied { .. },
                ..
            }
        ));
    }

    #[test]
    fn correct_owner_update_roundtrip() {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let key = volatile_key(&path);
        let mut rule = rules_from_plan(&plan(&["1.1.1.1"], &["corp.example"]), "io.test").remove(0);
        write_rule_values(&key, &rule).unwrap();
        rule.servers = vec!["8.8.8.8".parse().unwrap()];
        write_rule_values(&key, &rule).unwrap();
        let read = read_rule_values(&key, &rule.key, marker_for("io.test")).unwrap();
        drop(key);
        CURRENT_USER.remove_tree(&path).unwrap();
        assert_eq!(read.servers, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
        assert_eq!(read.comment, marker_for("io.test"));
    }

    #[test]
    fn canonical_snapshot_is_lossless() {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let key = volatile_key(&path);
        let rule = rules_from_plan(
            &plan(
                &["1.1.1.1", "2606:4700:4700::1111"],
                &["corp.example", "lab.example"],
            ),
            "io.test",
        )
        .remove(0);
        write_rule_values(&key, &rule).unwrap();
        let restored = read_rule_values(&key, &rule.key, marker_for("io.test")).unwrap();
        drop(key);
        CURRENT_USER.remove_tree(&path).unwrap();
        assert_eq!(restored, rule);
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

    #[test]
    fn foreign_marker_is_rejected_as_occupied() {
        let resource = ResourceId::new("windows:nrpt:test").unwrap();
        let error = verify_marker(&marker_for("io.foreign"), "io.test", &resource).unwrap_err();
        assert!(matches!(
            error,
            Error::Conflict {
                reason: ConflictReason::ResourceOccupied { .. },
                ..
            }
        ));
    }
}
