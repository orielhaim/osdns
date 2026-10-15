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
use crate::platform::windows::ffi::{self, GUID, create_hklm, open_hklm};
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

fn create_rule_key(key: &str) -> Result<(Key, bool)> {
    let base = create_hklm(NRPT_BASE).map_err(|error| map_error(error, "NRPT open for create"))?;
    create_child_key(&base, key)
}

fn create_child_key(base: &Key, key: &str) -> Result<(Key, bool)> {
    let name: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
    let mut raw = std::ptr::null_mut();
    let mut disposition = 0;
    // SAFETY: base and name are live, outputs are writable; success transfers one HKEY.
    let status = unsafe {
        ffi::RegCreateKeyExW(
            base.as_raw(),
            name.as_ptr(),
            0,
            std::ptr::null(),
            ffi::REG_OPTION_NON_VOLATILE as u32,
            (ffi::KEY_READ | ffi::KEY_WRITE | ffi::KEY_WOW64_64KEY) as u32 | 0x0001_0000,
            std::ptr::null(),
            &mut raw,
            &mut disposition,
        )
    };
    super::error::check_status(status, "NRPT create")?;
    // SAFETY: the successful create call transferred the returned handle.
    Ok((
        unsafe { Key::from_raw(raw) },
        disposition == ffi::REG_CREATED_NEW_KEY as u32,
    ))
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
    validate_rule(rule, owner)?;
    reject_foreign_rule(&rule.key, owner, resource)?;
    let (dnskey, created) = create_rule_key(&rule.key)?;
    if !created {
        let marker = read_marker(&dnskey, resource)?;
        verify_marker(&marker, owner, resource)?;
        let before = read_rule_values(&dnskey, &rule.key, marker)?;
        validate_rule(&before, owner)?;
        return write_rule_values(&dnskey, rule, Some(&before));
    }
    match write_rule_values(&dnskey, rule, None) {
        Ok(()) => Ok(()),
        Err(primary) => match delete_created_key(&dnskey) {
            Ok(()) => Err(primary),
            Err(error) => Err(Error::TransactionFailed {
                primary: Box::new(primary),
                cleanup: vec![error],
            }),
        },
    }
}

fn delete_created_key(key: &Key) -> Result<()> {
    windows_link::link!("ntdll.dll" "system" fn NtDeleteKey(key: *mut core::ffi::c_void) -> i32);
    // SAFETY: this handle refers to the exact newly created object and carries DELETE.
    let status = unsafe { NtDeleteKey(key.as_raw()) };
    if status >= 0 {
        Ok(())
    } else {
        Err(Error::platform(
            BackendKind::WindowsIpHelper,
            format_args!("NtDeleteKey failed with NTSTATUS {status:#x}"),
        ))
    }
}

fn write_rule_values(dnskey: &Key, rule: &NrptRule, previous: Option<&NrptRule>) -> Result<()> {
    write_rule_values_with(dnskey, rule, previous, |_| Ok(()))
}

fn write_rule_values_with(
    dnskey: &Key,
    rule: &NrptRule,
    previous: Option<&NrptRule>,
    mut before_write: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let servers = rule
        .servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(";");
    if let Some(before) = previous {
        if before.key != rule.key
            || before.version != rule.version
            || before.config_options != rule.config_options
            || before.namespaces != rule.namespaces
            || before.display_name != rule.display_name
            || before.comment != rule.comment
        {
            return Err(Error::JournalCorrupt(
                "existing NRPT rule changes immutable policy fields".to_string(),
            ));
        }
        if before.servers == rule.servers {
            return Ok(());
        }
        // Only this value can change for a validated existing rule; publish it once.
        before_write("GenericDNSServers")?;
        dnskey
            .set_string("GenericDNSServers", servers)
            .map_err(|e| map_error(e, "NRPT update GenericDNSServers"))?;
        before_write("AfterGenericDNSServers")?;
        return Ok(());
    }
    before_write("Comment")?;
    dnskey
        .set_string("Comment", &rule.comment)
        .map_err(|e| map_error(e, "NRPT set Comment"))?;
    before_write("Version")?;
    dnskey
        .set_u32("Version", rule.version)
        .map_err(|e| map_error(e, "NRPT set Version"))?;
    before_write("Name")?;
    let namespace_refs: Vec<&str> = rule.namespaces.iter().map(|s| s.as_str()).collect();
    dnskey
        .set_multi_string("Name", &namespace_refs)
        .map_err(|e| map_error(e, "NRPT set Name"))?;
    before_write("GenericDNSServers")?;
    dnskey
        .set_string("GenericDNSServers", servers)
        .map_err(|e| map_error(e, "NRPT set GenericDNSServers"))?;
    before_write("DisplayName")?;
    dnskey
        .set_string("DisplayName", &rule.display_name)
        .map_err(|e| map_error(e, "NRPT set DisplayName"))?;
    before_write("ConfigOptions")?;
    dnskey
        .set_u32("ConfigOptions", rule.config_options)
        .map_err(|e| map_error(e, "NRPT set ConfigOptions"))?;
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
    let rule = read_rule_values(&rule_key, key, comment)?;
    validate_rule(&rule, owner).map_err(|error| Error::ExternalModification {
        resource: resource.clone(),
        detail: error.to_string(),
    })?;
    Ok(Some(rule))
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

pub(crate) fn validate_rule(rule: &NrptRule, owner: &str) -> Result<()> {
    let valid_namespaces = !rule.namespaces.is_empty()
        && rule.namespaces.len() <= MAX_NAMESPACES_PER_RULE
        && rule.namespaces.iter().all(|namespace| {
            namespace == "."
                || namespace
                    .strip_prefix('.')
                    .and_then(|domain| crate::DnsSuffix::parse(domain).ok())
                    .is_some_and(|domain| !domain.is_root() && namespace == &format!(".{domain}"))
        });
    if !valid_namespaces
        || rule.key != guid_to_string(&rule_key(owner, &rule.namespaces))
        || rule.comment != marker_for(owner)
        || rule.servers.is_empty()
        || rule.servers.iter().any(|server| server.is_unspecified())
        || rule.version != 1
        || rule.config_options != CONFIG_OPTIONS_OVERRIDE
        || rule.display_name != "osdns"
    {
        return Err(Error::JournalCorrupt(
            "NRPT rule has invalid policy fields or resource binding".to_string(),
        ));
    }
    Ok(())
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
    fn newly_created_unmarked_key_cleanup_uses_object_handle() {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let base = CURRENT_USER.create(&path).unwrap();
        let (created, is_new) = create_child_key(&base, "original").unwrap();
        assert!(is_new);
        let (_, existing) = create_child_key(&base, "original").unwrap();
        assert!(!existing);
        base.rename("original", "retained").unwrap();
        let replacement = base.create("original").unwrap();
        replacement.set_string("Comment", "foreign").unwrap();
        delete_created_key(&created).unwrap();
        drop(created);
        assert!(registry_not_found(&base.open("retained").unwrap_err()));
        assert_eq!(replacement.get_string("Comment").unwrap(), "foreign");
        drop(replacement);
        drop(base);
        CURRENT_USER.remove_tree(&path).unwrap();
    }

    #[test]
    fn native_registry_rule_roundtrip() {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let key = volatile_key(&path);
        let rule =
            rules_from_plan(&plan(&["127.0.0.1", "::1"], &["matrix.test"]), "io.test").remove(0);
        let result = std::panic::catch_unwind(|| {
            write_rule_values(&key, &rule, None).unwrap();
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
        write_rule_values(&key, &rule, None).unwrap();
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

    #[rstest::rstest]
    #[case(None)]
    #[case(Some("GenericDNSServers"))]
    #[case(Some("AfterGenericDNSServers"))]
    fn existing_rule_update_is_one_value_even_when_interrupted(#[case] interruption: Option<&str>) {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let key = volatile_key(&path);
        let before = rules_from_plan(&plan(&["1.1.1.1"], &["corp.example"]), "io.test").remove(0);
        write_rule_values(&key, &before, None).unwrap();
        let mut rule = before.clone();
        rule.servers = vec!["8.8.8.8".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let result = write_rule_values_with(&key, &rule, Some(&before), |field| {
            if interruption == Some(field) {
                Err(Error::platform(
                    BackendKind::WindowsIpHelper,
                    "interrupted existing-rule update",
                ))
            } else {
                Ok(())
            }
        });
        assert_eq!(result.is_err(), interruption.is_some());
        let read = read_rule_values(&key, &rule.key, marker_for("io.test")).unwrap();
        assert_eq!(
            read,
            if interruption == Some("GenericDNSServers") {
                before.clone()
            } else {
                rule
            }
        );
        write_rule_values(&key, &before, Some(&read)).unwrap();
        assert_eq!(
            read_rule_values(&key, &before.key, marker_for("io.test")).unwrap(),
            before
        );
        drop(key);
        CURRENT_USER.remove_tree(&path).unwrap();
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
        write_rule_values(&key, &rule, None).unwrap();
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
    #[rstest::rstest]
    #[case("Comment")]
    #[case("Version")]
    #[case("Name")]
    #[case("GenericDNSServers")]
    #[case("DisplayName")]
    #[case("ConfigOptions")]
    fn interrupted_rule_construction_writes_config_options_last(#[case] fail: &str) {
        let path = format!(r"Software\osdns-test-{}", uuid::Uuid::new_v4());
        let key = volatile_key(&path);
        let rule = rules_from_plan(&plan(&["1.1.1.1"], &["corp.example"]), "io.test").remove(0);
        let result = write_rule_values_with(&key, &rule, None, |field| {
            if field == fail {
                Err(Error::platform(
                    BackendKind::WindowsIpHelper,
                    "injected value failure",
                ))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert!(registry_not_found(
            &key.get_u32("ConfigOptions").unwrap_err()
        ));
        if fail != "Comment" {
            assert_eq!(key.get_string("Comment").unwrap(), marker_for("io.test"));
        }
        write_rule_values(&key, &rule, None).unwrap();
        assert_eq!(
            read_rule_values(&key, &rule.key, marker_for("io.test")).unwrap(),
            rule
        );
        drop(key);
        CURRENT_USER.remove_tree(&path).unwrap();
    }
}
