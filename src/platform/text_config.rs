//! Target-independent helpers shared by the POSIX-family backends: canonical
//! resolv.conf text, resolved/NM DNS field mappings, and NetworkManager
//! configuration parsing. Pure functions, unit-tested on every platform.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::normalize::{DnsSuffix, NormalizedConfig};

pub(crate) fn build_resolv_conf_content(plan: &NormalizedConfig) -> Vec<u8> {
    let mut text = String::new();
    for ns in &plan.nameservers {
        text.push_str(&format!("nameserver {ns}\n"));
    }
    let search: Vec<&DnsSuffix> = plan
        .search_domains
        .iter()
        .filter(|d| !d.is_root())
        .collect();
    if !search.is_empty() {
        let names: Vec<String> = search.iter().map(|d| d.to_string()).collect();
        text.push_str(&format!("search {}\n", names.join(" ")));
    }
    text.into_bytes()
}

pub(crate) fn parse_resolv_conf_content(bytes: &[u8]) -> Result<(Vec<IpAddr>, Vec<DnsSuffix>)> {
    let config = resolv_conf::Config::parse(bytes)
        .map_err(|e| Error::invalid_config(format_args!("unparseable resolv.conf content: {e}")))?;
    let nameservers = config.nameservers.iter().map(IpAddr::from).collect();
    let mut search = Vec::new();
    for domain in config.get_last_search_or_domain() {
        let suffix = DnsSuffix::parse(domain)?;
        if !search.contains(&suffix) {
            search.push(suffix);
        }
    }
    Ok((nameservers, search))
}

pub(crate) fn resolved_dns_from_plan(plan: &NormalizedConfig) -> Vec<(i32, Vec<u8>)> {
    plan.nameservers
        .iter()
        .map(|ip| match ip {
            // Linux AF_INET/AF_INET6 are the tuple's first field, not a
            // byte prepended to the address. These are wire constants,
            // independent of the host compiling this shared module.
            IpAddr::V4(v4) => (2, v4.octets().to_vec()),
            IpAddr::V6(v6) => (10, v6.octets().to_vec()),
        })
        .collect()
}

pub(crate) fn resolved_dns_to_nameservers(dns: &[(i32, Vec<u8>)]) -> Vec<IpAddr> {
    dns.iter()
        .filter_map(|(family, bytes)| match (*family, bytes.as_slice()) {
            (2, [a, b, c, d]) => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
            (10, bytes) => {
                let octets: [u8; 16] = bytes.try_into().ok()?;
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn resolved_domains_from_plan(plan: &NormalizedConfig) -> Vec<(String, bool)> {
    let mut domains: Vec<(String, bool)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for domain in &plan.search_domains {
        let name = domain.to_string();
        if !seen.contains(&name) {
            seen.push(name.clone());
            domains.push((name, false));
        }
    }
    for domain in &plan.routing_domains {
        let name = domain.to_string();
        if !seen.contains(&name) {
            seen.push(name.clone());
            domains.push((name, true));
        }
    }
    domains
}

pub(crate) fn resolved_domains_to_public(
    domains: &[(String, bool)],
) -> (Vec<DnsSuffix>, Vec<DnsSuffix>) {
    let mut search = Vec::new();
    let mut routing = Vec::new();
    for (name, route_only) in domains {
        let Ok(suffix) = DnsSuffix::parse(name) else {
            continue;
        };
        if !route_only {
            if !search.contains(&suffix) {
                search.push(suffix);
            }
        } else if !routing.contains(&suffix) {
            routing.push(suffix);
        }
    }
    (search, routing)
}

/// The DNS-related fields of a NetworkManager applied connection, per
/// address family. This is the exact set osdns reads, writes, and restores;
/// every other field of the connection is passed through untouched.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NmDnsFields {
    pub(crate) ipv4_dns: Vec<u32>,
    pub(crate) ipv4_dns_search: Vec<String>,
    pub(crate) ipv4_ignore_auto_dns: bool,
    pub(crate) ipv4_dns_priority: Option<i32>,
    pub(crate) ipv6_dns: Vec<Vec<u8>>,
    pub(crate) ipv6_dns_search: Vec<String>,
    pub(crate) ipv6_ignore_auto_dns: bool,
    pub(crate) ipv6_dns_priority: Option<i32>,
}

impl NmDnsFields {
    pub(crate) fn from_plan(plan: &NormalizedConfig, split_dns: bool) -> Self {
        let mut fields = Self::default();
        for ip in &plan.nameservers {
            match ip {
                IpAddr::V4(v4) => fields.ipv4_dns.push(u32::from_be_bytes(v4.octets())),
                IpAddr::V6(v6) => fields.ipv6_dns.push(v6.octets().to_vec()),
            }
        }
        let mut search: Vec<String> = Vec::new();
        for domain in &plan.search_domains {
            if domain.is_root() {
                continue;
            }
            let name = domain.as_str().to_string();
            if !search.contains(&name) {
                search.push(name);
            }
        }
        let mut routing: Vec<String> = Vec::new();
        if split_dns {
            for domain in &plan.routing_domains {
                // The root domain is the NetworkManager wildcard `~.`;
                // never the accidental empty-string form `~`.
                let name = domain.to_string();
                if !search.contains(&name) && !routing.contains(&name) {
                    routing.push(name);
                }
            }
        }
        let search_entries = search
            .iter()
            .cloned()
            .chain(routing.iter().map(|r| format!("~{r}")))
            .collect::<Vec<String>>();
        fields.ipv4_dns_search = search_entries.clone();
        fields.ipv6_dns_search = search_entries;
        fields.ipv4_ignore_auto_dns = true;
        fields.ipv6_ignore_auto_dns = true;
        fields
    }
}

/// Splits NetworkManager `dns-search` entries into `(search, routing)`.
///
/// Entries starting with `~` are routing domains; the wildcard default route
/// is the canonical `~.` (a bare legacy `~` is also accepted as the root).
/// Anything else is a plain search domain.
pub(crate) fn parse_nm_search_entries(entries: &[String]) -> (Vec<DnsSuffix>, Vec<DnsSuffix>) {
    let mut search = Vec::new();
    let mut routing = Vec::new();
    for entry in entries {
        if let Some(rest) = entry.strip_prefix('~') {
            // `~.` is the canonical wildcard; accept a bare `~` as the same
            // root for backward compatibility with older state.
            let name = if rest.is_empty() { "." } else { rest };
            let Ok(suffix) = DnsSuffix::parse(name) else {
                continue;
            };
            if !routing.contains(&suffix) {
                routing.push(suffix);
            }
        } else {
            let Ok(suffix) = DnsSuffix::parse(entry) else {
                continue;
            };
            if !search.contains(&suffix) {
                search.push(suffix);
            }
        }
    }
    (search, routing)
}

pub(crate) fn parse_nm_dns_fields(
    settings: &HashMap<String, HashMap<String, SettingValue>>,
) -> NmDnsFields {
    let mut fields = NmDnsFields::default();
    if let Some(ipv4) = settings.get("ipv4") {
        fields.ipv4_dns = string_keys(ipv4.get("dns"))
            .into_iter()
            .filter_map(|v| v.parse::<u32>().ok())
            .collect();
        fields.ipv4_dns_search = string_list(ipv4.get("dns-search"));
        fields.ipv4_ignore_auto_dns = bool_value(ipv4.get("ignore-auto-dns"));
        fields.ipv4_dns_priority = int_value(ipv4.get("dns-priority"));
    }
    if let Some(ipv6) = settings.get("ipv6") {
        fields.ipv6_dns = byte_array_list(ipv6.get("dns"));
        fields.ipv6_dns_search = string_list(ipv6.get("dns-search"));
        fields.ipv6_ignore_auto_dns = bool_value(ipv6.get("ignore-auto-dns"));
        fields.ipv6_dns_priority = int_value(ipv6.get("dns-priority"));
    }
    fields
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SettingValue {
    Bool(bool),
    Int(i32),
    Uint(u32),
    Str(String),
    StrList(Vec<String>),
    UintList(Vec<u32>),
    ByteArrayList(Vec<Vec<u8>>),
    Other,
}

fn string_keys(value: Option<&SettingValue>) -> Vec<String> {
    match value {
        Some(SettingValue::UintList(items)) => items.iter().map(|v| v.to_string()).collect(),
        _ => Vec::new(),
    }
}

fn string_list(value: Option<&SettingValue>) -> Vec<String> {
    match value {
        Some(SettingValue::StrList(items)) => items.clone(),
        _ => Vec::new(),
    }
}

fn bool_value(value: Option<&SettingValue>) -> bool {
    match value {
        Some(SettingValue::Bool(b)) => *b,
        _ => false,
    }
}

fn int_value(value: Option<&SettingValue>) -> Option<i32> {
    match value {
        Some(SettingValue::Int(i)) => Some(*i),
        _ => None,
    }
}

fn byte_array_list(value: Option<&SettingValue>) -> Vec<Vec<u8>> {
    match value {
        Some(SettingValue::ByteArrayList(items)) => items.clone(),
        _ => Vec::new(),
    }
}

/// The DNS-relevant knobs of NetworkManager's main configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NmMainConf {
    pub(crate) dns: Option<String>,
    pub(crate) rc_manager: Option<String>,
}

pub(crate) fn parse_nm_main_conf(text: &str) -> NmMainConf {
    let mut conf = NmMainConf::default();
    let mut in_main = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let inner = line.trim_start_matches('[').trim_end_matches(']');
            in_main = inner.eq_ignore_ascii_case("main");
            continue;
        }
        if !in_main {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_ascii_lowercase();
            match key.as_str() {
                "dns" => conf.dns = Some(value),
                "rc-manager" => conf.rc_manager = Some(value),
                _ => {}
            }
        }
    }
    conf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(
        ns: &[&str],
        search: &[&str],
        routing: &[&str],
        default_route: Option<bool>,
    ) -> NormalizedConfig {
        NormalizedConfig {
            nameservers: ns.iter().map(|s| s.parse().unwrap()).collect(),
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

    #[test]
    fn resolv_conf_content_roundtrip() {
        let p = plan(
            &["1.1.1.1", "2606:4700:4700::1111"],
            &["Example.COM", "corp.example"],
            &[],
            None,
        );
        let content = build_resolv_conf_content(&p);
        let text = String::from_utf8(content.clone()).unwrap();
        assert_eq!(
            text,
            "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\nsearch example.com corp.example\n"
        );
        let (ns, search) = parse_resolv_conf_content(&content).unwrap();
        assert_eq!(ns, p.nameservers);
        assert_eq!(search, p.search_domains);
    }

    #[test]
    fn resolv_conf_content_is_deterministic() {
        let p = plan(&["8.8.8.8"], &["a.example"], &[], None);
        assert_eq!(build_resolv_conf_content(&p), build_resolv_conf_content(&p));
    }

    #[test]
    fn resolved_dns_mapping() {
        let p = plan(&["1.1.1.1", "2606:4700:4700::1111"], &[], &[], None);
        let dns = resolved_dns_from_plan(&p);
        assert_eq!(dns[0], (2, vec![1, 1, 1, 1]));
        assert_eq!(
            dns[1],
            (
                10,
                vec![38, 6, 71, 0, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 17]
            )
        );
        let back = resolved_dns_to_nameservers(&dns);
        assert_eq!(back, p.nameservers);
    }

    #[test]
    fn resolved_domains_search_implies_routing() {
        let p = plan(
            &[],
            &["corp.example"],
            &["corp.example", "internal.example"],
            None,
        );
        let domains = resolved_domains_from_plan(&p);
        assert_eq!(
            domains,
            vec![
                ("corp.example".to_string(), false),
                ("internal.example".to_string(), true),
            ]
        );
        let (search, routing) = resolved_domains_to_public(&domains);
        assert_eq!(search, p.search_domains);
        assert_eq!(routing, vec![DnsSuffix::parse("internal.example").unwrap()]);
    }

    #[test]
    fn resolved_root_routing_domain_uses_dot_and_route_only() {
        let p = plan(&[], &[], &["."], None);
        let domains = resolved_domains_from_plan(&p);
        assert_eq!(domains, vec![(".".to_string(), true)]);
        let (search, routing) = resolved_domains_to_public(&domains);
        assert!(search.is_empty());
        assert_eq!(routing, vec![DnsSuffix::root()]);
    }

    #[test]
    fn nm_fields_from_plan() {
        let p = plan(
            &["8.8.8.8", "2001:4860:4860::8888"],
            &["corp.example"],
            &["internal.example"],
            None,
        );
        let fields = NmDnsFields::from_plan(&p, true);
        assert_eq!(fields.ipv4_dns, vec![u32::from_be_bytes([8, 8, 8, 8])]);
        assert_eq!(
            fields.ipv6_dns,
            vec![vec![
                0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88
            ]]
        );
        assert_eq!(
            fields.ipv4_dns_search,
            vec!["corp.example".to_string(), "~internal.example".to_string()]
        );
        assert_eq!(fields.ipv6_dns_search, fields.ipv4_dns_search);
        assert!(fields.ipv4_ignore_auto_dns && fields.ipv6_ignore_auto_dns);
    }

    #[test]
    fn nm_fields_root_routing_domain() {
        let p = plan(&[], &[], &["."], None);
        let fields = NmDnsFields::from_plan(&p, true);
        assert_eq!(fields.ipv4_dns_search, vec!["~.".to_string()]);
        assert_eq!(fields.ipv6_dns_search, vec!["~.".to_string()]);
    }

    #[test]
    fn nm_fields_without_split_dns_drop_routing() {
        let p = plan(&["1.1.1.1"], &["corp.example"], &["internal.example"], None);
        let fields = NmDnsFields::from_plan(&p, false);
        assert_eq!(fields.ipv4_dns_search, vec!["corp.example".to_string()]);
    }

    #[test]
    fn nm_root_routing_domain_serialization_is_canonical_wildcard() {
        let p = plan(&[], &[], &["."], None);
        let fields = NmDnsFields::from_plan(&p, true);
        assert_eq!(fields.ipv4_dns_search, vec!["~.".to_string()]);
        assert_eq!(fields.ipv6_dns_search, vec!["~.".to_string()]);
    }

    #[test]
    fn nm_root_routing_domain_parsing_roundtrip() {
        // Canonical form.
        let (search, routing) =
            parse_nm_search_entries(&["~.".to_string(), "corp.example".to_string()]);
        assert!(search == vec![DnsSuffix::parse("corp.example").unwrap()]);
        assert_eq!(routing, vec![DnsSuffix::root()]);
        // Legacy bare `~` is accepted as the same root.
        let (_, routing) = parse_nm_search_entries(&["~".to_string()]);
        assert_eq!(routing, vec![DnsSuffix::root()]);
    }

    #[test]
    fn nm_routing_entries_roundtrip_through_plan() {
        let p = plan(
            &["1.1.1.1"],
            &["corp.example"],
            &[".", "internal.example"],
            None,
        );
        let fields = NmDnsFields::from_plan(&p, true);
        assert!(fields.ipv4_dns_search.contains(&"~.".to_string()));
        assert!(
            fields
                .ipv4_dns_search
                .contains(&"~internal.example".to_string())
        );
        let (search, routing) = parse_nm_search_entries(&fields.ipv4_dns_search);
        assert_eq!(search, p.search_domains);
        assert_eq!(routing.len(), 2);
        assert!(routing.contains(&DnsSuffix::root()));
        assert!(routing.contains(&DnsSuffix::parse("internal.example").unwrap()));
    }

    #[test]
    fn nm_routing_matching_semantics_split_search_and_routing() {
        let (search, routing) = parse_nm_search_entries(&[
            "corp.example".to_string(),
            "~internal.example".to_string(),
            "~.".to_string(),
        ]);
        assert_eq!(search, vec![DnsSuffix::parse("corp.example").unwrap()]);
        assert!(routing.contains(&DnsSuffix::root()));
        assert!(routing.contains(&DnsSuffix::parse("internal.example").unwrap()));
        assert!(!routing.contains(&DnsSuffix::parse("corp.example").unwrap()));
    }

    #[test]
    fn nm_fields_parse_roundtrip() {
        let mut ipv4 = HashMap::new();
        ipv4.insert(
            "dns".to_string(),
            SettingValue::UintList(vec![u32::from_be_bytes([1, 2, 3, 4])]),
        );
        ipv4.insert(
            "dns-search".to_string(),
            SettingValue::StrList(vec!["a.example".to_string()]),
        );
        ipv4.insert("ignore-auto-dns".to_string(), SettingValue::Bool(true));
        ipv4.insert("dns-priority".to_string(), SettingValue::Int(-5));
        let mut ipv6 = HashMap::new();
        ipv6.insert(
            "dns".to_string(),
            SettingValue::ByteArrayList(vec![vec![0u8; 16]]),
        );
        let mut settings = HashMap::new();
        settings.insert("ipv4".to_string(), ipv4);
        settings.insert("ipv6".to_string(), ipv6);

        let fields = parse_nm_dns_fields(&settings);
        assert_eq!(fields.ipv4_dns, vec![u32::from_be_bytes([1, 2, 3, 4])]);
        assert_eq!(fields.ipv4_dns_search, vec!["a.example"]);
        assert!(fields.ipv4_ignore_auto_dns);
        assert_eq!(fields.ipv4_dns_priority, Some(-5));
        assert_eq!(fields.ipv6_dns, vec![vec![0u8; 16]]);
        assert!(fields.ipv6_dns_search.is_empty());
        assert_eq!(fields.ipv6_dns_priority, None);
    }

    #[test]
    fn nm_conf_parsing() {
        let conf =
            parse_nm_main_conf("[main]\ndns=dnsmasq\nrc-manager=symlink\n[logging]\nlevel=DEBUG\n");
        assert_eq!(conf.dns.as_deref(), Some("dnsmasq"));
        assert_eq!(conf.rc_manager.as_deref(), Some("symlink"));

        let conf = parse_nm_main_conf("# nothing here\n[other]\ndns=ignored\n");
        assert_eq!(conf, NmMainConf::default());

        let conf = parse_nm_main_conf("[main]\nDNS = SYSTEMD-RESOLVED\n");
        assert_eq!(conf.dns.as_deref(), Some("systemd-resolved"));
    }
}
