use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// A validated, canonical DNS domain suffix.
///
/// Values are normalized once at the API boundary: IDNA (UTS #46) to ASCII,
/// lowercase, no trailing dot, RFC 1035 label and length rules. The root
/// domain is the empty name and renders as `.`; it selects the default route
/// on backends that support it (systemd-resolved, Windows NRPT). macOS
/// scoped resolvers cannot represent the root — use
/// [`DnsConfigBuilder::default_route`](crate::DnsConfigBuilder::default_route)
/// there instead.
///
/// Parses with [`DnsSuffix::parse`] or `"<name>".parse::<DnsSuffix>()`;
/// invalid names fail with [`Error::InvalidConfig`](crate::Error).
///
/// ```
/// # use osdns::DnsSuffix;
/// assert!(DnsSuffix::parse("Corp.EXAMPLE.").unwrap().as_str() == "corp.example");
/// assert!(DnsSuffix::root().is_root());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnsSuffix(String);

impl DnsSuffix {
    /// The root domain (`.`), i.e. the default routing domain on backends
    /// that represent it (systemd-resolved, Windows NRPT).
    pub fn root() -> Self {
        Self(String::new())
    }

    /// Parses and normalizes a domain suffix.
    ///
    /// Accepts Unicode (IDNA UTS #46), uppercase, and an optional trailing
    /// dot. `""` and `"."` both yield the root domain. Fails with
    /// [`Error::InvalidConfig`](crate::Error) on empty labels, overlong
    /// labels, illegal characters, leading/trailing hyphens, or names over
    /// 253 characters.
    pub fn parse(input: &str) -> Result<Self> {
        normalize_domain(input).map(Self)
    }

    /// Whether this is the root (default routing) domain.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The canonical ASCII form without a trailing dot (the root domain is
    /// the empty string).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DnsSuffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str(".")
        } else {
            f.write_str(&self.0)
        }
    }
}

impl std::str::FromStr for DnsSuffix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        DnsSuffix::parse(s)
    }
}

impl Serialize for DnsSuffix {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DnsSuffix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        DnsSuffix::parse(&raw).map_err(serde::de::Error::custom)
    }
}

fn normalize_domain(input: &str) -> Result<String> {
    let trimmed = input.trim();
    let core = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if core.is_empty() {
        return Ok(String::new());
    }
    let ascii = idna::domain_to_ascii(core)
        .map_err(|_| Error::invalid_config(format_args!("invalid DNS domain {input:?}")))?;
    let mut total = 0usize;
    for label in ascii.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(Error::invalid_config(format_args!(
                "domain {input:?} contains a label with invalid length"
            )));
        }
        for &byte in bytes {
            if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
                return Err(Error::invalid_config(format_args!(
                    "domain {input:?} contains a character that is not allowed in DNS names"
                )));
            }
        }
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return Err(Error::invalid_config(format_args!(
                "domain {input:?} contains a label with a leading or trailing hyphen"
            )));
        }
        if bytes.len() >= 4 && bytes[2] == b'-' && bytes[3] == b'-' && bytes[..4] != *b"xn--" {
            return Err(Error::invalid_config(format_args!(
                "domain {input:?} contains a label with reserved hyphen placement"
            )));
        }
        total += bytes.len() + 1;
    }
    if total - 1 > 253 {
        return Err(Error::invalid_config(format_args!(
            "domain {input:?} exceeds the maximum DNS name length"
        )));
    }
    Ok(ascii)
}

/// The canonical, validated form of a [`crate::DnsConfig`] handed to a
/// backend. This is an internal type: it exists so journals can record the
/// exact desired semantics and backends can compare state against them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NormalizedConfig {
    pub(crate) nameservers: Vec<IpAddr>,
    pub(crate) search_domains: Vec<crate::normalize::DnsSuffix>,
    pub(crate) routing_domains: Vec<crate::normalize::DnsSuffix>,
    pub(crate) default_route: Option<bool>,
}
