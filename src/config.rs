use std::ffi::OsString;
use std::net::IpAddr;

use crate::capability::Capabilities;
use crate::error::{Error, Result};
use crate::normalize::{DnsSuffix, NormalizedConfig};

/// Selects the target of a DNS configuration operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsScope {
    /// System-wide DNS configuration.
    Global,
    /// DNS configuration of a specific interface.
    Interface(InterfaceSelector),
}

/// Selects an interface within [`DnsScope::Interface`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InterfaceSelector {
    /// The backend's notion of the primary/default interface.
    Default,
    /// By OS interface index.
    Index(u32),
    /// By OS interface name.
    Name(OsString),
}

/// A validated DNS configuration request or observed state.
///
/// Construct via [`DnsConfig::builder`]; invalid configurations cannot be
/// built. Backends may additionally reject configurations they cannot
/// represent (see [`crate::Capabilities`]) — this is checked by
/// [`DnsManager::validate`](crate::DnsManager::validate) and again inside
/// [`DnsManager::apply`](crate::DnsManager::apply) before any mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    scope: DnsScope,
    nameservers: Vec<IpAddr>,
    search_domains: Vec<DnsSuffix>,
    routing_domains: Vec<DnsSuffix>,
    default_route: Option<bool>,
}

impl DnsConfig {
    /// Starts building a configuration for `scope`.
    pub fn builder(scope: DnsScope) -> DnsConfigBuilder {
        DnsConfigBuilder::new(scope)
    }

    #[allow(dead_code)]
    pub(crate) fn from_parts(
        scope: DnsScope,
        nameservers: Vec<IpAddr>,
        search_domains: Vec<DnsSuffix>,
        routing_domains: Vec<DnsSuffix>,
        default_route: Option<bool>,
    ) -> Self {
        Self {
            scope,
            nameservers,
            search_domains,
            routing_domains,
            default_route,
        }
    }

    /// The scope this configuration targets.
    pub fn scope(&self) -> &DnsScope {
        &self.scope
    }

    /// Nameservers, in preference order.
    pub fn nameservers(&self) -> &[IpAddr] {
        &self.nameservers
    }

    /// Search domains.
    pub fn search_domains(&self) -> &[DnsSuffix] {
        &self.search_domains
    }

    /// Routing domains (split DNS). Only valid with an interface scope.
    pub fn routing_domains(&self) -> &[DnsSuffix] {
        &self.routing_domains
    }

    /// Whether this interface should be the default route for DNS.
    /// Only valid with an interface scope.
    pub fn default_route(&self) -> Option<bool> {
        self.default_route
    }
}

/// Builder for [`DnsConfig`].
///
/// Domains are validated when [`DnsConfigBuilder::build`] is called; a
/// builder can therefore never produce an invalid configuration.
#[derive(Debug, Clone)]
pub struct DnsConfigBuilder {
    scope: DnsScope,
    nameservers: Vec<IpAddr>,
    search_domains: Vec<String>,
    routing_domains: Vec<String>,
    default_route: Option<bool>,
}

impl DnsConfigBuilder {
    pub(crate) fn new(scope: DnsScope) -> Self {
        Self {
            scope,
            nameservers: Vec::new(),
            search_domains: Vec::new(),
            routing_domains: Vec::new(),
            default_route: None,
        }
    }

    /// Adds a nameserver. Duplicates are removed, order is preserved.
    pub fn nameserver(mut self, ip: IpAddr) -> Self {
        self.nameservers.push(ip);
        self
    }

    /// Adds nameservers. Duplicates are removed, order is preserved.
    pub fn nameservers<I: IntoIterator<Item = IpAddr>>(mut self, ips: I) -> Self {
        self.nameservers.extend(ips);
        self
    }

    /// Adds a search domain (validated on build).
    pub fn search_domain(mut self, domain: impl AsRef<str>) -> Self {
        self.search_domains.push(domain.as_ref().to_string());
        self
    }

    /// Adds search domains (validated on build).
    pub fn search_domains<I, S>(mut self, domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.search_domains
            .extend(domains.into_iter().map(|d| d.as_ref().to_string()));
        self
    }

    /// Adds a routing domain (split DNS; validated on build).
    pub fn routing_domain(mut self, domain: impl AsRef<str>) -> Self {
        self.routing_domains.push(domain.as_ref().to_string());
        self
    }

    /// Adds routing domains (split DNS; validated on build).
    pub fn routing_domains<I, S>(mut self, domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.routing_domains
            .extend(domains.into_iter().map(|d| d.as_ref().to_string()));
        self
    }

    /// Sets the default-route flag for an interface scope.
    pub fn default_route(mut self, enabled: bool) -> Self {
        self.default_route = Some(enabled);
        self
    }

    /// Validates and builds the configuration.
    pub fn build(self) -> Result<DnsConfig> {
        let mut nameservers = Vec::new();
        for ip in self.nameservers {
            if ip.is_unspecified() {
                return Err(Error::invalid_config(format_args!(
                    "nameserver address {ip} is unspecified"
                )));
            }
            if !nameservers.contains(&ip) {
                nameservers.push(ip);
            }
        }
        let mut search_domains = Vec::new();
        for domain in &self.search_domains {
            let suffix = DnsSuffix::parse(domain)?;
            if !search_domains.contains(&suffix) {
                search_domains.push(suffix);
            }
        }
        let mut routing_domains = Vec::new();
        for domain in &self.routing_domains {
            let suffix = DnsSuffix::parse(domain)?;
            if !routing_domains.contains(&suffix) {
                routing_domains.push(suffix);
            }
        }
        match self.scope {
            DnsScope::Global => {
                if !routing_domains.is_empty() {
                    return Err(Error::invalid_config(
                        "routing domains are only valid with an interface scope",
                    ));
                }
                if self.default_route.is_some() {
                    return Err(Error::invalid_config(
                        "default_route is only valid with an interface scope",
                    ));
                }
            }
            DnsScope::Interface(_) => {}
        }
        Ok(DnsConfig {
            scope: self.scope,
            nameservers,
            search_domains,
            routing_domains,
            default_route: self.default_route,
        })
    }
}

/// Validates `config` against backend capabilities and produces the
/// normalized form used by the transaction engine. Runs before any mutation.
pub(crate) fn validate_against(
    config: &DnsConfig,
    caps: &Capabilities,
) -> Result<NormalizedConfig> {
    match config.scope() {
        DnsScope::Global => {
            if !caps.global_dns {
                return Err(Error::unsupported(
                    caps.backend,
                    "this backend cannot configure global DNS",
                ));
            }
        }
        DnsScope::Interface(_) => {
            if !caps.per_interface_dns {
                return Err(Error::unsupported(
                    caps.backend,
                    "this backend cannot configure per-interface DNS",
                ));
            }
            if !config.routing_domains().is_empty() && !caps.split_dns {
                return Err(Error::unsupported(
                    caps.backend,
                    "this backend cannot configure split DNS routing domains",
                ));
            }
        }
    }
    if !config.search_domains().is_empty() && !caps.search_domains {
        return Err(Error::unsupported(
            caps.backend,
            "this backend cannot configure search domains",
        ));
    }
    Ok(NormalizedConfig {
        nameservers: config.nameservers().to_vec(),
        search_domains: config.search_domains().to_vec(),
        routing_domains: config.routing_domains().to_vec(),
        default_route: config.default_route(),
    })
}
