use std::ffi::OsString;
use std::net::IpAddr;

use crate::capability::Capabilities;
use crate::error::{Error, Result};
use crate::normalize::{DnsSuffix, NormalizedConfig};

/// Selects the target of a DNS configuration operation.
///
/// - [`DnsScope::Global`] addresses system-wide DNS state. Only backends with
///   [`Capabilities::global_dns`](crate::Capabilities) support it (Linux
///   resolvconf/direct and macOS); Windows rejects it with
///   [`Error::Unsupported`](crate::Error).
/// - [`DnsScope::Interface`] addresses one interface's DNS state. Requires
///   [`Capabilities::per_interface_dns`](crate::Capabilities).
///
/// The scope also determines which [`ResourceId`](crate::ResourceId)s a
/// [`DnsManager::apply`](crate::DnsManager::apply) call locks and journals.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsScope {
    /// System-wide DNS configuration.
    Global,
    /// DNS configuration of a specific interface.
    Interface(InterfaceSelector),
}

/// Selects an interface within [`DnsScope::Interface`].
///
/// Names and indexes are convenience selectors resolved by the backend at
/// apply time; the lease owns the backend's stable native identifier (GUID on
/// Windows, ifindex on Linux, service UUID on macOS), so renames do not
/// silently retarget a lease. `Default` resolves to the backend's notion of
/// the primary interface (default route on Linux, primary service on macOS).
/// macOS rejects [`InterfaceSelector::Index`] with
/// [`Error::InvalidConfig`](crate::Error); use `Default` or `Name` there.
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
/// Construct via [`DnsConfig::builder`]; [`DnsConfigBuilder::build`] rejects
/// unspecified nameservers, malformed domains, routing domains on a global
/// scope, and `default_route` on a global scope with
/// [`Error::InvalidConfig`](crate::Error). Backends may additionally reject
/// configurations they cannot represent (see [`crate::Capabilities`]) - this
/// is checked by [`DnsManager::validate`](crate::DnsManager::validate) and
/// again inside [`DnsManager::apply`](crate::DnsManager::apply) before any
/// mutation.
///
/// `DnsConfig` is a plain value: cloning is cheap, it borrows nothing, and it
/// holds no OS resources. Passing it to `apply` copies the desired semantics
/// into the journal; later mutating the value has no effect on live leases.
/// Use [`DnsManager::snapshot`](crate::DnsManager::snapshot) to read current
/// state back into this form.
///
/// # Example
///
/// ```
/// # use osdns::{DnsConfig, DnsScope, InterfaceSelector};
/// let config = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Default))
///     .nameserver("127.0.0.1".parse().unwrap())
///     .routing_domain("corp.example")
///     .build()?;
/// # Ok::<(), osdns::Error>(())
/// ```
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
    ///
    /// No validation happens here; errors surface at
    /// [`DnsConfigBuilder::build`].
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

    /// Nameservers, in preference order. Empty means "no nameservers".
    pub fn nameservers(&self) -> &[IpAddr] {
        &self.nameservers
    }

    /// Search domains.
    pub fn search_domains(&self) -> &[DnsSuffix] {
        &self.search_domains
    }

    /// Routing domains (split DNS). Only valid with an interface scope and
    /// only on backends with [`Capabilities::split_dns`](crate::Capabilities);
    /// otherwise [`DnsManager::apply`](crate::DnsManager::apply) returns
    /// [`Error::Unsupported`](crate::Error). The root domain (`.`) selects
    /// the default route on backends that support it; macOS rejects it -
    /// use [`DnsConfigBuilder::default_route`] there.
    ///
    /// Semantics: `nameservers` are the resolver endpoints owned by this
    /// configuration and `routing_domains` are the names routed to them.
    /// With non-empty routing domains and `default_route != Some(true)`,
    /// unrelated DNS stays outside the overlay on backends with true split
    /// DNS; backends own only the scoped resources needed (minimal
    /// ownership).
    pub fn routing_domains(&self) -> &[DnsSuffix] {
        &self.routing_domains
    }

    /// Whether this interface should be the default route for DNS.
    /// Only valid with an interface scope; `None` means preserve / leave
    /// unspecified and never implicitly `false`. Requires
    /// [`Capabilities::default_route`](crate::Capabilities); otherwise
    /// validation fails with [`Error::Unsupported`](crate::Error) before
    /// any mutation.
    pub fn default_route(&self) -> Option<bool> {
        self.default_route
    }
}

/// Builder for [`DnsConfig`].
///
/// Domains are parsed as [`DnsSuffix`] (IDNA, lowercase,
/// length-checked) when [`DnsConfigBuilder::build`] is called. Nameserver
/// order is preserved with duplicates removed. The builder itself performs no
/// I/O and needs no privileges.
///
/// # Example
///
/// ```
/// # use osdns::{DnsConfig, DnsScope, InterfaceSelector};
/// let config = DnsConfig::builder(DnsScope::Global)
///     .nameserver("1.1.1.1".parse().unwrap())
///     .search_domain("example.com")
///     .build()?;
/// # Ok::<(), osdns::Error>(())
/// ```
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

    /// Adds a nameserver. Duplicates are removed at build time, order is preserved.
    /// Unspecified addresses (`0.0.0.0`, `::`) are rejected at build time.
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
    ///
    /// Each entry is parsed as [`DnsSuffix`]; `"."` selects
    /// the root (default-route) domain where the backend supports it.
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
    ///
    /// Rejected at build time on a global scope.
    pub fn default_route(mut self, enabled: bool) -> Self {
        self.default_route = Some(enabled);
        self
    }

    /// Validates and builds the configuration.
    ///
    /// Returns [`Error::InvalidConfig`] for unspecified nameservers,
    /// unparsable domains, routing domains or `default_route` on a global
    /// scope. Backend capability checks happen later in
    /// [`DnsManager::validate`](crate::DnsManager::validate) and
    /// [`DnsManager::apply`](crate::DnsManager::apply).
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
    if config.default_route().is_some() && !caps.default_route {
        return Err(Error::unsupported(
            caps.backend,
            "this backend cannot represent explicit default-route semantics",
        ));
    }
    Ok(NormalizedConfig {
        nameservers: config.nameservers().to_vec(),
        search_domains: config.search_domains().to_vec(),
        routing_domains: config.routing_domains().to_vec(),
        default_route: config.default_route(),
    })
}
