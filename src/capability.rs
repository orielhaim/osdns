use std::fmt;

use serde::{Deserialize, Serialize};

/// Identifies the DNS configuration backend in use.
///
/// The backend is selected by [`DnsManager`](crate::DnsManager) construction
/// from the component that actually owns DNS state on the host. See
/// [`Capabilities`] for what the active backend guarantees.
///
/// [`BackendKind`] is [`#[non_exhaustive]`](https://doc.rust-lang.org/reference/attributes/type_system.html)
/// so new backends can be added without a breaking change; match with a
/// wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    /// `systemd-resolved` via `org.freedesktop.resolve1`.
    SystemdResolved,
    /// NetworkManager via its D-Bus API.
    NetworkManager,
    /// The `resolvconf` or `openresolv` utility.
    Resolvconf,
    /// Direct manipulation of `/etc/resolv.conf`.
    ResolvConfFile,
    /// The Windows IP Helper API (`GetInterfaceDnsSettings` et al.).
    WindowsIpHelper,
    /// Apple SystemConfiguration.
    MacosSystemConfiguration,
    /// In-memory backend used by the `test-util` feature for tests.
    ///
    /// Never selected for real managers; construct it explicitly through
    /// [`FakeDns`](crate::testing::FakeDns) in tests.
    Fake,
}

impl BackendKind {
    /// Returns `true` for real operating-system backends and `false` for the
    /// in-memory test backend.
    pub fn is_real(&self) -> bool {
        *self != BackendKind::Fake
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            BackendKind::SystemdResolved => "systemd-resolved",
            BackendKind::NetworkManager => "network-manager",
            BackendKind::Resolvconf => "resolvconf",
            BackendKind::ResolvConfFile => "resolv-conf-file",
            BackendKind::WindowsIpHelper => "windows-ip-helper",
            BackendKind::MacosSystemConfiguration => "macos-system-configuration",
            BackendKind::Fake => "fake",
        };
        f.write_str(name)
    }
}

/// Describes what the active backend can actually guarantee.
///
/// Returned by [`DnsManager::capabilities`](crate::DnsManager::capabilities).
/// Configuration is rejected with [`Error::Unsupported`](crate::Error) before
/// any mutation when the backend cannot represent it. Never assume two
/// backends behave identically: these fields exist precisely because they do
/// not.
///
/// Linux backends: systemd-resolved supports per-interface DNS, search
/// domains, split DNS, watch, and cache flush; NetworkManager supports
/// per-interface DNS with backend-dependent split DNS; resolvconf/openresolv
/// is global-only with limited split DNS; direct `/etc/resolv.conf` is
/// global-only without split DNS. Windows supports per-interface DNS, search
/// domains, split DNS (NRPT), watch, and cache flush, but no global scope.
/// macOS supports global and per-interface DNS, search domains, split DNS
/// (scoped `/etc/resolver` files), and watch, but no cache flush.
///
/// The struct is `#[non_exhaustive]`: construct with [`Capabilities::new`]
/// plus `with_*` builders, never with a literal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Capabilities {
    /// The backend these capabilities describe.
    pub backend: BackendKind,
    /// Whether current DNS state can be read.
    pub read: bool,
    /// Whether global (system-wide) DNS can be configured.
    pub global_dns: bool,
    /// Whether per-interface DNS can be configured.
    pub per_interface_dns: bool,
    /// Whether search domains can be configured.
    pub search_domains: bool,
    /// Whether routing domains (split DNS) can be configured.
    pub split_dns: bool,
    /// Whether native change notifications are supported.
    pub watch: bool,
    /// Whether the OS DNS cache can be flushed (best-effort only).
    pub cache_flush: bool,
}

impl Capabilities {
    /// Creates capabilities for `backend` with every capability disabled.
    pub fn new(backend: BackendKind) -> Self {
        Self {
            backend,
            read: false,
            global_dns: false,
            per_interface_dns: false,
            search_domains: false,
            split_dns: false,
            watch: false,
            cache_flush: false,
        }
    }

    /// Sets [`Capabilities::read`].
    pub fn with_read(mut self, enabled: bool) -> Self {
        self.read = enabled;
        self
    }

    /// Sets [`Capabilities::global_dns`].
    pub fn with_global_dns(mut self, enabled: bool) -> Self {
        self.global_dns = enabled;
        self
    }

    /// Sets [`Capabilities::per_interface_dns`].
    pub fn with_per_interface_dns(mut self, enabled: bool) -> Self {
        self.per_interface_dns = enabled;
        self
    }

    /// Sets [`Capabilities::search_domains`].
    pub fn with_search_domains(mut self, enabled: bool) -> Self {
        self.search_domains = enabled;
        self
    }

    /// Sets [`Capabilities::split_dns`].
    pub fn with_split_dns(mut self, enabled: bool) -> Self {
        self.split_dns = enabled;
        self
    }

    /// Sets [`Capabilities::watch`].
    pub fn with_watch(mut self, enabled: bool) -> Self {
        self.watch = enabled;
        self
    }

    /// Sets [`Capabilities::cache_flush`].
    pub fn with_cache_flush(mut self, enabled: bool) -> Self {
        self.cache_flush = enabled;
        self
    }
}
