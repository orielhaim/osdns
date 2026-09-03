use std::ffi::OsString;

/// Information about a network interface, as reported by the active backend.
///
/// Returned by [`DnsManager::interfaces`](crate::DnsManager::interfaces).
/// Read-only snapshot; `index` is the OS interface index (0 when the platform
/// does not expose one, e.g. macOS service enumeration), `name` the OS name,
/// `friendly_name` a human-readable name when available, `guid` the stable
/// native identifier when available (Windows GUID, macOS service UUID).
/// `is_up` reflects the backend's liveness signal and may be approximate.
///
/// Names and indexes are convenience selectors only; backends internally
/// identify interfaces by their stable native identifier, so a rename between
/// `interfaces()` and `apply()` fails cleanly rather than retargeting.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InterfaceInfo {
    /// OS interface index.
    pub index: u32,
    /// OS interface name.
    pub name: OsString,
    /// Human-friendly display name, when the platform provides one.
    pub friendly_name: Option<String>,
    /// Interface GUID, when the platform exposes one.
    pub guid: Option<String>,
    /// Whether the interface is currently up.
    pub is_up: bool,
}
