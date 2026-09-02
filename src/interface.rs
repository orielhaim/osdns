use std::ffi::OsString;

/// Information about a network interface, as reported by the active backend.
///
/// Names and indexes are convenience selectors only; backends internally
/// identify interfaces by their stable native identifier (e.g. GUID on
/// Windows, ifindex on Linux).
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
