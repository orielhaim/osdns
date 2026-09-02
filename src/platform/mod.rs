#[cfg(feature = "test-util")]
pub(crate) mod fake;
#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod text_config;
#[cfg(target_os = "windows")]
pub(crate) mod windows;

use serde::{Deserialize, Serialize};

use crate::capability::{BackendKind, Capabilities};
use crate::config::{DnsConfig, DnsScope};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::watch::{WatchCallback, WatchHandle};

/// An exact, opaque capture of a platform resource's native DNS state.
///
/// Only the backend that produced a snapshot can interpret it. Snapshots are
/// serialized into journals so restoration works after crashes and reboots.
/// They must retain enough native state for lossless restoration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PlatformSnapshot {
    pub(crate) backend: BackendKind,
    pub(crate) resource: ResourceId,
    pub(crate) data: serde_json::Value,
}

impl PlatformSnapshot {
    #[allow(dead_code)]
    pub(crate) fn new(backend: BackendKind, resource: ResourceId, data: serde_json::Value) -> Self {
        Self {
            backend,
            resource,
            data,
        }
    }
}

/// Receipt of a successful (per the OS API) mutation. The transaction engine
/// never trusts this alone; it always verifies via read-back.
#[derive(Debug, Clone)]
pub(crate) struct ApplyReceipt {
    #[allow(dead_code)]
    pub(crate) resource: ResourceId,
}

/// The boundary between the transaction engine and platform-specific code.
///
/// Implementations are crate-internal; the public API never exposes
/// platform-specific structures. Backends own semantic equality
/// ([`Backend::equivalent`], [`Backend::matches_desired`]) because only they
/// know which parts of native state are meaningful.
pub(crate) trait Backend: Send + Sync {
    fn kind(&self) -> BackendKind;

    fn capabilities(&self) -> Capabilities;

    /// Maps a scope and plan to the concrete resources that would be
    /// mutated. The engine acquires locks over all of them, in sorted order,
    /// before any mutation.
    fn resolve_resources(
        &self,
        scope: &DnsScope,
        plan: &NormalizedConfig,
    ) -> Result<Vec<ResourceId>>;

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>>;

    /// Reads the authoritative current state of `resource`.
    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot>;

    /// Applies `plan` to `resource`. Must be idempotent when possible.
    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt>;

    /// Reads the state back after a mutation for verification.
    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot>;

    /// Restores an exact previous snapshot.
    ///
    /// Implementations must restore only the fields they manage and merge
    /// with unrelated native state where the platform requires it, so that
    /// restoration never destroys changes made by other actors to unmanaged
    /// fields.
    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()>;

    /// Semantic equality of two snapshots of the same resource: `true` when
    /// the managed DNS fields are equivalent.
    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool;

    /// Whether `snapshot` already expresses the semantics of `plan`.
    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool;

    /// Interprets a snapshot as a platform-neutral [`DnsConfig`].
    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig>;

    /// Starts native change notifications for the backend's resources.
    fn start_watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let _ = callback;
        Err(Error::unsupported(
            self.kind(),
            "this backend does not support change notifications",
        ))
    }

    /// Flushes the OS DNS cache. Best-effort only; never part of
    /// correctness.
    fn flush_cache(&self) -> Result<()> {
        Err(Error::unsupported(
            self.kind(),
            "this backend does not support cache flushing",
        ))
    }
}

/// Selects the platform backend. Real backends are introduced phase by
/// phase; until then only explicitly-provided test backends work.
pub(crate) fn select_default_backend(owner: &str) -> Result<std::sync::Arc<dyn Backend>> {
    #[cfg(target_os = "linux")]
    {
        linux::detect::select(owner)
    }
    #[cfg(target_os = "macos")]
    {
        Ok(std::sync::Arc::new(macos::MacosBackend::new(owner)))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(std::sync::Arc::new(windows::WindowsBackend::new(owner)))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = owner;
        Err(Error::BackendUnavailable(
            "no platform backend is implemented for this target".to_string(),
        ))
    }
}
