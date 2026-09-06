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
    ///
    /// # Partial-mutation contract
    ///
    /// A backend may perform several native mutations to express one plan
    /// (for example separate IPv4 and IPv6 calls). When any step fails the
    /// backend returns `Err`, but the resource may already be partially
    /// mutated: callers must treat an `Err` return as indeterminate state,
    /// never as proof that nothing changed. The transaction engine always
    /// reads back and rolls back after an apply failure; backends must not
    /// rely on callers assuming atomicity.
    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt>;

    /// Reads the state back after a mutation for verification.
    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot>;

    /// Applies `plan`, but only while the current state still matches
    /// `expected`: the forward-mutation counterpart of
    /// [`Backend::restore_guarded`]. The default implementation is a plain
    /// [`Backend::apply`] (best-effort: a concurrent external change
    /// between the engine's verification read and this apply cannot be
    /// ruled out). Backends with native generation or version semantics
    /// override it with a true atomic check-and-mutate.
    fn apply_guarded(
        &self,
        resource: &ResourceId,
        _expected: &PlatformSnapshot,
        plan: &NormalizedConfig,
    ) -> Result<ApplyReceipt> {
        self.apply(resource, plan)
    }

    /// Restores an exact previous snapshot.
    ///
    /// Implementations must restore only the fields they manage and merge
    /// with unrelated native state where the platform requires it, so that
    /// restoration never destroys changes made by other actors to unmanaged
    /// fields.
    ///
    /// Prefer [`Backend::restore_guarded`]: it checks ownership of
    /// `expected` first. Every destructive restore in the engine
    /// (rollback, lease restore, recovery, rebase) goes through the
    /// guarded form.
    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()>;

    /// Restores `target`, but only while the current state still matches
    /// `expected`. The default implementation reads back, compares with
    /// [`Backend::equivalent`], and restores on match, returning
    /// [`Error::ExternalModification`](crate::Error::ExternalModification)
    /// without mutating otherwise. Backends with native generation or
    /// version semantics (NetworkManager `version_id`, the test fake's
    /// generation counter) override this with a true atomic check.
    fn restore_guarded(
        &self,
        resource: &ResourceId,
        expected: &PlatformSnapshot,
        target: &PlatformSnapshot,
    ) -> Result<()> {
        let current = self.readback(resource)?;
        if !self.equivalent(&current, expected) {
            return Err(Error::ExternalModification {
                resource: resource.clone(),
                detail: "the current state changed since ownership was verified".to_string(),
            });
        }
        self.restore(resource, target)
    }

    /// Semantic equality of two snapshots of the same resource: `true` when
    /// the managed DNS fields are equivalent.
    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool;

    /// Whether `snapshot` already expresses the semantics of `plan`.
    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool;

    /// Backend-specific semantic validation: reject plans the backend cannot
    /// faithfully represent, even when the generic capability checks pass.
    ///
    /// Runs after [`crate::config::validate_against`] and before any lock,
    /// journal write, or OS mutation. The default is to accept everything.
    fn validate_plan(&self, _scope: &DnsScope, _plan: &NormalizedConfig) -> Result<()> {
        Ok(())
    }

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

/// Constructs a specific backend by kind, bypassing detection. Used by the
/// testing module and the real-backend integration matrix.
#[cfg_attr(not(feature = "test-util"), allow(dead_code))]
pub(crate) fn construct_backend(
    kind: BackendKind,
    owner: &str,
) -> Result<std::sync::Arc<dyn Backend>> {
    use std::sync::Arc;
    match kind {
        #[cfg(target_os = "linux")]
        BackendKind::SystemdResolved => {
            linux::resolved::SystemdResolved::connect().map(|b| Arc::new(b) as Arc<dyn Backend>)
        }
        #[cfg(target_os = "linux")]
        BackendKind::NetworkManager => linux::network_manager::NetworkManager::connect()
            .map(|b| Arc::new(b) as Arc<dyn Backend>),
        #[cfg(target_os = "linux")]
        BackendKind::Resolvconf => {
            let probe = linux::resolvconf::probe().ok_or_else(|| {
                Error::BackendUnavailable("resolvconf/openresolv is not available".to_string())
            })?;
            Ok(Arc::new(linux::resolvconf::Resolvconf::new(probe, owner)))
        }
        #[cfg(target_os = "linux")]
        BackendKind::ResolvConfFile => Ok(Arc::new(linux::direct::DirectResolvConf::new())),
        #[cfg(target_os = "windows")]
        BackendKind::WindowsIpHelper => Ok(Arc::new(windows::WindowsBackend::new(owner))),
        #[cfg(target_os = "macos")]
        BackendKind::MacosSystemConfiguration => Ok(Arc::new(macos::MacosBackend::new(owner))),
        #[cfg(feature = "test-util")]
        BackendKind::Fake => Ok(Arc::new(fake::FakeBackend::new())),
        #[allow(unreachable_patterns)]
        _ => Err(Error::BackendUnavailable(format!(
            "{kind} is not available on this platform"
        ))),
    }
}

/// Selects the platform backend based on which component actually owns DNS
/// state on this host (Linux) or the single native backend (Windows, macOS).
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
