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

use crate::capability::{BackendKind, Capabilities, MutationGuard, OwnershipIdentity};
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

/// Backend-defined evidence naming the native resource incarnation that a
/// journal record was created against.  This is deliberately separate from
/// [`ResourceId`], which is only the current mutation/locking target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ResourceIdentity {
    pub(crate) backend: BackendKind,
    pub(crate) resource: ResourceId,
    pub(crate) data: serde_json::Value,
}

impl ResourceIdentity {
    pub(crate) fn new(backend: BackendKind, resource: ResourceId, data: serde_json::Value) -> Self {
        Self {
            backend,
            resource,
            data,
        }
    }
}

/// Result of comparing durable incarnation evidence with the current OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceStatus {
    Same,
    Gone,
    Replaced,
    Ambiguous,
}

/// One backend observation that binds incarnation evidence to the DNS
/// snapshot captured from that same native object.
#[derive(Debug, Clone)]
pub(crate) struct BoundObservation {
    pub(crate) identity: ResourceIdentity,
    pub(crate) snapshot: PlatformSnapshot,
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

/// Backend-issued identity of a mutation we performed.
///
/// Constructed only from a mutation result. A later capture is not an
/// [`OwnershipProof`].
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OwnershipProof {
    snapshot: PlatformSnapshot,
}

impl OwnershipProof {
    pub(crate) fn issued(snapshot: PlatformSnapshot) -> Self {
        Self { snapshot }
    }

    pub(crate) fn as_snapshot(&self) -> &PlatformSnapshot {
        &self.snapshot
    }

    pub(crate) fn into_snapshot(self) -> PlatformSnapshot {
        self.snapshot
    }
}

/// A mutation that matched the desired configuration on read-back.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedMutation {
    /// Durable identity when the backend issued one that still names
    /// [`VerifiedMutation::observed`].
    pub(crate) proof: Option<OwnershipProof>,
    /// Semantic snapshot from the verification read.
    pub(crate) observed: PlatformSnapshot,
}

impl VerifiedMutation {
    pub(crate) fn persist(&self) -> PlatformSnapshot {
        self.proof
            .as_ref()
            .map(|proof| proof.as_snapshot().clone())
            .unwrap_or_else(|| self.observed.clone())
    }
}

/// Receipt of a successful (per the OS API) mutation. The transaction engine
/// never trusts this alone; it always verifies via read-back.
#[derive(Debug, Clone)]
pub(crate) struct ApplyReceipt {
    #[allow(dead_code)]
    pub(crate) resource: ResourceId,
}

/// What a backend mutation actually did. The engine must not treat every
/// `Err` as the same state: a CAS rejection is not a partial write.
#[derive(Debug)]
pub(crate) enum MutationAttempt {
    /// The mutation completed. `produced` is backend-issued identity of the
    /// resulting state (generation, version, file identity) when the backend
    /// can name it. A later rollback may use it as `expected`; a fresh read
    /// after failure is not a substitute.
    Performed { produced: Option<PlatformSnapshot> },
    /// The backend guarantees it did not mutate (compare-and-mutate rejected
    /// the call). Must never trigger rollback.
    Rejected { error: Error },
    /// The mutation may have occurred. Rollback is allowed only when
    /// `produced` is backend-issued proof of the state we created.
    Indeterminate {
        error: Error,
        produced: Option<PlatformSnapshot>,
    },
}

impl MutationAttempt {
    pub(crate) fn from_apply_result(result: Result<ApplyReceipt>) -> Self {
        match result {
            Ok(_) => Self::Performed { produced: None },
            Err(error) if error.is_external_modification() => Self::Rejected { error },
            Err(error) => Self::Indeterminate {
                error,
                produced: None,
            },
        }
    }
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

    /// Captures the native lifetime identity before a journal is written.
    fn identify(&self, resource: &ResourceId) -> Result<ResourceIdentity> {
        Ok(ResourceIdentity::new(
            self.kind(),
            resource.clone(),
            serde_json::Value::Null,
        ))
    }

    /// Establishes whether `identity` still denotes the same native object.
    /// This must run before any resource-scoped DNS read or mutation.
    fn resource_status(&self, identity: &ResourceIdentity) -> Result<ResourceStatus> {
        if identity.backend != self.kind() || identity.resource.as_str().is_empty() {
            return Err(Error::JournalCorrupt(
                "resource identity backend/resource mismatch".to_string(),
            ));
        }
        Ok(ResourceStatus::Same)
    }

    /// Captures identity and DNS state as one coherent backend observation.
    fn observe(&self, resource: &ResourceId) -> Result<BoundObservation> {
        let identity = self.identify(resource)?;
        let snapshot = self.capture(resource)?;
        if self.resource_status(&identity)? != ResourceStatus::Same {
            return Err(Error::ResourceIdentity {
                backend: self.kind(),
                resource: resource.clone(),
                message: "resource incarnation changed while it was being observed".to_string(),
            });
        }
        Ok(BoundObservation { identity, snapshot })
    }

    /// Applies through the authoritative incarnation-checked operation path.
    fn apply_bound(
        &self,
        identity: &ResourceIdentity,
        expected: &PlatformSnapshot,
        plan: &NormalizedConfig,
    ) -> MutationAttempt {
        match self.resource_status(identity) {
            Ok(ResourceStatus::Same) => match self.mutation_guard() {
                MutationGuard::CompareAndMutate => {
                    self.apply_guarded(&identity.resource, expected, plan)
                }
                MutationGuard::Unconditional => match self.readback(&identity.resource) {
                    Ok(current) if self.equivalent(expected, &current) => {
                        match self.resource_status(identity) {
                            Ok(ResourceStatus::Same) => MutationAttempt::from_apply_result(
                                self.apply(&identity.resource, plan),
                            ),
                            Ok(status) => MutationAttempt::Rejected {
                                error: Error::ResourceIdentity {
                                    backend: self.kind(),
                                    resource: identity.resource.clone(),
                                    message: format!(
                                        "resource incarnation became {status:?} before mutation"
                                    ),
                                },
                            },
                            Err(error) => MutationAttempt::Rejected { error },
                        }
                    }
                    Ok(_) => MutationAttempt::Rejected {
                        error: Error::ExternalModification {
                            resource: identity.resource.clone(),
                            detail: "the current state changed since it was captured".to_string(),
                        },
                    },
                    Err(error) => MutationAttempt::Indeterminate {
                        error,
                        produced: None,
                    },
                },
            },
            Ok(status) => MutationAttempt::Rejected {
                error: Error::ResourceIdentity {
                    backend: self.kind(),
                    resource: identity.resource.clone(),
                    message: format!("resource incarnation is {status:?}; refusing mutation"),
                },
            },
            Err(error) => MutationAttempt::Rejected { error },
        }
    }

    /// Restores through the authoritative incarnation-checked operation path.
    fn restore_bound(
        &self,
        identity: &ResourceIdentity,
        expected: &PlatformSnapshot,
        target: &PlatformSnapshot,
    ) -> MutationAttempt {
        match self.resource_status(identity) {
            Ok(ResourceStatus::Same) => match self.mutation_guard() {
                MutationGuard::CompareAndMutate => {
                    self.restore_guarded(&identity.resource, expected, target)
                }
                MutationGuard::Unconditional => match self.readback(&identity.resource) {
                    Ok(current) if self.owns_current(expected, &current) => {
                        match self.resource_status(identity) {
                            Ok(ResourceStatus::Same) => {
                                match self.restore(&identity.resource, target) {
                                    Ok(()) => MutationAttempt::Performed { produced: None },
                                    Err(error) => MutationAttempt::Indeterminate {
                                        error,
                                        produced: None,
                                    },
                                }
                            }
                            Ok(status) => MutationAttempt::Rejected {
                                error: Error::ResourceIdentity {
                                    backend: self.kind(),
                                    resource: identity.resource.clone(),
                                    message: format!(
                                        "resource incarnation became {status:?} before restore"
                                    ),
                                },
                            },
                            Err(error) => MutationAttempt::Rejected { error },
                        }
                    }
                    Ok(_) => MutationAttempt::Rejected {
                        error: Error::ExternalModification {
                            resource: identity.resource.clone(),
                            detail: "the current state changed since ownership was verified"
                                .to_string(),
                        },
                    },
                    Err(error) => MutationAttempt::Indeterminate {
                        error,
                        produced: None,
                    },
                },
            },
            Ok(status) => MutationAttempt::Rejected {
                error: Error::ResourceIdentity {
                    backend: self.kind(),
                    resource: identity.resource.clone(),
                    message: format!("resource incarnation is {status:?}; refusing restore"),
                },
            },
            Err(error) => MutationAttempt::Rejected { error },
        }
    }

    /// Reads the authoritative current state of `resource`.
    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot>;

    /// Applies `plan` to `resource`. Must be idempotent when possible.
    ///
    /// A backend may perform several native mutations to express one plan.
    /// When any step fails the backend returns `Err`, and the resource may
    /// already be partially mutated. That is
    /// [`MutationAttempt::Indeterminate`], never proof that nothing changed.
    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt>;

    /// Reads the state back after a mutation for verification.
    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot>;

    /// Native compare-and-mutate strength. Defaults to the value advertised
    /// in [`Capabilities::mutation_guard`].
    fn mutation_guard(&self) -> MutationGuard {
        self.capabilities().mutation_guard
    }

    /// Whether snapshots carry mutation identity. Defaults to
    /// [`Capabilities::ownership_identity`].
    fn ownership_identity(&self) -> OwnershipIdentity {
        self.capabilities().ownership_identity
    }

    /// Whether `claimed` still names `current` as a state we produced.
    fn owns_current(&self, claimed: &PlatformSnapshot, current: &PlatformSnapshot) -> bool {
        match self.ownership_identity() {
            OwnershipIdentity::Durable => self.proves_current(claimed, current),
            OwnershipIdentity::BestEffort => self.equivalent(claimed, current),
        }
    }

    /// Applies `plan` only while current state still matches `expected`.
    ///
    /// Implemented only by backends with [`MutationGuard::CompareAndMutate`].
    /// The default does not fall back to [`Backend::apply`]: a missing
    /// primitive is a rejection, not a silent unguarded write.
    fn apply_guarded(
        &self,
        _resource: &ResourceId,
        _expected: &PlatformSnapshot,
        _plan: &NormalizedConfig,
    ) -> MutationAttempt {
        MutationAttempt::Rejected {
            error: Error::unsupported(
                self.kind(),
                "this backend has no compare-and-mutate primitive",
            ),
        }
    }

    /// Restores an exact previous snapshot.
    ///
    /// Implementations must restore only the fields they manage and merge
    /// with unrelated native state where the platform requires it, so that
    /// restoration never destroys changes made by other actors to unmanaged
    /// fields.
    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()>;

    /// Restores `target` only while current state still matches `expected`.
    ///
    /// Implemented only by backends with [`MutationGuard::CompareAndMutate`].
    /// The default does not perform a read-then-write.
    fn restore_guarded(
        &self,
        _resource: &ResourceId,
        _expected: &PlatformSnapshot,
        _target: &PlatformSnapshot,
    ) -> MutationAttempt {
        MutationAttempt::Rejected {
            error: Error::unsupported(
                self.kind(),
                "this backend has no compare-and-mutate primitive",
            ),
        }
    }

    /// Whether `proof` still names `current` as the same backend-issued
    /// mutation (generation, version, or file identity). Semantic DNS
    /// equality is not enough: an external writer can reproduce the same
    /// nameservers under a new identity.
    fn proves_current(&self, _proof: &PlatformSnapshot, _current: &PlatformSnapshot) -> bool {
        false
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
