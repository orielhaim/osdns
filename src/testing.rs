//! Testing utilities for applications and tests built on `osdns`.
//!
//! Requires the `test-util` feature; never enable it in production builds.
//! Provides an in-memory backend ([`FakeDns`]) that participates fully in the
//! transaction engine (locks, journals, read-back verification, recovery),
//! fault injection ([`FaultInjector`], [`FakeOp`]) at backend and transaction
//! checkpoints ([`TxPoint`]), and [`catch_crash`] for simulating abrupt
//! process death mid-transaction.
//!
//! Managers built with [`manager_for_testing`] use an isolated temporary
//! state directory supplied by the caller, so parallel tests never share
//! journal or lock state.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::fault::{CrashSignal, FaultAction, FaultHook};
use crate::fsutil::ensure_private_dir;
use crate::journal::JournalStore;
use crate::manager::{ConflictPolicy, DnsManager, Inner};
use crate::ownership::ResourceLockManager;
use crate::platform::Backend;
use crate::platform::fake::FakeBackend;
use crate::watch::{DnsEvent, SuppressionRegistry};

pub use crate::fault::TxPoint;
pub use crate::platform::fake::{FakeOp, FakeState};

/// Handle for driving the in-memory fake backend from tests.
///
/// Cheap to clone: clones share the same backend state. Create with
/// [`FakeDns::new`] (all capabilities on) or [`FakeDns::with_capabilities`]
/// to simulate a restricted backend, pair with [`manager_for_testing`], and
/// drive external actors with [`FakeDns::external_change`].
/// Never use in production; requires the `test-util` feature.
#[derive(Clone)]
pub struct FakeDns {
    backend: Arc<FakeBackend>,
}

impl std::fmt::Debug for FakeDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeDns").finish()
    }
}

impl FakeDns {
    /// Creates a fake backend with every capability enabled.
    pub fn new() -> Self {
        Self {
            backend: Arc::new(FakeBackend::new()),
        }
    }

    /// Creates a fake backend with exactly the given capabilities.
    pub fn with_capabilities(caps: crate::capability::Capabilities) -> Self {
        Self {
            backend: Arc::new(FakeBackend::with_capabilities(caps)),
        }
    }

    /// Creates a fake backend that resolves interface scopes to a service
    /// resource plus one resolver resource per routing domain, mirroring the
    /// macOS backend shape, for multi-resource engine tests.
    pub fn with_multi_resource(caps: crate::capability::Capabilities) -> Self {
        Self {
            backend: Arc::new(FakeBackend::with_multi_resource(caps)),
        }
    }

    /// Simulates an external actor (DHCP, NetworkManager, the user, another
    /// VPN) rewriting the DNS state of `resource`.
    pub fn external_change(&self, resource: &str, state: FakeState) -> Result<()> {
        let id: crate::ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        self.backend.external_change(&id, state);
        Ok(())
    }

    /// Simulates the resource disappearing (e.g. an interface being removed).
    /// Returns whether anything was removed.
    pub fn external_remove(&self, resource: &str) -> Result<bool> {
        let id: crate::ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        Ok(self.backend.external_remove(&id))
    }

    /// Forces incarnation validation for `resource` to be ambiguous.
    pub fn set_identity_ambiguous(&self, resource: &str, ambiguous: bool) -> Result<()> {
        let id: crate::ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        self.backend.set_identity_ambiguous(id, ambiguous);
        Ok(())
    }

    /// Replaces `resource` with a new incarnation immediately before the
    /// next guarded apply.
    pub fn replace_before_next_apply(&self, resource: &str, state: FakeState) -> Result<()> {
        let id: crate::ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        self.backend.replace_before_next_apply(id, state);
        Ok(())
    }

    /// Replaces `resource` between identity and snapshot acquisition inside
    /// the next bound observation.
    pub fn replace_during_next_observe(&self, resource: &str, state: FakeState) -> Result<()> {
        let id: crate::ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        self.backend.replace_during_next_observe(id, state);
        Ok(())
    }

    /// Reads the current fake OS state of `resource`.
    pub fn current_state(&self, resource: &str) -> Result<Option<FakeState>> {
        let id: crate::ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        Ok(self.backend.state_of(&id))
    }

    /// Reads the fake generation token of `resource`.
    pub fn generation(&self, resource: &str) -> Result<Option<u64>> {
        let id: crate::ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        Ok(self.backend.generation_of(&id))
    }

    /// Delivers a watch event through any registered callback.
    pub fn emit_event(&self, event: DnsEvent) {
        self.backend.notify(event);
    }

    /// Makes the next `times` invocations of `op` fail with a platform
    /// error carrying `message`.
    pub fn inject_backend_failure(&self, op: FakeOp, times: u32, message: impl Into<String>) {
        self.backend.inject_failure(op, times, message);
    }

    /// Allows `skip` calls of `op`, then fails the next `times` calls.
    /// Useful for reaching a mutation after successful stability reads.
    pub fn inject_backend_failure_after(
        &self,
        op: FakeOp,
        skip: u32,
        times: u32,
        message: impl Into<String>,
    ) {
        self.backend.inject_failure_after(op, skip, times, message);
    }

    /// Makes the next read-back return `state` regardless of the real state,
    /// simulating an OS whose read-back disagrees with what was applied.
    pub fn lie_once_on_readback(&self, state: FakeState) {
        self.backend.lie_once_on_readback(state);
    }

    /// Arms the next `times` applies to mutate the resource and then fail,
    /// modelling a backend that partially mutates before returning `Err`.
    pub fn inject_partial_apply_failure(&self, times: u32) {
        self.backend.inject_partial_apply_failure(times);
    }

    /// Applies an external write immediately before the next guarded
    /// mutation of `resource`, modelling an adversarial writer between
    /// verification and compare-and-mutate.
    pub fn inject_external_before_guarded(&self, resource: &str, state: FakeState) -> Result<()> {
        let id: crate::ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        self.backend.inject_external_before_guarded(id, state);
        Ok(())
    }

    /// Applies an external write after the next guarded mutation of
    /// `resource` has already changed the backend, and before the engine
    /// observes the result. Models a partial mutation followed by an
    /// external change before rollback.
    pub fn inject_external_after_guarded_mutation(
        &self,
        resource: &str,
        state: FakeState,
    ) -> Result<()> {
        let id: crate::ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        self.backend
            .inject_external_after_guarded_mutation(id, state);
        Ok(())
    }

    /// Rewrites `resource` to `state` at the start of the guarded apply
    /// after `skip` successful guarded-apply entries.
    pub fn inject_external_before_nth_guarded(
        &self,
        skip: u32,
        resource: &str,
        state: FakeState,
    ) -> Result<()> {
        let id: crate::ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        self.backend
            .inject_external_before_nth_guarded(skip, id, state);
        Ok(())
    }

    /// Blocks the next native watch installation until the returned function
    /// is called. Used to inject an external change in the watcher-start
    /// window.
    pub fn block_next_start_watch(&self) -> impl FnOnce() + Send {
        self.backend.block_next_start_watch()
    }
}

impl Default for FakeDns {
    fn default() -> Self {
        Self::new()
    }
}

/// Machine-wide lock directory used by production managers. Journal
/// `state_dir` never feeds this path.
pub fn production_lock_root() -> Result<std::path::PathBuf> {
    crate::manager::global_lock_root()
}

/// Builds a [`DnsManager`] around an explicit fake backend and a temporary
/// state directory.
///
/// The caller owns `state_dir` (use a fresh temp dir per test); locks and
/// journals live under it. Uses [`ConflictPolicy::Cooperative`]; see
/// [`manager_for_testing_with_policy`] for Enforce tests.
pub fn manager_for_testing(
    owner: &str,
    state_dir: &Path,
    fake: &FakeDns,
    lock_timeout: Duration,
) -> Result<DnsManager> {
    manager_for_testing_with_policy(
        owner,
        state_dir,
        fake,
        lock_timeout,
        ConflictPolicy::Cooperative,
    )
}

/// Like [`manager_for_testing`], but with an explicit conflict policy, so
/// Enforce-policy reconciliation can be tested against the fake backend.
pub fn manager_for_testing_with_policy(
    owner: &str,
    state_dir: &Path,
    fake: &FakeDns,
    lock_timeout: Duration,
    conflict_policy: ConflictPolicy,
) -> Result<DnsManager> {
    use std::collections::HashMap;
    ensure_private_dir(state_dir)?;
    // Namespaced by simulated OS instance, not by state dir.
    let locks = ResourceLockManager::with_namespace(
        state_dir.join("locks"),
        lock_timeout,
        fake.backend.lock_namespace().to_string(),
    );
    locks.ensure_dir()?;
    let journal = JournalStore::open(state_dir.join("journal"))?;
    let backend: Arc<dyn Backend> = fake.backend.clone();
    if conflict_policy == ConflictPolicy::Enforce && !backend.capabilities().watch {
        return Err(Error::unsupported(
            backend.capabilities().backend,
            "ConflictPolicy::Enforce requires change notifications, which this backend does not support",
        ));
    }
    Ok(DnsManager::from_inner(Arc::new(Inner {
        owner: owner.to_string(),
        backend,
        locks,
        journal,
        conflict_policy,
        hook: Mutex::new(None),
        suppressions: std::sync::Arc::new(SuppressionRegistry::new()),
        active: Mutex::new(HashMap::new()),
        lease_tokens: Mutex::new(HashMap::new()),
        reconciler: crate::reconciliation::Reconciler::default(),
        enforce: Mutex::new(crate::manager::EnforceState::default()),
    })))
}

/// Builds a [`DnsManager`] pinned to a specific real backend, bypassing
/// detection.
///
/// Used by the real-backend integration matrix; unavailable backends fail
/// with [`Error::BackendUnavailable`] and nothing is mutated. Requires the
/// `test-util` feature. Real mutations need elevated privileges and the
/// `OSDNS_ALLOW_SYSTEM_MUTATION` opt-in used by the test suite.
pub fn manager_for_backend(
    owner: &str,
    state_dir: &Path,
    kind: crate::capability::BackendKind,
    lock_timeout: Duration,
) -> Result<DnsManager> {
    use std::collections::HashMap;
    ensure_private_dir(state_dir)?;
    let locks = ResourceLockManager::new(state_dir.join("locks"), lock_timeout);
    locks.ensure_dir()?;
    let journal = JournalStore::open(state_dir.join("journal"))?;
    let backend = crate::platform::construct_backend(kind, owner)?;
    Ok(DnsManager::from_inner(Arc::new(Inner {
        owner: owner.to_string(),
        backend,
        locks,
        journal,
        conflict_policy: ConflictPolicy::Cooperative,
        hook: Mutex::new(None),
        suppressions: std::sync::Arc::new(SuppressionRegistry::new()),
        active: Mutex::new(HashMap::new()),
        lease_tokens: Mutex::new(HashMap::new()),
        reconciler: crate::reconciliation::Reconciler::default(),
        enforce: Mutex::new(crate::manager::EnforceState::default()),
    })))
}

/// Deterministic reconciliation outcome for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugReconcile {
    /// No active lease owns the resource.
    NotOwned,
    /// The state still matches the lease's applied overlay.
    StillOurs,
    /// The external base was adopted and the overlay reapplied.
    Rebased,
    /// The pass was deferred (unstable, busy, or circuit breaker).
    Deferred,
    /// The pass failed and was deferred with an error.
    Failed,
}

#[derive(Debug, Clone)]
enum FaultSpec {
    Crash,
    Fail(String),
}

/// Arms failures or simulated process death at transaction checkpoints.
///
/// Install on a manager with
/// [`DnsManager::install_fault_injector`](crate::DnsManager::install_fault_injector).
/// `crash_at` simulates abrupt death: journal state persists, locks release,
/// and [`catch_crash`] converts the panic into [`CrashOutcome::Crashed`];
/// `fail_at` makes the transaction return an injected platform error.
/// Requires the `test-util` feature.
#[derive(Debug, Default)]
pub struct FaultInjector {
    actions: Mutex<HashMap<TxPoint, FaultSpec>>,
}

impl FaultInjector {
    /// Creates an empty injector.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Simulates abrupt process death when the transaction reaches `point`.
    pub fn crash_at(&self, point: TxPoint) -> &Self {
        self.actions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(point, FaultSpec::Crash);
        self
    }

    /// Makes the transaction fail with an injected platform error when it
    /// reaches `point`.
    pub fn fail_at(&self, point: TxPoint, message: impl Into<String>) -> &Self {
        self.actions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(point, FaultSpec::Fail(message.into()));
        self
    }

    /// Removes the action armed at `point`.
    pub fn disarm(&self, point: TxPoint) {
        self.actions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&point);
    }

    /// Removes all armed actions.
    pub fn clear(&self) {
        self.actions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

impl FaultHook for FaultInjector {
    fn on_point(&self, point: TxPoint) -> FaultAction {
        match self
            .actions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&point)
        {
            Some(FaultSpec::Crash) => FaultAction::Crash,
            Some(FaultSpec::Fail(message)) => FaultAction::Fail(message.clone()),
            None => FaultAction::Continue,
        }
    }
}

/// What happened to an operation run under [`catch_crash`].
#[derive(Debug)]
pub enum CrashOutcome<T> {
    /// The operation completed without simulating a crash.
    Completed(Result<T>),
    /// The operation died at an armed [`TxPoint`], exactly like a process
    /// crash: journal state persists, locks are released, nothing is cleaned
    /// up beyond what the OS would do.
    Crashed,
}

/// Runs `f`, converting a crash armed via [`FaultInjector::crash_at`] into
/// [`CrashOutcome::Crashed`]. Any other panic is resumed.
pub fn catch_crash<T>(f: impl FnOnce() -> Result<T>) -> CrashOutcome<T> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => CrashOutcome::Completed(result),
        Err(payload) => {
            if payload.downcast_ref::<CrashSignal>().is_some() {
                CrashOutcome::Crashed
            } else {
                resume_unwind(payload)
            }
        }
    }
}
