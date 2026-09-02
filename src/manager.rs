use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use uuid::Uuid;

use crate::capability::Capabilities;
use crate::config::{DnsConfig, DnsScope, validate_against};
use crate::error::{ConflictReason, Error, Result};
use crate::fault::{CrashSignal, FaultAction, FaultHook, TxPoint};
use crate::fsutil::ensure_private_dir;
use crate::interface::InterfaceInfo;
use crate::journal::{JournalRecord, JournalStore, Phase, SCHEMA_VERSION};
use crate::lease::{Lease, LiveRecord};
use crate::normalize::NormalizedConfig;
use crate::ownership::{ResourceId, ResourceLockManager};
use crate::platform::{Backend, PlatformSnapshot, select_default_backend};
use crate::reconciliation::Reconciler;
use crate::watch::SuppressionRegistry;
use crate::watch::{WatchCallback, WatchHandle};

/// How the manager reacts when an external actor changes DNS state that we
/// hold a lease over.
///
/// - [`ConflictPolicy::Cooperative`] (default): never overwrite; surface
///   conflicts to the lease owner.
/// - [`ConflictPolicy::Enforce`]: intended for active VPN/mesh/tunnel agents;
///   legitimate external base changes are rebased and the desired overlay is
///   reapplied. Enforcement is introduced with the platform backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictPolicy {
    /// Never overwrite externally changed state automatically.
    #[default]
    Cooperative,
    /// Rebase on legitimate external changes and reapply the overlay.
    Enforce,
}

/// The result of inspecting one journal record during stale recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryOutcome {
    /// The recorded transaction was still in effect; the original state was
    /// restored and verified, and the journal record was removed.
    Restored {
        /// The recovered resource.
        resource: ResourceId,
        /// The lease that left the record behind.
        lease_id: Uuid,
    },
    /// The transaction never became effective (or was already reverted), so
    /// only the journal record was removed. No mutation was needed.
    JournalCleared {
        /// The recovered resource.
        resource: ResourceId,
        /// The lease that left the record behind.
        lease_id: Uuid,
    },
    /// The current state matches neither the recorded applied state nor the
    /// original state: another actor changed it. Nothing was mutated and the
    /// journal record was kept.
    ExternalConflict {
        /// The contended resource.
        resource: ResourceId,
        /// The lease that left the record behind.
        lease_id: Uuid,
    },
    /// The resource is currently locked by an active lease, so it was not
    /// inspected.
    Busy {
        /// The locked resource.
        resource: ResourceId,
    },
}

pub(crate) struct Inner {
    pub(crate) owner: String,
    pub(crate) backend: Arc<dyn Backend>,
    pub(crate) locks: ResourceLockManager,
    pub(crate) journal: JournalStore,
    pub(crate) conflict_policy: ConflictPolicy,
    pub(crate) hook: Mutex<Option<Arc<dyn FaultHook>>>,
    pub(crate) suppressions: Arc<SuppressionRegistry>,
    pub(crate) active: Mutex<HashMap<ResourceId, Arc<Mutex<LiveRecord>>>>,
    pub(crate) lease_tokens: Mutex<HashMap<ResourceId, Arc<Mutex<()>>>>,
    #[allow(dead_code)]
    pub(crate) reconciler: Reconciler,
}

const COALESCE_WINDOW: Duration = Duration::from_millis(50);

impl Inner {
    pub(crate) fn share_records(&self, records: Vec<JournalRecord>) -> Vec<Arc<Mutex<LiveRecord>>> {
        let mut live = Vec::with_capacity(records.len());
        for record in records {
            let shared = Arc::new(Mutex::new(LiveRecord { record }));
            self.register_active(Arc::clone(&shared));
            live.push(shared);
        }
        live
    }
}

struct MutatePoints {
    apply: TxPoint,
    readback: TxPoint,
    verify: TxPoint,
}

const INITIAL_POINTS: MutatePoints = MutatePoints {
    apply: TxPoint::AfterApply,
    readback: TxPoint::AfterReadback,
    verify: TxPoint::AfterVerify,
};

const UPDATE_POINTS: MutatePoints = MutatePoints {
    apply: TxPoint::AfterUpdateApply,
    readback: TxPoint::AfterUpdateReadback,
    verify: TxPoint::AfterUpdateVerify,
};

enum RecoverBlock {
    Corrupt(Error),
    Conflict(String),
}

impl Inner {
    pub(crate) fn fire(&self, point: TxPoint) -> Result<()> {
        let hook = self
            .hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(hook) = hook {
            match hook.on_point(point) {
                FaultAction::Continue => {}
                FaultAction::Crash => std::panic::panic_any(CrashSignal),
                FaultAction::Fail(message) => {
                    return Err(Error::platform(
                        self.backend.kind(),
                        format_args!("injected transaction failure: {message}"),
                    ));
                }
            }
        }
        Ok(())
    }

    fn mutate_and_verify(
        &self,
        resource: &ResourceId,
        plan: &NormalizedConfig,
        rollback_to: Option<&PlatformSnapshot>,
        points: MutatePoints,
    ) -> Result<PlatformSnapshot> {
        self.suppressions.suppress(resource);
        let _receipt = self.backend.apply(resource, plan)?;
        self.fire(points.apply)?;
        let actual = match self.backend.readback(resource) {
            Ok(actual) => actual,
            Err(error) => {
                if let Some(target) = rollback_to {
                    self.attempt_rollback(resource, target);
                }
                return Err(error);
            }
        };
        self.fire(points.readback)?;
        if !self.backend.matches_desired(&actual, plan) {
            if let Some(target) = rollback_to {
                self.attempt_rollback(resource, target);
            }
            return Err(Error::VerificationFailed {
                resource: resource.clone(),
                detail:
                    "the state read back from the system does not match the desired configuration"
                        .to_string(),
            });
        }
        self.fire(points.verify)?;
        Ok(actual)
    }

    #[allow(unused_variables)]
    fn attempt_rollback(&self, resource: &ResourceId, target: &PlatformSnapshot) {
        let current = match self.backend.readback(resource) {
            Ok(current) => current,
            Err(error) => {
                osdns_warn!(
                    resource = %resource,
                    error = %error,
                    "rollback after failed verification could not read back the current state"
                );
                return;
            }
        };
        if self.backend.equivalent(&current, target) {
            return;
        }
        if let Err(error) = self.backend.restore(resource, target) {
            osdns_warn!(
                resource = %resource,
                error = %error,
                "rollback after failed verification could not restore the previous state"
            );
            return;
        }
        match self.backend.readback(resource) {
            Ok(now) if self.backend.equivalent(&now, target) => {}
            Ok(_) => {
                osdns_warn!(
                    resource = %resource,
                    "rollback after failed verification did not read back as the previous state"
                );
            }
            Err(error) => {
                osdns_warn!(
                    resource = %resource,
                    error = %error,
                    "rollback after failed verification could not read back the restored state"
                );
            }
        }
    }

    pub(crate) fn transact_with_locks(
        &self,
        resources: Vec<ResourceId>,
        plan: &NormalizedConfig,
        befores: Vec<PlatformSnapshot>,
    ) -> Result<Vec<JournalRecord>> {
        let lease_id = Uuid::new_v4();
        let mut records: Vec<JournalRecord> = resources
            .into_iter()
            .zip(befores)
            .map(|(resource, before)| JournalRecord {
                schema_version: SCHEMA_VERSION,
                owner: self.owner.clone(),
                lease_id,
                resource,
                backend: self.backend.kind(),
                phase: Phase::Prepared,
                before,
                desired: plan.clone(),
                applied: None,
            })
            .collect();
        for record in &records {
            self.journal.write(record)?;
        }
        self.fire(TxPoint::AfterPrepared)?;
        let mut actuals: Vec<PlatformSnapshot> = Vec::new();
        for index in 0..records.len() {
            match self.mutate_and_verify(
                &records[index].resource,
                plan,
                Some(&records[index].before),
                INITIAL_POINTS,
            ) {
                Ok(actual) => actuals.push(actual),
                Err(error) => {
                    for record in &records[..=index] {
                        self.revert_record(record);
                    }
                    for record in &records[index + 1..] {
                        let _ = self.journal.remove(&record.lease_id, &record.resource);
                    }
                    return Err(error);
                }
            }
        }
        for (record, actual) in records.iter_mut().zip(actuals) {
            record.phase = Phase::Applied;
            record.applied = Some(actual);
        }
        let written = records.clone();
        for record in &written {
            self.journal.write(record)?;
        }
        self.fire(TxPoint::AfterApplied)?;
        Ok(records)
    }

    #[allow(unused_variables)]
    fn revert_record(&self, record: &JournalRecord) {
        self.suppressions.suppress(&record.resource);
        if let Err(error) = self.backend.restore(&record.resource, &record.before) {
            osdns_warn!(
                resource = %record.resource,
                error = %error,
                "transaction rollback could not restore the previous state; the journal record was kept for later recovery"
            );
            return;
        }
        match self.backend.readback(&record.resource) {
            Ok(current) if self.backend.equivalent(&current, &record.before) => {
                let _ = self.journal.remove(&record.lease_id, &record.resource);
            }
            Ok(_) => {
                osdns_warn!(
                    resource = %record.resource,
                    "transaction rollback did not read back as the previous state; the journal record was kept for later recovery"
                );
            }
            Err(error) => {
                osdns_warn!(
                    resource = %record.resource,
                    error = %error,
                    "transaction rollback could not read back the restored state; the journal record was kept for later recovery"
                );
            }
        }
    }

    pub(crate) fn update_owned(
        &self,
        record: &mut JournalRecord,
        plan: &NormalizedConfig,
    ) -> Result<()> {
        let resource = &record.resource;
        self.fire(TxPoint::AfterUpdateResolve)?;
        let applied = record.applied.clone().ok_or_else(|| {
            Error::platform(
                self.backend.kind(),
                format_args!("owned lease record for {resource} is missing its applied snapshot"),
            )
        })?;
        let current = self.backend.readback(resource)?;
        self.fire(TxPoint::AfterUpdateCapture)?;
        if !self.backend.equivalent(&current, &applied) {
            return Err(Error::ExternalModification {
                resource: resource.clone(),
                detail: "the current state no longer matches the state applied by this lease"
                    .to_string(),
            });
        }
        if self.backend.matches_desired(&current, plan) {
            self.fire(TxPoint::AfterUpdateNoopCheck)?;
            return Ok(());
        }
        record.desired = plan.clone();
        record.phase = Phase::Prepared;
        record.applied = Some(applied.clone());
        self.journal.write(record)?;
        self.fire(TxPoint::AfterUpdatePrepared)?;
        match self.mutate_and_verify(resource, plan, Some(&applied), UPDATE_POINTS) {
            Ok(actual) => {
                record.phase = Phase::Applied;
                record.applied = Some(actual);
                self.journal.write(record)?;
                self.fire(TxPoint::AfterUpdateApplied)?;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn restore_lease_state(&self, record: &JournalRecord) -> Result<()> {
        let resource = &record.resource;
        self.suppressions.suppress(resource);
        let current = self.backend.readback(resource)?;
        self.fire(TxPoint::AfterRestoreReadback)?;
        if self.backend.equivalent(&current, &record.before) {
            self.journal.remove(&record.lease_id, resource)?;
            self.fire(TxPoint::AfterRestoreJournal)?;
            return Ok(());
        }
        let applied_ours = record
            .applied
            .as_ref()
            .is_some_and(|applied| self.backend.equivalent(&current, applied));
        if !applied_ours {
            return Err(Error::ExternalModification {
                resource: resource.clone(),
                detail: "the current state is neither the state applied by this lease nor the original state"
                    .to_string(),
            });
        }
        self.backend.restore(resource, &record.before)?;
        self.fire(TxPoint::AfterRestoreRestore)?;
        let now = self.backend.readback(resource)?;
        if !self.backend.equivalent(&now, &record.before) {
            return Err(Error::VerificationFailed {
                resource: resource.clone(),
                detail: "the restored state failed read-back verification".to_string(),
            });
        }
        self.journal.remove(&record.lease_id, resource)?;
        self.fire(TxPoint::AfterRestoreJournal)?;
        Ok(())
    }

    #[allow(unused_variables)]
    pub(crate) fn best_effort_restore(&self, record: &JournalRecord) {
        if let Err(error) = self.restore_lease_state(record) {
            osdns_warn!(
                owner = %self.owner,
                resource = %record.resource,
                error = %error,
                "best-effort restore on lease drop failed; the journal record was kept for later recovery"
            );
        }
    }

    fn recover_record(&self, record: JournalRecord) -> Result<RecoveryOutcome> {
        let resource = record.resource.clone();
        let current = self.backend.capture(&resource)?;
        self.fire(TxPoint::AfterRecoveryReadback)?;
        if self.backend.equivalent(&current, &record.before) {
            self.journal.remove(&record.lease_id, &resource)?;
            self.fire(TxPoint::AfterRecoveryJournal)?;
            return Ok(RecoveryOutcome::JournalCleared {
                resource,
                lease_id: record.lease_id,
            });
        }
        let applied_ours = record
            .applied
            .as_ref()
            .is_some_and(|applied| self.backend.equivalent(&current, applied));
        if applied_ours || self.backend.matches_desired(&current, &record.desired) {
            self.suppressions.suppress(&resource);
            self.backend.restore(&resource, &record.before)?;
            self.fire(TxPoint::AfterRecoveryRestore)?;
            let now = self.backend.readback(&resource)?;
            if !self.backend.equivalent(&now, &record.before) {
                return Err(Error::VerificationFailed {
                    resource,
                    detail: "the recovery restore did not read back as the original state"
                        .to_string(),
                });
            }
            self.journal.remove(&record.lease_id, &resource)?;
            self.fire(TxPoint::AfterRecoveryJournal)?;
            return Ok(RecoveryOutcome::Restored {
                resource,
                lease_id: record.lease_id,
            });
        }
        Ok(RecoveryOutcome::ExternalConflict {
            resource,
            lease_id: record.lease_id,
        })
    }

    fn recover_for_resource(&self, resource: &ResourceId) -> std::result::Result<(), RecoverBlock> {
        let records = self
            .journal
            .records_for(resource)
            .map_err(RecoverBlock::Corrupt)?;
        let mut conflict = None;
        for record in records {
            match self.recover_record(record) {
                Ok(RecoveryOutcome::ExternalConflict { .. }) => {
                    conflict = Some(
                        "the current state matches neither the journal's applied state nor its original state"
                            .to_string(),
                    );
                }
                Ok(_) => {}
                Err(error @ Error::JournalCorrupt(_)) => {
                    return Err(RecoverBlock::Corrupt(error));
                }
                Err(error) => {
                    return Err(RecoverBlock::Conflict(error.to_string()));
                }
            }
        }
        match conflict {
            Some(detail) => Err(RecoverBlock::Conflict(detail)),
            None => Ok(()),
        }
    }

    pub(crate) fn recover_stale(&self) -> Result<Vec<RecoveryOutcome>> {
        let records = self.journal.records()?;
        let mut outcomes = Vec::new();
        for record in records {
            let resource = record.resource.clone();
            match self.locks.try_acquire(&resource) {
                Ok(Some(lock)) => {
                    let outcome = self.recover_record(record)?;
                    drop(lock);
                    outcomes.push(outcome);
                }
                Ok(None) => outcomes.push(RecoveryOutcome::Busy { resource }),
                Err(Error::Conflict { .. }) => {
                    outcomes.push(RecoveryOutcome::Busy { resource });
                }
                Err(error) => return Err(error),
            }
        }
        Ok(outcomes)
    }

    pub(crate) fn abandon_journal(&self, resource: &ResourceId) -> Result<()> {
        let lock = self.locks.acquire(resource)?;
        let records = self.journal.records_for(resource)?;
        let mut result = Ok(());
        for record in records {
            if let Err(error) = self.journal.remove(&record.lease_id, resource) {
                result = Err(error);
                break;
            }
        }
        drop(lock);
        result
    }
}

/// Entry point for reading, applying, watching, reconciling, and safely
/// restoring host OS DNS configuration.
///
/// The central invariant: **we never destroy DNS state that we do not own.**
/// Every mutation belongs to an explicit owner and lease, is journaled before
/// it happens, is verified by read-back, and can be undone — unless an
/// external actor changed the state in the meantime, in which case
/// [`Error::ExternalModification`] is returned and nothing is touched.
///
/// ```
/// use osdns::{DnsConfig, DnsManager, DnsScope};
///
/// # fn main() -> osdns::Result<()> {
/// let manager = DnsManager::builder()
///     .owner("io.tunnet.agent")
///     // Selects a real platform backend (Linux, Windows, and macOS are
///     // supported).
///     .build();
/// # let _ = manager;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct DnsManager {
    inner: Arc<Inner>,
}

impl DnsManager {
    pub(crate) fn from_inner(inner: Arc<Inner>) -> Self {
        Self { inner }
    }

    /// Returns a builder for constructing a manager.
    pub fn builder() -> DnsManagerBuilder {
        DnsManagerBuilder::new()
    }

    /// The owner identifier every lease created by this manager carries.
    pub fn owner(&self) -> &str {
        &self.inner.owner
    }

    /// The configured conflict policy.
    pub fn conflict_policy(&self) -> ConflictPolicy {
        self.inner.conflict_policy
    }

    /// What the active backend can actually guarantee.
    pub fn capabilities(&self) -> Result<Capabilities> {
        Ok(self.inner.backend.capabilities())
    }

    /// Lists network interfaces known to the backend.
    pub fn interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        self.inner.backend.list_interfaces()
    }

    /// Reads the current DNS configuration of `scope` from the system.
    ///
    /// For multi-resource scopes this reports the primary resource (for
    /// example the network service backing the interface), not the per-domain
    /// scoped resolvers.
    pub fn snapshot(&self, scope: &DnsScope) -> Result<DnsConfig> {
        let resources = self
            .inner
            .backend
            .resolve_resources(scope, &NormalizedConfig::default())?;
        let resource = resources.first().ok_or_else(|| {
            Error::invalid_config("the backend resolved the scope to no resources")
        })?;
        let snapshot = self.inner.backend.capture(resource)?;
        self.inner.backend.public_state(&snapshot, scope)
    }

    /// Validates a configuration against backend capabilities without
    /// touching the system.
    pub fn validate(&self, config: &DnsConfig) -> Result<()> {
        let caps = self.inner.backend.capabilities();
        validate_against(config, &caps).map(|_| ())
    }

    /// Applies `config` transactionally and returns a [`Lease`] owning the
    /// mutated resources.
    ///
    /// The exact sequence: resolve resources, acquire exclusive resource
    /// locks (in sorted order, so multi-resource leases can never deadlock),
    /// inspect and recover any stale journals, capture current state, detect
    /// semantic no-ops, persist `Prepared` records, mutate and verify each
    /// resource by read-back, persist `Applied` records, and return the lease
    /// holding the locks.
    pub fn apply(&self, config: &DnsConfig) -> Result<Lease> {
        let caps = self.inner.backend.capabilities();
        let plan = validate_against(config, &caps)?;
        self.inner.fire(TxPoint::AfterValidate)?;
        let resources = self
            .inner
            .backend
            .resolve_resources(config.scope(), &plan)?;
        self.inner.fire(TxPoint::AfterResolve)?;
        let locks = self.inner.locks.acquire_all(&resources)?;
        self.inner.fire(TxPoint::AfterLock)?;
        for resource in &resources {
            match self.inner.recover_for_resource(resource) {
                Ok(()) => {}
                Err(RecoverBlock::Corrupt(error)) => return Err(error),
                Err(RecoverBlock::Conflict(detail)) => {
                    return Err(Error::Conflict {
                        resource: resource.clone(),
                        reason: ConflictReason::StaleJournalUnresolved { detail },
                    });
                }
            }
        }
        self.inner.fire(TxPoint::AfterRecovery)?;
        let mut befores = Vec::with_capacity(resources.len());
        for resource in &resources {
            befores.push(self.inner.backend.capture(resource)?);
            self.inner.fire(TxPoint::AfterCapture)?;
        }
        if resources
            .iter()
            .zip(&befores)
            .all(|(_resource, before)| self.inner.backend.matches_desired(before, &plan))
        {
            self.inner.fire(TxPoint::AfterNoopDecision)?;
            return Ok(Lease::new_noop(self.inner.clone(), resources, locks));
        }
        match self.inner.transact_with_locks(resources, &plan, befores) {
            Ok(records) => Ok(Lease::new_owned(self.inner.clone(), records, locks)),
            Err(error) => Err(error),
        }
    }

    /// Registers a callback for native DNS change notifications.
    ///
    /// Events are coalesced per resource within a small window, and events
    /// caused by this manager's own mutations are suppressed so they are
    /// never reported as external changes. Callbacks must still only enqueue
    /// or coalesce; never perform expensive or mutating work inside them.
    ///
    /// Under [`ConflictPolicy::Enforce`] this also starts the reconciliation
    /// worker, which rebases onto externally modified base state and reapplies
    /// the desired overlay of every active lease.
    pub fn watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let feed = if self.inner.conflict_policy == ConflictPolicy::Enforce {
            Some(crate::reconciliation::spawn_reconciler(self.inner.clone())?)
        } else {
            None
        };
        let coalescer =
            crate::watch::spawn_coalescer(self.inner.backend.kind(), callback, COALESCE_WINDOW)?;
        let suppressions = Arc::clone(&self.inner.suppressions);
        let filtered: WatchCallback = Arc::new(move |event| {
            if suppressions.is_suppressed(event.resource()) {
                return;
            }
            if let Some(feed) = &feed {
                let _ = feed.send(event.resource().clone());
            }
            coalescer(event);
        });
        self.inner.backend.start_watch(filtered)
    }

    /// Flushes the OS DNS cache, when the backend supports it.
    ///
    /// Best-effort only; correctness never depends on cache state.
    pub fn flush_cache(&self) -> Result<()> {
        self.inner.backend.flush_cache()
    }

    /// Scans the journal for records left behind by crashed or exited
    /// processes and recovers them where it is safe to do so.
    ///
    /// Resources whose lock is still held by an active lease (here or in
    /// another process) are reported as [`RecoveryOutcome::Busy`] and left
    /// untouched. On any parse failure the call fails closed with
    /// [`Error::JournalCorrupt`].
    pub fn recover_stale(&self) -> Result<Vec<RecoveryOutcome>> {
        self.inner.recover_stale()
    }

    /// Explicitly discards our ownership claim over `resource` without
    /// touching the system.
    ///
    /// Use this after an [`Error::ExternalModification`] conflict when the
    /// external state should win and the journal record should stop being
    /// reported.
    pub fn abandon_journal(&self, resource: &ResourceId) -> Result<()> {
        self.inner.abandon_journal(resource)
    }

    #[cfg(feature = "test-util")]
    /// Installs a fault injector for transaction-level failure and crash
    /// injection (testing only).
    pub fn install_fault_injector(&self, injector: Arc<crate::testing::FaultInjector>) {
        let hook: Arc<dyn FaultHook> = injector;
        *self
            .inner
            .hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }
}

impl std::fmt::Debug for DnsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsManager")
            .field("owner", &self.inner.owner)
            .field("conflict_policy", &self.inner.conflict_policy)
            .finish_non_exhaustive()
    }
}

/// Builder for [`DnsManager`].
pub struct DnsManagerBuilder {
    owner: Option<String>,
    state_dir: Option<PathBuf>,
    lock_timeout: Duration,
    conflict_policy: ConflictPolicy,
}

impl DnsManagerBuilder {
    pub(crate) fn new() -> Self {
        Self {
            owner: None,
            state_dir: None,
            lock_timeout: Duration::from_secs(30),
            conflict_policy: ConflictPolicy::default(),
        }
    }

    /// Sets the owner identifier (e.g. `io.tunnet.agent`). Required.
    ///
    /// Owners are reverse-DNS style identifiers: 1-255 characters of ASCII
    /// letters, digits, dots, dashes, and underscores.
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    /// Overrides the directory used for journals and resource locks.
    ///
    /// Defaults to a platform-appropriate system location. The directory is
    /// created and secured against unprivileged modification.
    pub fn state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Sets how long acquiring a contended resource lock may block.
    /// Defaults to 30 seconds.
    pub fn lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    /// Sets the conflict policy. Defaults to
    /// [`ConflictPolicy::Cooperative`].
    pub fn conflict_policy(mut self, policy: ConflictPolicy) -> Self {
        self.conflict_policy = policy;
        self
    }

    /// Builds the manager.
    ///
    /// Fails with [`Error::RequiresPrivilege`] when the state directory
    /// cannot be created or secured, and with [`Error::BackendUnavailable`]
    /// until a platform backend exists (phases 2-4).
    pub fn build(self) -> Result<DnsManager> {
        let owner = self
            .owner
            .ok_or_else(|| Error::invalid_config("an owner identifier is required"))?;
        validate_owner(&owner)?;
        if self.lock_timeout.is_zero() {
            return Err(Error::invalid_config(
                "lock_timeout must be greater than zero",
            ));
        }
        let state_dir = match self.state_dir {
            Some(dir) => dir,
            None => default_state_dir()?,
        };
        ensure_private_dir(&state_dir)?;
        let locks = ResourceLockManager::new(state_dir.join("locks"), self.lock_timeout);
        locks.ensure_dir()?;
        let journal = JournalStore::open(state_dir.join("journal"))?;
        let backend = select_default_backend(&owner)?;
        Ok(DnsManager::from_inner(Arc::new(Inner {
            owner,
            backend,
            locks,
            journal,
            conflict_policy: self.conflict_policy,
            hook: Mutex::new(None),
            suppressions: Arc::new(SuppressionRegistry::new()),
            active: Mutex::new(HashMap::new()),
            lease_tokens: Mutex::new(HashMap::new()),
            reconciler: Reconciler::default(),
        })))
    }
}

impl Default for DnsManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_owner(owner: &str) -> Result<()> {
    if owner.is_empty() || owner.len() > 255 {
        return Err(Error::invalid_config(
            "owner identifier must be 1-255 characters",
        ));
    }
    for c in owner.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
            return Err(Error::invalid_config(format_args!(
                "owner identifier {owner:?} contains invalid character {c:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn default_state_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("PROGRAMDATA") {
        return Ok(PathBuf::from(dir).join("osdns"));
    }
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        return Ok(PathBuf::from(dir).join("osdns"));
    }
    Err(Error::RequiresPrivilege(
        "cannot determine the default state directory; set one explicitly with state_dir()"
            .to_string(),
    ))
}

#[cfg(target_os = "macos")]
fn default_state_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("/Library/Application Support/osdns"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn default_state_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("/var/lib/osdns"))
}
