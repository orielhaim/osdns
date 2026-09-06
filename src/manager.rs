use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use uuid::Uuid;

use crate::capability::{Capabilities, MutationGuard};
use crate::config::{DnsConfig, DnsScope, validate_against};
use crate::error::{ConflictReason, Error, Result};
use crate::fault::{CrashSignal, FaultAction, FaultHook, TxPoint};
use crate::fsutil::ensure_private_dir;
use crate::interface::InterfaceInfo;
use crate::journal::{JournalRecord, JournalStore, Phase, SCHEMA_VERSION};
use crate::lease::{Lease, LiveRecord};
use crate::normalize::NormalizedConfig;
use crate::ownership::{ResourceId, ResourceLockManager};
use crate::platform::{Backend, MutationAttempt, PlatformSnapshot, select_default_backend};
use crate::reconciliation::Reconciler;
use crate::watch::SuppressionRegistry;
use crate::watch::{WatchCallback, WatchHandle};

/// How the manager reacts when an external actor changes DNS state that we
/// hold a lease over.
///
/// - [`ConflictPolicy::Cooperative`] (default): never overwrite; surface
///   conflicts to the lease owner.
/// - [`ConflictPolicy::Enforce`]: for active VPN/mesh/tunnel agents; the
///   manager keeps the native observation needed for reconciliation alive
///   while at least one lease is active, without requiring a public
///   [`DnsManager::watch`] subscription. See [`DnsManager::watch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictPolicy {
    /// Never overwrite externally changed state automatically.
    ///
    /// Applies, updates, restores, and recovery report
    /// [`Error::ExternalModification`](crate::Error) and mutate nothing when
    /// current state is no longer ours. This is the default and the right
    /// choice unless the application is an always-on network agent.
    #[default]
    Cooperative,
    /// Rebase on legitimate external changes and reapply the overlay.
    ///
    /// Enforce is self-contained: the first active lease starts the internal
    /// native watch and reconciliation worker, and the last lease ending
    /// stops them. The reconciliation worker waits for stable authoritative
    /// state, adopts the new external base in the journal, and reapplies the
    /// lease's desired overlay transactionally. Restoring a rebased lease
    /// returns to the new external base. [`DnsManager::watch`] remains a
    /// pure observability subscription and is never required for Enforce to
    /// work. Backends without watch support fail lease creation with
    /// [`Error::Unsupported`] rather than silently behaving cooperatively.
    Enforce,
}

/// The result of inspecting one journal record during stale recovery.
///
/// Returned per record by [`DnsManager::recover_stale`]. `Restored` and
/// `JournalCleared` both removed the record; `ExternalConflict` kept it (call
/// [`DnsManager::abandon_journal`] to drop the claim without mutating);
/// `Busy` skipped a locked resource. The enum is `#[non_exhaustive]` so new
/// outcomes can be added without breakage.
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
    pub(crate) enforce: Mutex<EnforceState>,
}

/// Internal observation state for [`ConflictPolicy::Enforce`].
///
/// Independent of public [`DnsManager::watch`] subscriptions: the first
/// active lease starts one native watch feeding the shared reconciler, and
/// the last active lease ending stops it. `refs` counts live leases.
#[derive(Default)]
pub(crate) struct EnforceState {
    refs: usize,
    handle: Option<WatchHandle>,
    feed: Option<std::sync::mpsc::Sender<ResourceId>>,
    parked: bool,
}

impl std::fmt::Debug for EnforceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnforceState")
            .field("refs", &self.refs)
            .field("watching", &self.handle.is_some())
            .finish()
    }
}

const COALESCE_WINDOW: Duration = Duration::from_millis(50);

impl Inner {
    /// Starts internal Enforce observation when the first lease becomes
    /// active. Fails honestly with [`Error::Unsupported`] when the backend
    /// cannot watch, instead of silently behaving cooperatively.
    pub(crate) fn ensure_enforce_watch(self: &Arc<Self>) -> Result<()> {
        if self.conflict_policy != ConflictPolicy::Enforce {
            return Ok(());
        }
        if !self.backend.capabilities().watch {
            return Err(Error::unsupported(
                self.backend.kind(),
                "ConflictPolicy::Enforce requires change notifications, which this backend does not support",
            ));
        }
        let mut enforce = self
            .enforce
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if enforce.refs == 0 {
            debug_assert!(enforce.handle.is_none() && enforce.feed.is_none());
            let feed = crate::reconciliation::spawn_reconciler(Arc::clone(self))?;
            let feed_clone = feed.clone();
            let callback: WatchCallback = Arc::new(move |event| {
                let _ = feed_clone.send(event.resource().clone());
            });
            match self.backend.start_watch(callback) {
                Ok(handle) => {
                    enforce.handle = Some(handle);
                    enforce.feed = Some(feed);
                    enforce.parked = false;
                }
                Err(error) => {
                    drop(feed);
                    return Err(error);
                }
            }
        }
        enforce.refs += 1;
        Ok(())
    }

    /// Releases one Enforce lease reference, stopping internal observation
    /// when the last active lease ends.
    pub(crate) fn release_enforce_watch(&self) {
        if self.conflict_policy != ConflictPolicy::Enforce {
            return;
        }
        let mut enforce = self
            .enforce
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if enforce.refs == 0 {
            return;
        }
        enforce.refs -= 1;
        if enforce.refs == 0 {
            enforce.handle = None;
            enforce.feed = None;
            enforce.parked = false;
        }
    }

    /// Clones the internal Enforce feed when one is running, so public
    /// watchers share the same reconciler instead of spawning duplicate
    /// worker threads.
    pub(crate) fn enforce_feed(&self) -> Option<std::sync::mpsc::Sender<ResourceId>> {
        self.enforce
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .feed
            .clone()
    }

    /// Number of live leases holding Enforce observation (testing only).
    #[cfg(feature = "test-util")]
    #[allow(dead_code)]
    pub(crate) fn enforce_refs(&self) -> usize {
        self.enforce
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .refs
    }

    /// Drops the internal Enforce watch/feed without touching the refcount,
    /// so deterministic tests can drive reconciliation via `debug_reconcile`
    /// without racing a background worker. The lease-drop balance is kept:
    /// `release_enforce_watch` still runs once per lease.
    pub(crate) fn enforce_parked(&self) -> bool {
        self.enforce
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .parked
    }

    #[cfg(feature = "test-util")]
    #[allow(dead_code)]
    pub(crate) fn suspend_enforce_watch(&self) {
        {
            let mut enforce = self
                .enforce
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            enforce.handle = None;
            enforce.feed = None;
            enforce.parked = true;
        }
        self.reconciler.clear();
    }

    /// Queues an authoritative reconciliation of every active resource.
    /// Called after native observation is installed so changes that arrived
    /// in the watcher-start window cannot be missed.
    pub(crate) fn rescan_enforce(&self) {
        let Some(feed) = self.enforce_feed() else {
            return;
        };
        let resources: Vec<ResourceId> = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .cloned()
            .collect();
        for resource in resources {
            let _ = feed.send(resource);
        }
    }

    /// Whether the internal Enforce watcher is currently running.
    #[cfg(feature = "test-util")]
    #[allow(dead_code)]
    pub(crate) fn enforce_watching(&self) -> bool {
        self.enforce
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .handle
            .is_some()
    }
}

pub(crate) struct MutatePoints {
    apply: TxPoint,
    readback: TxPoint,
    verify: TxPoint,
}

pub(crate) const INITIAL_POINTS: MutatePoints = MutatePoints {
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

    /// Applies `plan` and verifies by read-back.
    ///
    /// `expected_current` is the caller's fresh ownership read. Backends with
    /// [`MutationGuard::CompareAndMutate`] refuse to overwrite a concurrent
    /// external change. A CAS rejection never rolls back. Rollback after a
    /// performed or proven-partial mutation uses the backend-issued proof,
    /// never a fresh post-failure read.
    pub(crate) fn mutate_and_verify(
        &self,
        resource: &ResourceId,
        expected_current: &PlatformSnapshot,
        plan: &NormalizedConfig,
        rollback_to: Option<&PlatformSnapshot>,
        points: MutatePoints,
        leftover: &mut Option<PlatformSnapshot>,
    ) -> Result<PlatformSnapshot> {
        leftover.take();
        self.suppressions.suppress(resource);
        match self.apply_attempt(resource, expected_current, plan) {
            MutationAttempt::Rejected { error } => Err(error),
            MutationAttempt::Indeterminate { error, produced } => {
                if !self.rollback_proven(resource, produced.as_ref(), rollback_to) {
                    *leftover = produced;
                }
                Err(error)
            }
            MutationAttempt::Performed { produced } => {
                let fail = |this: &Self,
                            leftover: &mut Option<PlatformSnapshot>,
                            produced: Option<PlatformSnapshot>,
                            error: Error| {
                    if !this.rollback_proven(resource, produced.as_ref(), rollback_to) {
                        *leftover = produced;
                    }
                    Err(error)
                };
                if let Err(error) = self.fire(points.apply) {
                    return fail(self, leftover, produced, error);
                }
                match self.backend.readback(resource) {
                    Ok(actual) => {
                        if let Err(error) = self.fire(points.readback) {
                            return fail(self, leftover, produced, error);
                        }
                        if !self.backend.matches_desired(&actual, plan) {
                            return fail(
                                self,
                                leftover,
                                produced,
                                Error::VerificationFailed {
                                    resource: resource.clone(),
                                    detail: "the state read back from the system does not match the desired configuration"
                                        .to_string(),
                                },
                            );
                        }
                        if let Err(error) = self.fire(points.verify) {
                            return fail(self, leftover, produced, error);
                        }
                        Ok(actual)
                    }
                    Err(error) => fail(self, leftover, produced, error),
                }
            }
        }
    }

    fn apply_attempt(
        &self,
        resource: &ResourceId,
        expected: &PlatformSnapshot,
        plan: &NormalizedConfig,
    ) -> MutationAttempt {
        match self.backend.mutation_guard() {
            MutationGuard::CompareAndMutate => self.backend.apply_guarded(resource, expected, plan),
            MutationGuard::Unconditional => {
                MutationAttempt::from_apply_result(self.backend.apply(resource, plan))
            }
        }
    }

    fn restore_if_current(
        &self,
        resource: &ResourceId,
        expected: &PlatformSnapshot,
        target: &PlatformSnapshot,
    ) -> Result<()> {
        match self.backend.mutation_guard() {
            MutationGuard::CompareAndMutate => self
                .backend
                .restore_guarded(resource, expected, target)
                .into_result(),
            MutationGuard::Unconditional => {
                let current = self.backend.readback(resource)?;
                if !self.backend.equivalent(&current, expected) {
                    return Err(Error::ExternalModification {
                        resource: resource.clone(),
                        detail: "the current state changed since ownership was verified"
                            .to_string(),
                    });
                }
                self.backend.restore(resource, target)
            }
        }
    }

    /// Rolls back only when `proof` is backend-issued identity of a state we
    /// created. A post-failure read is not proof.
    #[allow(unused_variables)]
    fn rollback_proven(
        &self,
        resource: &ResourceId,
        proof: Option<&PlatformSnapshot>,
        target: Option<&PlatformSnapshot>,
    ) -> bool {
        let (Some(proof), Some(target)) = (proof, target) else {
            return false;
        };
        if self.backend.equivalent(proof, target) {
            return true;
        }
        if let Err(error) = self.restore_if_current(resource, proof, target) {
            osdns_warn!(
                resource = %resource,
                error = %error,
                "rollback could not restore the previous state; the journal record was kept for later recovery"
            );
            return false;
        }
        match self.backend.readback(resource) {
            Ok(now) => self.backend.equivalent(&now, target),
            Err(error) => {
                osdns_warn!(
                    resource = %resource,
                    error = %error,
                    "rollback could not read back the restored state; the journal record was kept for later recovery"
                );
                false
            }
        }
    }

    /// Runs one apply transaction over already-locked resources.
    ///
    /// Returns the journal records plus whether the transaction was a
    /// semantic no-op (every `before` already expressed the plan). No-ops
    /// persist `Applied` records with `applied == before` and never touch
    /// the OS, but the returned lease is otherwise a fully owned,
    /// enforceable lease: it holds live records, active registration, and
    /// a lease id.
    pub(crate) fn transact_with_locks(
        &self,
        resources: Vec<ResourceId>,
        plan: &NormalizedConfig,
        befores: Vec<PlatformSnapshot>,
    ) -> Result<(Uuid, Vec<JournalRecord>, bool)> {
        let lease_id = Uuid::new_v4();
        let was_noop = resources
            .iter()
            .zip(&befores)
            .all(|(_resource, before)| self.backend.matches_desired(before, plan));
        if was_noop {
            let records: Vec<JournalRecord> = resources
                .into_iter()
                .zip(befores)
                .map(|(resource, before)| JournalRecord {
                    schema_version: SCHEMA_VERSION,
                    owner: self.owner.clone(),
                    lease_id,
                    resource,
                    backend: self.backend.kind(),
                    phase: Phase::Applied,
                    before: before.clone(),
                    desired: plan.clone(),
                    applied: Some(before),
                })
                .collect();
            for record in &records {
                self.journal.write(record)?;
            }
            self.fire(TxPoint::AfterApplied)?;
            return Ok((lease_id, records, true));
        }
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
            let expected = records[index].before.clone();
            let mut leftover = None;
            match self.mutate_and_verify(
                &records[index].resource,
                &expected,
                plan,
                Some(&records[index].before),
                INITIAL_POINTS,
                &mut leftover,
            ) {
                Ok(actual) => actuals.push(actual),
                Err(error) => {
                    for (record, proof) in records[..index].iter().zip(&actuals) {
                        if self.rollback_proven(&record.resource, Some(proof), Some(&record.before))
                        {
                            let _ = self.journal.remove(&record.lease_id, &record.resource);
                        }
                    }
                    let failed = &records[index];
                    if leftover.is_none()
                        && let Ok(now) = self.backend.readback(&failed.resource)
                        && self.backend.equivalent(&now, &failed.before)
                    {
                        let _ = self.journal.remove(&failed.lease_id, &failed.resource);
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
        Ok((lease_id, records, false))
    }

    /// Transactionally moves every owned resource to `plan` as one logical
    /// transaction: old complete configuration or new complete configuration,
    /// never a silently mixed configuration.
    ///
    /// Sequence: verify all resources still match their applied state, write
    /// all `Prepared` records, mutate+verify each resource, then write all
    /// `Applied` records. On any failure, previously updated resources are
    /// rolled back to their immediately previous applied state and every
    /// journal record is restored to its pre-update form.
    pub(crate) fn transact_update(
        &self,
        live: &[Arc<Mutex<LiveRecord>>],
        plan: &NormalizedConfig,
    ) -> Result<()> {
        self.fire(TxPoint::AfterUpdateResolve)?;
        // Snapshot the pre-update records and verify ownership first; no
        // mutation happens below until every resource is proven still ours.
        let mut olds: Vec<JournalRecord> = Vec::with_capacity(live.len());
        let mut applieds: Vec<PlatformSnapshot> = Vec::with_capacity(live.len());
        for record in live {
            let guard = record
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let applied = guard.record.applied.clone().ok_or_else(|| {
                Error::platform(
                    self.backend.kind(),
                    format_args!(
                        "owned lease record for {} is missing its applied snapshot",
                        guard.record.resource
                    ),
                )
            })?;
            olds.push(guard.record.clone());
            applieds.push(applied);
        }
        let mut currents = Vec::with_capacity(live.len());
        for index in 0..live.len() {
            let resource = olds[index].resource.clone();
            let current = self.backend.readback(&resource)?;
            self.fire(TxPoint::AfterUpdateCapture)?;
            if !self.backend.equivalent(&current, &applieds[index]) {
                return Err(Error::ExternalModification {
                    resource,
                    detail: "the current state no longer matches the state applied by this lease"
                        .to_string(),
                });
            }
            currents.push(current);
        }
        if currents
            .iter()
            .all(|current| self.backend.matches_desired(current, plan))
        {
            self.fire(TxPoint::AfterUpdateNoopCheck)?;
            return Ok(());
        }
        // Persist the prepared intent for every resource before mutating any.
        for record in live {
            let mut guard = record
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.record.desired = plan.clone();
            guard.record.phase = Phase::Prepared;
            // `applied` still carries the previous applied state until the
            // mutation is verified; recovery therefore rolls back to it.
            if let Err(error) = self.journal.write(&guard.record) {
                // Restore any already-prepared journals to their old form so
                // the lease is never left half-prepared on a write failure.
                drop(guard);
                for (old, live_record) in olds.iter().zip(live.iter()) {
                    let mut guard = live_record
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    guard.record = old.clone();
                    let _ = self.journal.write(&guard.record);
                }
                return Err(error);
            }
        }
        self.fire(TxPoint::AfterUpdatePrepared)?;
        // On failure every touched resource (including the failed one)
        // rolls back to its previous applied state; journals are then
        // restored to their pre-update form.
        let mut actuals: Vec<Option<PlatformSnapshot>> = vec![None; live.len()];
        for index in 0..live.len() {
            let resource = olds[index].resource.clone();
            let expected = currents[index].clone();
            let mut leftover = None;
            match self.mutate_and_verify(
                &resource,
                &expected,
                plan,
                Some(&applieds[index]),
                UPDATE_POINTS,
                &mut leftover,
            ) {
                Ok(actual) => actuals[index] = Some(actual),
                Err(error) => {
                    for rollback_index in 0..index {
                        if let Some(proof) = &actuals[rollback_index] {
                            self.rollback_proven(
                                &olds[rollback_index].resource,
                                Some(proof),
                                Some(&applieds[rollback_index]),
                            );
                        }
                    }
                    self.fire(TxPoint::AfterUpdateVerify).ok();
                    for (old_index, (old, live_record)) in olds.iter().zip(live.iter()).enumerate()
                    {
                        let mut guard = live_record
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if old_index == index && leftover.is_some() {
                            guard.verified = leftover.take();
                            guard.record.phase = Phase::Prepared;
                            guard.record.applied = None;
                            let _ = self.journal.write(&guard.record);
                        } else {
                            guard.record = old.clone();
                            guard.verified = None;
                            let _ = self.journal.write(&guard.record);
                        }
                    }
                    return Err(error);
                }
            }
        }
        for (index, record) in live.iter().enumerate() {
            let mut guard = record
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.record.phase = Phase::Applied;
            guard.record.applied = actuals[index].clone();
            if let Err(error) = self.journal.write(&guard.record) {
                guard.verified = actuals[index].clone();
                guard.record.applied = None;
                guard.record.phase = Phase::Prepared;
                drop(guard);
                return Err(error);
            }
            guard.verified = None;
        }
        self.fire(TxPoint::AfterUpdateApplied)?;
        Ok(())
    }

    /// Restores one live-lease resource to its `before` snapshot, failing
    /// with [`Error::ExternalModification`] when the current state is no
    /// longer the verified applied state.
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
        // Only a verified applied snapshot proves ownership; a state that
        // merely matches the desired configuration does not.
        let applied = record.applied.as_ref().ok_or_else(|| Error::ExternalModification {
            resource: resource.clone(),
            detail: "the lease record carries no verified applied state; refusing to overwrite indeterminate state"
                .to_string(),
        })?;
        if !self.backend.equivalent(&current, applied) {
            return Err(Error::ExternalModification {
                resource: resource.clone(),
                detail: "the current state is neither the state applied by this lease nor the original state"
                    .to_string(),
            });
        }
        self.restore_if_current(resource, &current, &record.before)?;
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

    /// Crash recovery for one journal record. Only verified state is acted
    /// on: `current == before` clears the record, and `current == applied`
    /// restores the original. Anything else (including an unverified
    /// `Prepared` record whose state merely matches `desired`) reports
    /// `ExternalConflict` without mutating.
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
        let verified = record
            .applied
            .as_ref()
            .is_some_and(|applied| self.backend.equivalent(&current, applied));
        if verified {
            self.suppressions.suppress(&resource);
            if let Err(error) = self.restore_if_current(&resource, &current, &record.before) {
                if error.is_external_modification() {
                    return Ok(RecoveryOutcome::ExternalConflict {
                        resource,
                        lease_id: record.lease_id,
                    });
                }
                return Err(error);
            }
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
/// The central invariant is: **never overwrite DNS state that is not
/// demonstrably ours.** Every mutation belongs to an explicit owner and
/// [`Lease`], is journaled before it happens, is verified by read-back, and
/// can be undone - unless an external actor changed the state in the
/// meantime, in which case [`Error::ExternalModification`] is returned and
/// nothing is touched.
///
/// A manager is cheap to clone: clones share the same owner, backend, locks,
/// journal, and active-lease registry. It is `Send + Sync` and may be shared
/// across threads. Individual [`Lease`]s own their resources exclusively.
///
/// Mutations generally require elevated privileges (see [`Error::RequiresPrivilege`]);
/// `osdns` never escalates privileges on its own. Operations are synchronous
/// control-plane calls with no async runtime dependency.
///
/// After a process crash, journals left behind are recovered with
/// [`DnsManager::recover_stale`]; corrupt or unknown journal state fails
/// closed.
///
/// ```no_run
/// use osdns::{DnsConfig, DnsManager, DnsScope, InterfaceSelector};
///
/// # fn main() -> osdns::Result<()> {
/// let manager = DnsManager::builder()
///     .owner("io.example.agent")
///     .build()?;
/// let caps = manager.capabilities()?;
/// let current = manager.snapshot(&DnsScope::Interface(InterfaceSelector::Default))?;
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
    ///
    /// See [`DnsManagerBuilder`] for the required `owner` identifier and the
    /// optional state directory, lock timeout, and conflict policy.
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
    ///
    /// Never assumes uniformity across platforms: check fields such as
    /// `split_dns`, `per_interface_dns`, or `watch` before using the
    /// corresponding facility. Returns [`Error::BackendUnavailable`] only
    /// when no backend exists on this host.
    pub fn capabilities(&self) -> Result<Capabilities> {
        Ok(self.inner.backend.capabilities())
    }

    /// Lists network interfaces known to the backend.
    ///
    /// Read-only; requires no privileges beyond what the platform needs for
    /// enumeration. Names and indexes are selectors only - backends identify
    /// interfaces by stable native identifiers internally.
    pub fn interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        self.inner.backend.list_interfaces()
    }

    /// Reads the current DNS configuration of `scope` from the system.
    ///
    /// Read-only and side-effect free. For multi-resource scopes this reports
    /// the primary resource (for example the network service backing the
    /// interface), not per-domain scoped state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BackendUnavailable`] when the scope cannot be resolved
    /// on this backend and [`Error::Platform`] when the OS read fails.
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
    ///
    /// No locks are taken, no journal is written, and no OS state is read.
    /// Returns [`Error::InvalidConfig`] for malformed input and
    /// [`Error::Unsupported`] when the active backend cannot represent the
    /// request. [`DnsManager::apply`] performs the same check again before
    /// any mutation.
    pub fn validate(&self, config: &DnsConfig) -> Result<()> {
        let caps = self.inner.backend.capabilities();
        let plan = validate_against(config, &caps)?;
        self.inner.backend.validate_plan(config.scope(), &plan)?;
        Ok(())
    }

    /// Applies `config` transactionally and returns a [`Lease`] owning the
    /// resources.
    ///
    /// Every lease owns journal records and live reconciliation state, even
    /// when the desired state is already in effect: a no-op apply persists
    /// `Applied` records with `applied == before` instead of mutating, so
    /// an [`ConflictPolicy::Enforce`] lease over pre-existing desired state
    /// is still an enforceable ownership state with active reconciliation.
    ///
    /// The sequence is: resolve resources, acquire exclusive inter-process
    /// locks in sorted order (so multi-resource leases cannot deadlock),
    /// recover stale journals for those resources, capture current state,
    /// persist `Prepared` records (or `Applied` directly for the no-op
    /// fast path), mutate and verify each resource by read-back
    /// (attempting guarded rollback on failure), persist `Applied`
    /// records, and return the lease holding the locks.
    ///
    /// The operation is atomic per resource, not across resources: when a
    /// later resource fails, earlier resources are rolled back best-effort
    /// and their journals retained for [`DnsManager::recover_stale`].
    /// Requires elevated privileges on most platforms; see
    /// [`Error::RequiresPrivilege`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use osdns::{DnsConfig, DnsManager, DnsScope, InterfaceSelector};
    /// # fn main() -> osdns::Result<()> {
    /// # let manager = DnsManager::builder().owner("io.example.agent").build()?;
    /// let config = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Default))
    ///     .nameserver("127.0.0.1".parse().unwrap())
    ///     .build()?;
    /// let lease = manager.apply(&config)?;
    /// lease.restore()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn apply(&self, config: &DnsConfig) -> Result<Lease> {
        let caps = self.inner.backend.capabilities();
        let plan = validate_against(config, &caps)?;
        self.inner.backend.validate_plan(config.scope(), &plan)?;
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
        self.inner.fire(TxPoint::AfterNoopDecision)?;
        match self.inner.transact_with_locks(resources, &plan, befores) {
            Ok((lease_id, records, was_noop)) => {
                let lease =
                    Lease::new_owned(self.inner.clone(), lease_id, records, locks, was_noop);
                if let Err(error) = self.inner.ensure_enforce_watch() {
                    let _ = lease.restore();
                    return Err(error);
                }
                self.inner.rescan_enforce();
                Ok(lease)
            }
            Err(error) => Err(error),
        }
    }

    /// Registers a callback for native DNS change notifications.
    ///
    /// This is a pure observability subscription: events are coalesced per
    /// resource within a small window, and events caused by this manager's
    /// own mutations are suppressed for the user-callback path. It is never
    /// required for [`ConflictPolicy::Enforce`] to work; Enforce keeps its
    /// own internal observation alive while leases are active.
    ///
    /// Under [`ConflictPolicy::Enforce`] every event observed here is also
    /// fed to the shared reconciliation worker *before* suppression: the
    /// worker reads the authoritative state, treats events matching our
    /// applied overlay as no-ops (state-aware suppression), and
    /// rebases/reapplies on genuine external changes. Events deferred by the
    /// worker's scheduler are pending, never dropped. When internal Enforce
    /// observation is already running, this reuses its worker instead of
    /// spawning a duplicate.
    ///
    /// The callback must only enqueue or coalesce events; it must never
    /// perform expensive or mutating work. The returned [`WatchHandle`]
    /// cancels this subscription's native notification when stopped or
    /// dropped; dropping it never disables Enforce while an active lease
    /// still requires it.
    pub fn watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let feed = if self.inner.conflict_policy == ConflictPolicy::Enforce {
            match self.inner.enforce_feed() {
                Some(existing) => Some(existing),
                None => Some(crate::reconciliation::spawn_reconciler(self.inner.clone())?),
            }
        } else {
            None
        };
        let coalescer =
            crate::watch::spawn_coalescer(self.inner.backend.kind(), callback, COALESCE_WINDOW)?;
        let suppressions = Arc::clone(&self.inner.suppressions);
        let filtered: WatchCallback = Arc::new(move |event| {
            if let Some(feed) = &feed {
                let _ = feed.send(event.resource().clone());
            }
            if suppressions.is_suppressed(event.resource()) {
                return;
            }
            coalescer(event);
        });
        self.inner.backend.start_watch(filtered)
    }
    /// Flushes the OS DNS cache, when the backend supports it.
    ///
    /// Best-effort only; correctness never depends on cache state. Returns
    /// [`Error::Unsupported`] on backends without a flush facility. Check
    /// [`Capabilities::cache_flush`](crate::Capabilities) first.
    pub fn flush_cache(&self) -> Result<()> {
        self.inner.backend.flush_cache()
    }

    /// Scans the journal for records left behind by crashed or exited
    /// processes and recovers them where it is safe to do so.
    ///
    /// Resources locked by an active lease (in this or another process) are
    /// reported as [`RecoveryOutcome::Busy`] and left untouched. Records whose
    /// current state still matches their verified applied snapshot are
    /// restored to the original state; records already at the original state
    /// are simply cleared; anything else — including unverified `Prepared`
    /// records whose state merely matches the desired configuration — is
    /// reported as [`RecoveryOutcome::ExternalConflict`] and kept. On any
    /// parse failure or unknown schema version the call fails closed with
    /// [`Error::JournalCorrupt`] and mutates nothing.
    pub fn recover_stale(&self) -> Result<Vec<RecoveryOutcome>> {
        self.inner.recover_stale()
    }

    /// Explicitly discards our ownership claim over `resource` without
    /// touching the system.
    ///
    /// Removes this manager's journal records for `resource` while holding
    /// the resource lock. Use this after an [`Error::ExternalModification`]
    /// conflict when the external state should win and the record should stop
    /// being reported by [`DnsManager::recover_stale`]. Same primitive as
    /// [`Lease::abandon`](crate::Lease::abandon), but usable without holding
    /// the lease.
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

    /// Toggles injected journal write failures (testing only).
    #[cfg(feature = "test-util")]
    pub fn set_journal_fail_writes(&self, fail: bool) {
        self.inner.journal.set_fail_writes(fail);
    }

    /// Allows `skip` journal writes, then fails subsequent writes (testing
    /// only).
    #[cfg(feature = "test-util")]
    pub fn set_journal_fail_writes_after(&self, skip: u32) {
        self.inner.journal.set_fail_writes_after(skip);
    }

    /// Number of live leases holding internal Enforce observation (testing
    /// only). Cooperative managers always report zero.
    #[cfg(feature = "test-util")]
    pub fn debug_enforce_refs(&self) -> usize {
        self.inner.enforce_refs()
    }

    /// Whether the internal Enforce watcher is currently running (testing
    /// only).
    #[cfg(feature = "test-util")]
    pub fn debug_enforce_watching(&self) -> bool {
        self.inner.enforce_watching()
    }

    /// Stops the background Enforce worker without releasing the lease
    /// reference (testing only), so `debug_reconcile` drives reconciliation
    /// deterministically.
    #[cfg(feature = "test-util")]
    pub fn suspend_enforce_background(&self) {
        self.inner.suspend_enforce_watch();
    }

    /// Runs one synchronous reconciliation pass for `resource` (testing
    /// only), so Enforce semantics can be exercised deterministically
    /// without timing races against the worker thread.
    #[cfg(feature = "test-util")]
    pub fn debug_reconcile(&self, resource: &str) -> Result<crate::testing::DebugReconcile> {
        use crate::reconciliation::ReconcileOutcome;
        let resource: ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        Ok(
            match self
                .inner
                .reconcile_resource(&resource, &self.inner.reconciler)
            {
                ReconcileOutcome::NoActiveLease => crate::testing::DebugReconcile::NotOwned,
                ReconcileOutcome::StillOurs => crate::testing::DebugReconcile::StillOurs,
                ReconcileOutcome::Rebased => crate::testing::DebugReconcile::Rebased,
                ReconcileOutcome::Deferred => crate::testing::DebugReconcile::Deferred,
                ReconcileOutcome::Failed => crate::testing::DebugReconcile::Failed,
            },
        )
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
///
/// The `owner` identifier is required and names every lease, journal record,
/// and ownership marker this manager creates. Optional settings have stable
/// defaults: a platform-appropriate state directory, a 30-second lock
/// timeout, and [`ConflictPolicy::Cooperative`].
///
/// ```no_run
/// # use osdns::DnsManager;
/// # fn main() -> osdns::Result<()> {
/// let manager = DnsManager::builder()
///     .owner("io.example.agent")
///     .conflict_policy(osdns::ConflictPolicy::Cooperative)
///     .build()?;
/// # Ok(())
/// # }
/// ```
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

    /// Sets the owner identifier (e.g. `io.example.agent`). Required.
    ///
    /// Owners are reverse-DNS style identifiers: 1–255 characters of ASCII
    /// letters, digits, dots, dashes, and underscores. The owner tags every
    /// journal record and platform ownership marker, so two applications never
    /// mistake each other's state for their own. Invalid identifiers fail at
    /// [`DnsManagerBuilder::build`] with [`Error::InvalidConfig`].
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    /// Overrides the directory used for the durable journal.
    ///
    /// Defaults to a platform-appropriate system location (`/var/lib/osdns`
    /// on Linux, `PROGRAMDATA\osdns` on Windows, `/Library/Application
    /// Support/osdns` on macOS). The directory is created on
    /// [`DnsManagerBuilder::build`] and secured against unprivileged
    /// modification; failure surfaces as [`Error::RequiresPrivilege`] or
    /// [`Error::Io`].
    ///
    /// Journal storage never defines the ownership universe: inter-process
    /// resource locks live in a global system location independent of this
    /// setting, so two managers with different state directories still
    /// exclude each other on the same OS resource.
    pub fn state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Sets how long acquiring a contended resource lock may block.
    /// Defaults to 30 seconds. Must be non-zero. When the deadline expires,
    /// lock acquisition fails with [`Error::Timeout`] and nothing is mutated.
    pub fn lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    /// Sets the conflict policy. Defaults to
    /// [`ConflictPolicy::Cooperative`].
    ///
    /// [`ConflictPolicy::Enforce`] is self-contained and fails at build
    /// time when the backend cannot watch; no public
    /// [`DnsManager::watch`] subscription is ever required for it to work.
    pub fn conflict_policy(mut self, policy: ConflictPolicy) -> Self {
        self.conflict_policy = policy;
        self
    }

    /// Builds the manager.
    ///
    /// Fails with [`Error::RequiresPrivilege`] when the state directory
    /// cannot be created or secured, and with [`Error::BackendUnavailable`]
    /// when no platform backend is available on this host.
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
        // Locks are globally authoritative per OS resource, independent of
        // journal storage: a custom state_dir must never create a private
        // ownership universe. The directory is created lazily on first
        // lock acquisition so read-only flows never require its
        // privileges.
        let global_lock_dir = global_lock_root()?.join("locks");
        let locks = ResourceLockManager::new(global_lock_dir, self.lock_timeout);
        let journal = JournalStore::open(state_dir.join("journal"))?;
        let backend = select_default_backend(&owner)?;
        if self.conflict_policy == ConflictPolicy::Enforce && !backend.capabilities().watch {
            return Err(Error::unsupported(
                backend.kind(),
                "ConflictPolicy::Enforce requires change notifications, which this backend does not support",
            ));
        }
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
            enforce: Mutex::new(EnforceState::default()),
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
    windows_program_data().map(|dir| dir.join("osdns"))
}

#[cfg(target_os = "macos")]
fn default_state_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("/Library/Application Support/osdns"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn default_state_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("/var/lib/osdns"))
}

/// Machine-wide lock namespace. Independent of journal `state_dir` and of
/// process environment variables that can alias per-user directories.
pub(crate) fn global_lock_root() -> Result<PathBuf> {
    default_state_dir()
}

#[cfg(target_os = "windows")]
fn windows_program_data() -> Result<PathBuf> {
    use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    use windows::core::PWSTR;

    let pwstr: PWSTR = unsafe {
        SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None)
    }
    .map_err(|error| {
        Error::RequiresPrivilege(format!(
            "cannot resolve the machine ProgramData folder for the global lock namespace: {error}"
        ))
    })?;
    let path = unsafe { pwstr.to_string() }.map_err(|error| {
        Error::RequiresPrivilege(format!(
            "cannot decode the machine ProgramData folder: {error}"
        ))
    })?;
    unsafe {
        windows::Win32::System::Com::CoTaskMemFree(Some(pwstr.0.cast()));
    }
    if path.is_empty() {
        return Err(Error::RequiresPrivilege(
            "the machine ProgramData folder resolved empty; refusing a per-user lock namespace"
                .to_string(),
        ));
    }
    Ok(PathBuf::from(path))
}

#[cfg(all(test, target_os = "windows"))]
mod windows_lock_dir_tests {
    use super::windows_program_data;

    #[test]
    fn global_lock_root_ignores_programdata_and_localappdata() {
        let original_programdata = std::env::var_os("PROGRAMDATA");
        let original_local = std::env::var_os("LOCALAPPDATA");
        // SAFETY: tests in this process serialize on this function; we restore
        // the previous values before returning.
        unsafe {
            std::env::set_var("PROGRAMDATA", r"C:\osdns-test-programdata-not-real");
            std::env::set_var("LOCALAPPDATA", r"C:\osdns-test-localappdata-not-real");
        }
        let resolved = windows_program_data();
        unsafe {
            match original_programdata {
                Some(value) => std::env::set_var("PROGRAMDATA", value),
                None => std::env::remove_var("PROGRAMDATA"),
            }
            match original_local {
                Some(value) => std::env::set_var("LOCALAPPDATA", value),
                None => std::env::remove_var("LOCALAPPDATA"),
            }
        }
        let path = resolved.expect("machine ProgramData must be resolvable");
        let text = path.to_string_lossy();
        assert!(
            !text.contains("osdns-test-programdata-not-real"),
            "lock root followed PROGRAMDATA: {text}"
        );
        assert!(
            !text.contains("osdns-test-localappdata-not-real"),
            "lock root followed LOCALAPPDATA: {text}"
        );
    }
}
