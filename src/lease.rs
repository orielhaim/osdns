use std::fmt;
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::config::{DnsConfig, validate_against};
use crate::error::{ConflictReason, Error, Result};
use crate::fault::TxPoint;
use crate::journal::JournalRecord;
use crate::manager::Inner;
use crate::ownership::{ResourceId, ResourceLock};

/// A lease's authoritative, shared journal record.
///
/// The record lives behind a mutex so the Enforce-policy reconciler can
/// rebase `before`/`applied` in place while the lease is alive, keeping the
/// in-memory state, the journal, and the registry consistent.
pub(crate) struct LiveRecord {
    pub(crate) record: JournalRecord,
}

pub(crate) enum LeaseState {
    Noop {
        _locks: Vec<ResourceLock>,
    },
    Owned {
        live: Vec<Arc<Mutex<LiveRecord>>>,
        _locks: Vec<ResourceLock>,
    },
}

/// Exclusive, transactional ownership over DNS state.
///
/// A lease is created by [`DnsManager::apply`](crate::DnsManager::apply),
/// cannot be cloned, and holds the exclusive resource locks for its lifetime.
/// A single lease may span several resources (for example a primary network
/// service plus one scoped resolver file per routing domain); every resource
/// has its own journal record and its own compare-before-restore decision.
///
/// Explicit [`Lease::restore`] is the canonical way to end it; dropping
/// attempts a best-effort restore, but correctness must never depend on
/// `Drop` (a crashed process is recovered through
/// [`DnsManager::recover_stale`](crate::DnsManager::recover_stale)).
///
/// Restore is compare-before-restore per resource: the current state of a
/// resource is only overwritten when it still matches the state this lease
/// applied (or still matches the original state, in which case nothing needs
/// to happen). Otherwise [`Error::ExternalModification`] is returned for that
/// resource and nothing is mutated there.
///
/// Under [`ConflictPolicy::Enforce`](crate::ConflictPolicy::Enforce) an
/// active watch reconciles externally modified resources automatically by
/// rebasing onto the external state and reapplying this lease's desired
/// overlay; restore afterwards returns to that external base instead of the
/// pre-lease state, which is the point of the overlay model.
pub struct Lease {
    inner: Arc<Inner>,
    resources: Vec<ResourceId>,
    lease_id: Option<Uuid>,
    is_noop: bool,
    state: Mutex<Option<LeaseState>>,
}

impl Lease {
    pub(crate) fn new_noop(
        inner: Arc<Inner>,
        resources: Vec<ResourceId>,
        locks: Vec<ResourceLock>,
    ) -> Self {
        Self {
            inner,
            resources,
            lease_id: None,
            is_noop: true,
            state: Mutex::new(Some(LeaseState::Noop { _locks: locks })),
        }
    }

    pub(crate) fn new_owned(
        inner: Arc<Inner>,
        records: Vec<JournalRecord>,
        locks: Vec<ResourceLock>,
    ) -> Self {
        let mut resources = Vec::with_capacity(records.len());
        let mut live = Vec::with_capacity(records.len());
        let mut lease_id = None;
        for record in records {
            if lease_id.is_none() {
                lease_id = Some(record.lease_id);
            }
            resources.push(record.resource.clone());
            let shared = Arc::new(Mutex::new(LiveRecord { record }));
            inner.register_active(Arc::clone(&shared));
            live.push(shared);
        }
        Self {
            inner,
            resources,
            lease_id,
            is_noop: false,
            state: Mutex::new(Some(LeaseState::Owned {
                live,
                _locks: locks,
            })),
        }
    }

    /// The resources this lease owns.
    pub fn resources(&self) -> &[ResourceId] {
        &self.resources
    }

    /// The journal lease id, or `None` for a no-op lease.
    pub fn lease_id(&self) -> Option<Uuid> {
        self.lease_id
    }

    /// Whether this lease owns nothing (the desired state was already in
    /// effect at apply time). Restore and update on a no-op lease never
    /// touch the system unless `update` transitions it into an owned lease.
    pub fn is_noop(&self) -> bool {
        self.is_noop
    }

    /// Transactionally moves this lease to a new desired configuration.
    ///
    /// The original `before` snapshots are preserved, so a later
    /// [`Lease::restore`] still returns the machine to the pre-lease state
    /// (or to the rebased external base under
    /// [`ConflictPolicy::Enforce`](crate::ConflictPolicy::Enforce)).
    /// Each resource is checked against the state this lease applied; when
    /// any resource was externally modified, [`Error::ExternalModification`]
    /// is returned and that resource is left untouched. Resources updated
    /// before the failure keep their new state, and every resource stays
    /// individually journaled and recoverable.
    pub fn update(&self, config: &DnsConfig) -> Result<()> {
        let caps = self.inner.backend.capabilities();
        let plan = validate_against(config, &caps)?;
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) = guard.take() else {
            return Err(Error::Conflict {
                resource: self
                    .resources
                    .first()
                    .cloned()
                    .ok_or_else(|| Error::invalid_config("lease owns no resources"))?,
                reason: ConflictReason::LeaseNotActive,
            });
        };
        match state {
            LeaseState::Noop { _locks } => {
                let wanted = match self.inner.backend.resolve_resources(config.scope(), &plan) {
                    Ok(wanted) => wanted,
                    Err(error) => {
                        *guard = Some(LeaseState::Noop { _locks });
                        return Err(error);
                    }
                };
                let mut wanted_sorted = wanted.clone();
                wanted_sorted.sort();
                let mut owned_sorted = self.resources.clone();
                owned_sorted.sort();
                if wanted_sorted != owned_sorted {
                    *guard = Some(LeaseState::Noop { _locks });
                    return Err(Error::invalid_config(format_args!(
                        "update cannot change the target resources (lease owns {:?})",
                        self.resources
                    )));
                }
                self.inner.fire(TxPoint::AfterUpdateResolve)?;
                let mut befores = Vec::with_capacity(self.resources.len());
                for resource in self.resources.iter() {
                    befores.push(self.inner.backend.capture(resource)?);
                    self.inner.fire(TxPoint::AfterUpdateCapture)?;
                }
                let resources = self.resources.clone();
                if resources
                    .iter()
                    .zip(&befores)
                    .all(|(_resource, before)| self.inner.backend.matches_desired(before, &plan))
                {
                    self.inner.fire(TxPoint::AfterUpdateNoopCheck)?;
                    *guard = Some(LeaseState::Noop { _locks });
                    return Ok(());
                }
                match self.inner.transact_with_locks(resources, &plan, befores) {
                    Ok(records) => {
                        let shared = self.inner.share_records(records);
                        *guard = Some(LeaseState::Owned {
                            live: shared,
                            _locks,
                        });
                        Ok(())
                    }
                    Err(error) => {
                        *guard = Some(LeaseState::Noop { _locks });
                        Err(error)
                    }
                }
            }
            LeaseState::Owned { live, _locks } => {
                let wanted = match self.inner.backend.resolve_resources(config.scope(), &plan) {
                    Ok(wanted) => wanted,
                    Err(error) => {
                        *guard = Some(LeaseState::Owned { live, _locks });
                        return Err(error);
                    }
                };
                let mut wanted_sorted = wanted;
                wanted_sorted.sort();
                let mut owned_sorted: Vec<ResourceId> = live
                    .iter()
                    .map(|record| {
                        record
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .record
                            .resource
                            .clone()
                    })
                    .collect();
                owned_sorted.sort();
                if wanted_sorted != owned_sorted {
                    *guard = Some(LeaseState::Owned { live, _locks });
                    return Err(Error::invalid_config(format_args!(
                        "update cannot change the target resources (lease owns {:?})",
                        self.resources
                    )));
                }
                self.inner.fire(TxPoint::AfterUpdateResolve)?;
                let mut first_error = None;
                for record in &live {
                    let mut record = record
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let token = self.inner.lease_token(&record.record.resource);
                    let _token_guard = token
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if let Err(error) = self.inner.update_owned(&mut record.record, &plan) {
                        first_error = Some(error);
                        break;
                    }
                }
                *guard = Some(LeaseState::Owned { live, _locks });
                match first_error {
                    Some(error) => Err(error),
                    None => Ok(()),
                }
            }
        }
    }

    /// Restores the pre-lease state and ends the lease.
    ///
    /// This is the canonical way to end a lease. Every owned resource is
    /// restored independently; resources whose state was externally modified
    /// keep their journal record, and the first failure is reported through
    /// [`RestoreFailure`] together with the still-usable lease so it can be
    /// retried or explicitly given up with [`Lease::abandon`].
    #[allow(clippy::result_large_err)]
    pub fn restore(self) -> std::result::Result<(), RestoreFailure> {
        match self.restore_state() {
            Ok(()) => Ok(()),
            Err(error) => Err(RestoreFailure { error, lease: self }),
        }
    }

    fn restore_state(&self) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) = guard.take() else {
            return Err(Error::Conflict {
                resource: self
                    .resources
                    .first()
                    .cloned()
                    .ok_or_else(|| Error::invalid_config("lease owns no resources"))?,
                reason: ConflictReason::LeaseNotActive,
            });
        };
        match state {
            LeaseState::Noop { _locks } => {
                drop(_locks);
                Ok(())
            }
            LeaseState::Owned { live, _locks } => {
                let mut first_error = None;
                for record in &live {
                    let record = record
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let resource = record.record.resource.clone();
                    let token = self.inner.lease_token(&resource);
                    let _token_guard = token
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if let Err(error) = self.inner.restore_lease_state(&record.record) {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    } else {
                        self.inner.unregister_active(&resource);
                    }
                }
                match first_error {
                    None => {
                        drop(_locks);
                        Ok(())
                    }
                    Some(error) => {
                        *guard = Some(LeaseState::Owned { live, _locks });
                        Err(error)
                    }
                }
            }
        }
    }

    /// Ends the lease without touching the system: the ownership claims are
    /// released and the journal records removed.
    ///
    /// Use this when the current (externally modified) state should win.
    pub fn abandon(self) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(state) = guard.take() {
            match state {
                LeaseState::Noop { _locks } => {
                    drop(_locks);
                }
                LeaseState::Owned { live, _locks } => {
                    let mut failure = None;
                    for record in &live {
                        let record = record
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        let resource = record.record.resource.clone();
                        if failure.is_none()
                            && let Err(error) = self
                                .inner
                                .journal
                                .remove(&record.record.lease_id, &resource)
                        {
                            failure = Some(error);
                        }
                        self.inner.unregister_active(&resource);
                    }
                    drop(_locks);
                    if let Some(error) = failure {
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Failure returned by [`Lease::restore`]; carries the still-usable lease.
pub struct RestoreFailure {
    /// Why the restore failed. Typically [`Error::ExternalModification`].
    pub error: Error,
    /// The lease, still holding its resource locks and journal records.
    pub lease: Lease,
}

impl From<RestoreFailure> for Error {
    fn from(failure: RestoreFailure) -> Self {
        failure.error
    }
}

impl fmt::Debug for RestoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RestoreFailure")
            .field("error", &self.error)
            .field("lease", &self.lease)
            .finish()
    }
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("owner", &self.inner.owner)
            .field("resources", &self.resources)
            .field("lease_id", &self.lease_id)
            .field("is_noop", &self.is_noop)
            .finish()
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(state) = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            match state {
                LeaseState::Noop { _locks } => {
                    drop(_locks);
                }
                LeaseState::Owned { live, _locks } => {
                    for record in &live {
                        let record = record
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        let resource = record.record.resource.clone();
                        self.inner.best_effort_restore(&record.record);
                        self.inner.unregister_active(&resource);
                    }
                    drop(_locks);
                }
            }
        }
    }
}
