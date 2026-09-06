use std::fmt;
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::config::{DnsConfig, validate_against};
use crate::error::{ConflictReason, Error, Result};
use crate::journal::JournalRecord;
use crate::manager::Inner;
use crate::ownership::{ResourceId, ResourceLock};
use crate::platform::OwnershipProof;
use crate::platform::ResourceStatus;

/// A lease's authoritative, shared journal record.
///
/// The record lives behind a mutex so the Enforce-policy reconciler can
/// rebase `before`/`applied` in place while the lease is alive, keeping the
/// in-memory state, the journal, and the registry consistent.
pub(crate) struct LiveRecord {
    pub(crate) record: JournalRecord,
    /// Verified mutation identity retained when the durable `Applied` write
    /// failed. Never serialized; recovery must not see it.
    pub(crate) verified: Option<OwnershipProof>,
}

/// The live state of a [`Lease`]: shared journal records plus the
/// inter-process locks held until the lease ends. `None` (the `Mutex` in
/// [`Lease`] holding nothing) means the lease already ended.
pub(crate) struct LiveLease {
    live: Vec<Arc<Mutex<LiveRecord>>>,
    _locks: Vec<ResourceLock>,
}

/// Exclusive, transactional ownership over DNS state.
///
/// A lease is created by [`DnsManager::apply`](crate::DnsManager::apply),
/// cannot be cloned, and holds the exclusive inter-process resource locks for
/// its lifetime. It is `Send + Sync` but not `Clone`; move it to the scope
/// that owns the DNS state. A single lease may span several resources (for
/// example a primary network service plus one scoped resolver file per
/// routing domain); every resource has its own journal record and its own
/// compare-before-restore decision.
///
/// Explicit [`Lease::restore`] is the canonical way to end a lease; dropping
/// attempts a best-effort restore, but correctness must never depend on
/// `Drop` (a crashed process leaves its journal for
/// [`DnsManager::recover_stale`](crate::DnsManager::recover_stale)).
///
/// Restore is compare-before-restore per resource: the current state of a
/// resource is only overwritten when it still matches the state this lease
/// applied (or the original state, in which case nothing needs to happen).
/// Otherwise [`Error::ExternalModification`] is returned for that resource
/// and nothing is mutated there.
///
/// Under [`ConflictPolicy::Enforce`](crate::ConflictPolicy::Enforce) the
/// manager's internal observation reconciles externally modified resources
/// automatically by rebasing onto the external state and reapplying this
/// lease's desired overlay; restore afterwards returns to that external
/// base instead of the pre-lease state. No public watch subscription is
/// required.
///
/// # Example
///
/// ```no_run
/// # use osdns::{DnsConfig, DnsManager, DnsScope, InterfaceSelector};
/// # fn main() -> osdns::Result<()> {
/// # let manager = DnsManager::builder().owner("io.example.agent").build()?;
/// # let config = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Default))
/// #     .nameserver("127.0.0.1".parse().unwrap()).build()?;
/// let lease = manager.apply(&config)?;
/// // ... hold the lease while the configuration is needed ...
/// lease.restore()?;
/// # Ok(())
/// # }
/// ```
pub struct Lease {
    inner: Arc<Inner>,
    resources: Vec<ResourceId>,
    lease_id: Uuid,
    is_noop: bool,
    state: Mutex<Option<LiveLease>>,
}

impl Lease {
    /// Creates a lease owning `records` under `lease_id`. `was_noop`
    /// records whether the apply was a semantic no-op (desired already in
    /// effect, so `applied == before` and nothing was mutated); the lease
    /// is enforceable either way.
    pub(crate) fn new_owned(
        inner: Arc<Inner>,
        lease_id: Uuid,
        records: Vec<JournalRecord>,
        verified: Vec<Option<OwnershipProof>>,
        locks: Vec<ResourceLock>,
        was_noop: bool,
    ) -> Self {
        let mut resources = Vec::with_capacity(records.len());
        let mut live = Vec::with_capacity(records.len());
        for (record, verified) in records.into_iter().zip(verified) {
            resources.push(record.resource.clone());
            let shared = Arc::new(Mutex::new(LiveRecord { record, verified }));
            inner.register_active(Arc::clone(&shared));
            live.push(shared);
        }
        Self {
            inner,
            resources,
            lease_id,
            is_noop: was_noop,
            state: Mutex::new(Some(LiveLease {
                live,
                _locks: locks,
            })),
        }
    }

    /// The resources this lease owns. Empty only for a lease that was
    /// restored or abandoned; otherwise fixed at apply time.
    pub fn resources(&self) -> &[ResourceId] {
        &self.resources
    }

    /// The journal lease id shared by every record this lease owns.
    pub fn lease_id(&self) -> Uuid {
        self.lease_id
    }

    /// Whether the apply was a semantic no-op (the desired state was
    /// already in effect at apply time). A no-op lease is still a fully
    /// owned, enforceable lease: it holds locks, journal records, and
    /// active reconciliation state. Restore on a no-op lease clears the
    /// journal without touching the system unless external changes arrived
    /// (rebased or conflicting) in the meantime.
    pub fn is_noop(&self) -> bool {
        self.is_noop
    }

    /// Transactionally moves this lease to a new desired configuration.
    ///
    /// The update is one logical transaction across every owned resource:
    /// either all resources move to the new configuration or all remain on
    /// the old one (rolled back to their immediately previous applied state
    /// with journals restored). The original `before` snapshots are
    /// preserved, so a later [`Lease::restore`] still returns the machine to
    /// the pre-lease state (or to the rebased external base under
    /// [`ConflictPolicy::Enforce`](crate::ConflictPolicy::Enforce)).
    /// When any resource was externally modified,
    /// [`Error::ExternalModification`] is returned and nothing is mutated.
    /// The target resource set must be identical; a valid configuration that
    /// resolves to different resources fails with
    /// [`Error::UpdateRequiresRebind`]: restore or abandon this lease and
    /// apply fresh.
    pub fn update(&self, config: &DnsConfig) -> Result<()> {
        let caps = self.inner.backend.capabilities();
        let plan = validate_against(config, &caps)?;
        self.inner.backend.validate_plan(config.scope(), &plan)?;
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
        let LiveLease { live, _locks } = state;
        let repack = |live: Vec<Arc<Mutex<LiveRecord>>>| LiveLease { live, _locks };
        for entry in &live {
            let record = entry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .record
                .clone();
            if matches!(
                self.inner.backend.resource_status(&record.identity),
                Ok(ResourceStatus::Gone | ResourceStatus::Replaced)
            ) {
                if let Err(error) = self
                    .inner
                    .journal
                    .remove(&record.lease_id, &record.resource)
                {
                    *guard = Some(repack(live));
                    return Err(error);
                }
                self.inner.unregister_active(&record.resource);
                *guard = Some(repack(live));
                return Err(Error::ResourceGone {
                    backend: self.inner.backend.kind(),
                    resource: record.resource,
                    message: "the leased native resource incarnation no longer exists; its journal was cleared and a fresh lease is required".to_string(),
                });
            }
        }
        let wanted = match self.inner.backend.resolve_resources(config.scope(), &plan) {
            Ok(wanted) => wanted,
            Err(error) => {
                *guard = Some(repack(live));
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
            *guard = Some(repack(live));
            return Err(Error::UpdateRequiresRebind {
                owned: owned_sorted,
                requested: wanted_sorted,
            });
        }
        // Hold every per-resource token for the whole transaction so
        // reconciliation and concurrent updates cannot interleave with it.
        let tokens: Vec<std::sync::Arc<std::sync::Mutex<()>>> = owned_sorted
            .iter()
            .map(|resource| self.inner.lease_token(resource))
            .collect();
        let token_guards: Vec<_> = tokens
            .iter()
            .map(|token| {
                token
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            })
            .collect();
        let result = self.inner.transact_update(&live, &plan);
        drop(token_guards);
        drop(tokens);
        *guard = Some(repack(live));
        result
    }

    /// Restores the pre-lease state and ends the lease.
    ///
    /// This is the canonical way to end a lease. It consumes the lease; every
    /// owned resource is restored independently while the lease still owns
    /// current state ([`crate::OwnershipIdentity::Durable`] identity, or
    /// best-effort DNS comparison). Resources whose state was externally modified keep their
    /// journal record, and the first failure is reported through
    /// [`RestoreFailure`] together with the still-usable lease so it can be
    /// retried or explicitly given up with [`Lease::abandon`]. A no-op lease
    /// (desired already in effect) restores trivially by clearing its
    /// journal without touching the system, unless an external change
    /// arrived meanwhile.
    ///
    /// ```no_run
    /// # use osdns::{DnsConfig, DnsManager, DnsScope, InterfaceSelector};
    /// # fn main() -> osdns::Result<()> {
    /// # let manager = DnsManager::builder().owner("io.example.agent").build()?;
    /// # let config = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Default))
    /// #     .nameserver("127.0.0.1".parse().unwrap()).build()?;
    /// # let lease = manager.apply(&config)?;
    /// match lease.restore() {
    ///     Ok(()) => {}
    ///     Err(failure) if failure.error.is_external_modification() => {
    ///         failure.lease.abandon()?;
    ///     }
    ///     Err(failure) => return Err(failure.error),
    /// }
    /// # Ok(())
    /// # }
    /// ```
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
        let LiveLease { live, _locks } = state;
        let mut first_error = None;
        for record in &live {
            self.inner.with_live_record(record, |live| {
                let resource = live.record.resource.clone();
                if let Err(error) = self.inner.finalize_live(live, None) {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    return;
                }
                match self.inner.restore_lease_state(&live.record) {
                    Ok(()) => self.inner.unregister_active(&resource),
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            });
        }
        match first_error {
            None => {
                drop(_locks);
                self.inner.release_enforce_watch();
                Ok(())
            }
            Some(error) => {
                *guard = Some(LiveLease { live, _locks });
                Err(error)
            }
        }
    }

    /// Ends the lease without touching the system: the ownership claims are
    /// released and the journal records removed.
    ///
    /// Consumes the lease and releases its locks. Use this when the current
    /// (externally modified) state should win - typically after
    /// [`Error::ExternalModification`] from [`Lease::restore`]. Never fails
    /// due to external state; only journal I/O errors are reported.
    pub fn abandon(self) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(LiveLease { live, _locks }) = guard.take() {
            let mut failure = None;
            for record in &live {
                self.inner.with_live_record(record, |live| {
                    let resource = live.record.resource.clone();
                    if failure.is_none()
                        && let Err(error) =
                            self.inner.journal.remove(&live.record.lease_id, &resource)
                    {
                        failure = Some(error);
                    }
                    self.inner.unregister_active(&resource);
                });
            }
            drop(_locks);
            // Every live lease holds one Enforce reference.
            self.inner.release_enforce_watch();
            if let Some(error) = failure {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Releases locks and live registration without restoring or removing
    /// journals. Models process death for crash-recovery tests: in-memory
    /// proof is discarded.
    #[cfg(feature = "test-util")]
    pub fn debug_release_locks_keep_journal(self) {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(LiveLease { live, _locks }) = guard.take() {
            for record in &live {
                self.inner.with_live_record(record, |live| {
                    let resource = live.record.resource.clone();
                    self.inner.unregister_active(&resource);
                });
            }
            drop(_locks);
            self.inner.release_enforce_watch();
        }
    }
}

/// Failure returned by [`Lease::restore`]; carries the still-usable lease.
///
/// `error` is typically [`Error::ExternalModification`]: nothing was mutated
/// for the conflicting resource and its journal record was kept. The lease
/// still holds its locks, so the caller can retry `restore` after the
/// external state settles, or call [`Lease::abandon`] to leave the external
/// state in place. Convert to [`Error`] with `failure.error` or `into()`
/// when the lease should simply be dropped (dropping performs best-effort
/// restoration per resource).
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
        if let Some(LiveLease { live, _locks }) = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            for record in &live {
                self.inner.with_live_record(record, |live| {
                    let resource = live.record.resource.clone();
                    let _ = self.inner.finalize_live(live, None);
                    self.inner.best_effort_restore(&live.record);
                    self.inner.unregister_active(&resource);
                });
            }
            drop(_locks);
            self.inner.release_enforce_watch();
        }
    }
}
