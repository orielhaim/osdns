use std::fmt;
use std::sync::Arc;

use parking_lot::Mutex;
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
    phase: LeasePhase,
}

enum LeasePhase {
    Active,
    Restoring,
    Abandoning,
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
                phase: LeasePhase::Active,
            })),
        }
    }

    /// Resources whose latest verified state still needs durable journal finalization.
    /// Live ownership proof remains usable, but a crash may leave an ambiguous journal.
    /// A later update or restore retries finalization; Enforce retries automatically.
    pub fn pending_durability(&self) -> Vec<ResourceId> {
        let state = self.state.lock();
        let mut resources = state
            .as_ref()
            .into_iter()
            .flat_map(|state| &state.live)
            .filter_map(|entry| {
                let live = entry.lock();
                (live.verified.is_some() || live.record.phase == crate::journal::Phase::Prepared)
                    .then(|| live.record.resource.clone())
            })
            .collect::<Vec<_>>();
        resources.sort();
        resources
    }

    /// The original resource set, fixed at apply time. After a partial restore,
    /// only the unresolved resources remain owned.
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
    /// successful updates move every resource to the new configuration.
    /// Failures attempt rollback to each immediately previous applied state.
    /// If rollback also fails, [`Error::TransactionFailed`] retains the failure
    /// details and the lease tracks the state that remains owned.
    /// The original `before` snapshots are
    /// preserved, so a later [`Lease::restore`] still returns the machine to
    /// the pre-lease state (or to the rebased external base under
    /// [`ConflictPolicy::Enforce`](crate::ConflictPolicy::Enforce)).
    /// When any resource was externally modified,
    /// [`Error::ExternalModification`] is returned and nothing is mutated.
    /// The target resource set must be identical; a valid configuration that
    /// resolves to different resources fails with
    /// [`Error::UpdateRequiresRebind`]: restore or abandon this lease and
    /// apply fresh.
    /// Once restoration has started, updates are rejected even if only some
    /// resources were restored. Retry restore or abandon the remaining state.
    pub fn update(&self, config: &DnsConfig) -> Result<()> {
        let caps = self.inner.backend.capabilities();
        let plan = validate_against(config, &caps)?;
        self.inner.backend.validate_plan(config.scope(), &plan)?;
        let mut guard = self.state.lock();
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
        if !matches!(state.phase, LeasePhase::Active)
            || state.live.iter().any(|entry| {
                let resource = entry.lock().record.resource.clone();
                !self.inner.active.lock().contains_key(&resource)
            })
        {
            *guard = Some(state);
            return Err(Error::LeaseEnding);
        }
        let LiveLease {
            live,
            _locks,
            phase,
        } = state;
        let repack = |live: Vec<Arc<Mutex<LiveRecord>>>| LiveLease {
            live,
            _locks,
            phase,
        };
        for entry in &live {
            let record = entry.lock().record.clone();
            match self.inner.backend.resource_status(&record.identity) {
                Ok(ResourceStatus::Same) => {}
                Ok(status @ (ResourceStatus::Gone | ResourceStatus::Replaced)) => {
                    *guard = Some(repack(live));
                    return Err(match status {
                        ResourceStatus::Gone => Error::ResourceGone {
                            backend: self.inner.backend.kind(),
                            resource: record.resource,
                            message: "the leased native resource incarnation is gone; restore or abandon the lease".to_string(),
                        },
                        ResourceStatus::Replaced => Error::ResourceIdentity {
                            backend: self.inner.backend.kind(),
                            resource: record.resource,
                            message: "the lease target was replaced; restore or abandon the lease".to_string(),
                        },
                        _ => unreachable!(),
                    });
                }
                Ok(ResourceStatus::Ambiguous) => {
                    *guard = Some(repack(live));
                    return Err(Error::ResourceIdentity {
                        backend: self.inner.backend.kind(),
                        resource: record.resource,
                        message: "the leased native resource incarnation cannot be proven; refusing update".to_string(),
                    });
                }
                Err(error) => {
                    *guard = Some(repack(live));
                    return Err(error);
                }
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
            .map(|record| record.lock().record.resource.clone())
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
        let tokens: Vec<std::sync::Arc<parking_lot::Mutex<()>>> = owned_sorted
            .iter()
            .map(|resource| self.inner.lease_token(resource))
            .collect();
        let token_guards: Vec<_> = tokens.iter().map(|token| token.lock()).collect();
        let result = self.inner.transact_update(&live, &plan);
        drop(token_guards);
        drop(tokens);
        *guard = Some(repack(live));
        self.inner.rescan_enforce();
        result
    }

    /// Restores the pre-lease state and ends the lease.
    ///
    /// This is the canonical way to end a lease. It consumes the lease; every
    /// owned resource is restored independently while the lease still owns
    /// current state ([`crate::OwnershipIdentity::Durable`] identity, or
    /// best-effort DNS comparison). Resources whose state was externally modified keep their
    /// journal record, and the first failure is reported through
    /// [`LeaseFailure`] together with the still-usable lease so it can be
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
    pub fn restore(self) -> std::result::Result<(), LeaseFailure> {
        match self.restore_state() {
            Ok(()) => Ok(()),
            Err(error) => Err(LeaseFailure { error, lease: self }),
        }
    }

    fn restore_state(&self) -> Result<()> {
        let mut guard = self.state.lock();
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
        let LiveLease {
            mut live,
            mut _locks,
            phase,
        } = state;
        let mut first_error = None;
        live.retain(|record| {
            let mut keep = true;
            self.inner.with_live_record(record, |live| {
                let resource = live.record.resource.clone();
                self.inner.unregister_active(&resource);
                match self.inner.restore_live_state(live) {
                    Ok(()) => {
                        _locks.retain(|lock| lock.resource() != &resource);
                        keep = false;
                    }
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            });
            keep
        });
        if matches!(phase, LeasePhase::Active) {
            self.inner.release_enforce_watch();
        }
        match first_error {
            None => {
                drop(_locks);
                Ok(())
            }
            Some(error) => {
                *guard = Some(LiveLease {
                    live,
                    _locks,
                    phase: LeasePhase::Restoring,
                });
                Err(error)
            }
        }
    }

    /// Ends the lease without touching the system: the ownership claims are
    /// released and the journal records removed.
    ///
    /// On failure, returns the lease with unresolved records and locks for retry.
    /// Dropping that returned lease retries journal removal without restoring DNS.
    /// A record that still cannot be removed remains eligible for crash recovery.
    /// Use this when the current
    /// (externally modified) state should win - typically after
    /// [`Error::ExternalModification`] from [`Lease::restore`]. Never fails
    /// due to external state; only journal I/O errors are reported.
    #[allow(clippy::result_large_err)]
    pub fn abandon(self) -> std::result::Result<(), LeaseFailure> {
        match self.abandon_state() {
            Ok(()) => Ok(()),
            Err(error) => Err(LeaseFailure { error, lease: self }),
        }
    }

    fn abandon_state(&self) -> Result<()> {
        let mut guard = self.state.lock();
        let Some(LiveLease {
            mut live,
            mut _locks,
            phase,
        }) = guard.take()
        else {
            return Ok(());
        };
        let mut failure = None;
        live.retain(|record| {
            let mut keep = true;
            self.inner.with_live_record(record, |live| {
                let resource = &live.record.resource;
                self.inner.unregister_active(resource);
                match self.inner.journal.remove(&live.record.lease_id, resource) {
                    Ok(()) => {
                        _locks.retain(|lock| lock.resource() != resource);
                        keep = false;
                    }
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            });
            keep
        });
        if matches!(phase, LeasePhase::Active) {
            self.inner.release_enforce_watch();
        }
        if let Some(error) = failure {
            *guard = Some(LiveLease {
                live,
                _locks,
                phase: LeasePhase::Abandoning,
            });
            Err(error)
        } else {
            Ok(())
        }
    }

    /// Releases locks and live registration without restoring or removing
    /// journals. Models process death for crash-recovery tests: in-memory
    /// proof is discarded.
    #[cfg(feature = "test-util")]
    pub fn debug_release_locks_keep_journal(self) {
        let mut guard = self.state.lock();
        if let Some(LiveLease {
            live,
            _locks,
            phase,
        }) = guard.take()
        {
            for record in &live {
                self.inner.with_live_record(record, |live| {
                    let resource = live.record.resource.clone();
                    self.inner.unregister_active(&resource);
                });
            }
            drop(_locks);
            if matches!(phase, LeasePhase::Active) {
                self.inner.release_enforce_watch();
            }
        }
    }
}

/// Failure returned by [`Lease::restore`] or [`Lease::abandon`]; retains the lease.
///
/// `error` is typically [`Error::ExternalModification`]: nothing was mutated
/// for the conflicting resource and its journal record was kept. The lease
/// still holds its locks, so the caller can retry `restore` after the
/// external state settles, or call [`Lease::abandon`] to leave the external
/// state in place. Convert to [`Error`] with `failure.error` or `into()`
/// when the lease should simply be dropped (dropping performs best-effort
/// restoration per resource, or journal cleanup after a failed abandon).
pub struct LeaseFailure {
    /// Why restoration or journal abandonment failed.
    pub error: Error,
    /// The lease, still holding its resource locks and journal records.
    pub lease: Lease,
}

impl From<LeaseFailure> for Error {
    fn from(failure: LeaseFailure) -> Self {
        failure.error
    }
}

impl fmt::Debug for LeaseFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseFailure")
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
        if let Some(LiveLease {
            live,
            _locks,
            phase,
        }) = self.state.lock().take()
        {
            for record in &live {
                self.inner.with_live_record(record, |live| {
                    let resource = live.record.resource.clone();
                    if matches!(phase, LeasePhase::Abandoning) {
                        if let Err(_error) = self.inner.journal.remove(&live.record.lease_id, &resource) {
                            osdns_warn!(resource = %resource, error = %_error, "abandon cleanup remains journaled for explicit recovery");
                        }
                    } else {
                        if let Err(_error) = self.inner.restore_live_state(live) {
                            osdns_warn!(resource = %resource, error = %_error, "lease drop could not restore; journal remains available for recovery");
                        }
                    }
                    self.inner.unregister_active(&resource);
                });
            }
            drop(_locks);
            if matches!(phase, LeasePhase::Active) {
                self.inner.release_enforce_watch();
            }
        }
    }
}
