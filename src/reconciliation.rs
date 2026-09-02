//! Enforce-policy reconciliation: rebasing and reapplying an active lease's
//! desired overlay when an external actor changes the base DNS state.
//!
//! Reconciliation never runs as a background worker unless a watch is
//! active and the manager's conflict policy is [`Enforce`](crate::ConflictPolicy).
//! For every watcher event on a resource owned by an active lease the
//! reconciler:
//!
//! 1. takes the resource's lease token, serializing against concurrent
//!    `update`/`restore` on the same lease;
//! 2. rate-limits repeat attempts per resource;
//! 3. waits for a stable state (two read-backs separated by a window must
//!    agree) — a single watcher event is never treated as authoritative;
//! 4. classifies the state: still ours, base unchanged, or externally
//!    modified;
//! 5. on external modification: captures the external state as the new
//!    base, re-applies the desired overlay with bounded retries, verifies by
//!    read-back, and rewrites the journal record so crash recovery and
//!    restore keep working against the new base.
//!
//! Self-event suppression (owned by the watch path) plus the stability
//! window and the circuit breaker defend against feedback loops.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::journal::Phase;
use crate::lease::LiveRecord;
use crate::manager::Inner;
use crate::ownership::ResourceId;

pub(crate) const STABLE_WINDOW: Duration = Duration::from_millis(100);
pub(crate) const MIN_INTERVAL: Duration = Duration::from_millis(100);
const MAX_RETRIES: u32 = 3;
const RETRY_BACKOFF: Duration = Duration::from_millis(50);
const BREAKER_WINDOW: Duration = Duration::from_secs(5);
const BREAKER_THRESHOLD: usize = 6;
const BREAKER_COOLDOWN: Duration = Duration::from_secs(2);

/// What a single reconciliation pass decided. Returned by the testing-only
/// entry point so Enforce semantics can be tested deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconcileOutcome {
    NoActiveLease,
    RateLimited,
    CircuitOpen,
    Unstable,
    StillOurs,
    BaseUnchanged,
    Rebased,
    Failed,
}

#[derive(Default)]
struct ResourceState {
    attempts: VecDeque<Instant>,
    open_until: Option<Instant>,
    next_allowed: Option<Instant>,
}

/// Per-resource reconciliation bookkeeping: rate limiting and the
/// feedback-loop circuit breaker.
#[derive(Default)]
pub(crate) struct Reconciler {
    state: Mutex<HashMap<ResourceId, ResourceState>>,
}

enum Gate {
    Proceed,
    RateLimited,
    CircuitOpen,
}

impl Reconciler {
    fn gate(&self, resource: &ResourceId) -> Gate {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = state.entry(resource.clone()).or_default();
        let now = Instant::now();
        if let Some(open_until) = entry.open_until {
            if now < open_until {
                return Gate::CircuitOpen;
            }
            entry.open_until = None;
            entry.attempts.clear();
        }
        while let Some(oldest) = entry.attempts.front() {
            if now.duration_since(*oldest) > BREAKER_WINDOW {
                entry.attempts.pop_front();
            } else {
                break;
            }
        }
        if entry.attempts.len() >= BREAKER_THRESHOLD {
            entry.open_until = Some(now + BREAKER_COOLDOWN);
            entry.attempts.clear();
            return Gate::CircuitOpen;
        }
        if let Some(next_allowed) = entry.next_allowed
            && now < next_allowed
        {
            return Gate::RateLimited;
        }
        entry.attempts.push_back(now);
        entry.next_allowed = Some(now + MIN_INTERVAL);
        Gate::Proceed
    }
}

/// Spawns the reconciliation worker for an Enforce-policy manager and
/// returns the feed used to enqueue resources from watcher events.
pub(crate) fn spawn_reconciler(
    inner: Arc<Inner>,
) -> std::result::Result<std::sync::mpsc::Sender<ResourceId>, Error> {
    let (tx, rx) = std::sync::mpsc::channel::<ResourceId>();
    let reconciler = Reconciler::default();
    thread::Builder::new()
        .name("osdns-reconciler".to_string())
        .spawn(move || {
            for resource in rx {
                inner.reconcile_resource(&resource, &reconciler);
            }
        })
        .map_err(|e| Error::Platform {
            backend: crate::capability::BackendKind::Fake,
            message: format!("cannot spawn reconciler thread: {e}"),
        })?;
    Ok(tx)
}

impl Inner {
    pub(crate) fn lease_token(&self, resource: &ResourceId) -> Arc<Mutex<()>> {
        self.lease_tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(resource.clone())
            .or_default()
            .clone()
    }

    pub(crate) fn register_active(&self, record: Arc<Mutex<LiveRecord>>) {
        let resource = record
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record
            .resource
            .clone();
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(resource, record);
    }

    pub(crate) fn unregister_active(&self, resource: &ResourceId) {
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(resource);
        self.lease_tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(resource);
    }

    /// Runs one reconciliation pass for `resource`.
    pub(crate) fn reconcile_resource(
        &self,
        resource: &ResourceId,
        reconciler: &Reconciler,
    ) -> ReconcileOutcome {
        let Some(_entry) = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(resource)
            .cloned()
        else {
            return ReconcileOutcome::NoActiveLease;
        };
        let token = self.lease_token(resource);
        let _token_guard = token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(resource)
            .cloned()
        else {
            return ReconcileOutcome::NoActiveLease;
        };
        match reconciler.gate(resource) {
            Gate::Proceed => {}
            Gate::RateLimited => return ReconcileOutcome::RateLimited,
            Gate::CircuitOpen => return ReconcileOutcome::CircuitOpen,
        }

        let Ok(first) = self.backend.readback(resource) else {
            return ReconcileOutcome::Failed;
        };
        std::thread::sleep(STABLE_WINDOW);
        let Ok(second) = self.backend.readback(resource) else {
            return ReconcileOutcome::Failed;
        };
        if !self.backend.equivalent(&first, &second) {
            return ReconcileOutcome::Unstable;
        }

        let mut guard: MutexGuard<'_, LiveRecord> = entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let record = &mut guard.record;
        if self.backend.equivalent(&second, &record.before) {
            return ReconcileOutcome::BaseUnchanged;
        }
        if let Some(applied) = &record.applied
            && self.backend.equivalent(&second, applied)
        {
            return ReconcileOutcome::StillOurs;
        }

        // The external state is the new base. Rebase onto it and reapply the
        // desired overlay with bounded retries. Retry errors are folded into
        // the final warning instead of aborting the pass.
        self.suppressions.suppress(resource);
        let mut last_error: Option<Error> = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                std::thread::sleep(RETRY_BACKOFF);
            }
            if let Err(error) = self.backend.apply(resource, &record.desired) {
                last_error = Some(error);
                continue;
            }
            match self.backend.readback(resource) {
                Ok(actual) if self.backend.matches_desired(&actual, &record.desired) => {
                    record.before = second.clone();
                    record.applied = Some(actual);
                    record.phase = Phase::Applied;
                    #[allow(unused_variables)]
                    if let Err(error) = self.journal.write(record) {
                        osdns_warn!(
                            resource = %resource,
                            error = %error,
                            "reconciliation reapplied the overlay but could not rewrite the journal"
                        );
                        return ReconcileOutcome::Failed;
                    }
                    return ReconcileOutcome::Rebased;
                }
                Ok(_) => {
                    last_error = Some(Error::VerificationFailed {
                        resource: resource.clone(),
                        detail: "reconciliation reapply failed read-back verification".to_string(),
                    });
                }
                Err(error) => {
                    last_error = Some(error);
                }
            }
        }
        #[allow(unused_variables)]
        if let Some(error) = &last_error {
            osdns_warn!(
                resource = %resource,
                error = %error,
                "reconciliation could not reapply the desired overlay after external modification; the journal record was left for the next event"
            );
        } else {
            osdns_warn!(
                resource = %resource,
                "reconciliation could not reapply the desired overlay after external modification; the journal record was left for the next event"
            );
        }
        ReconcileOutcome::Failed
    }
}
