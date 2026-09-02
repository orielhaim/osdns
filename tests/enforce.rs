//! Enforce-policy reconciliation tests: external base changes are rebased
//! and the desired overlay reapplied; restore then returns to the external
//! base. Cooperative policy must keep the old conflict behavior.
//!
//! Reconciliation is state-aware (our own mutation events are no-ops) and
//! event-safe (events inside suppression or defer windows are pending, never
//! dropped), so external changes are acted on no matter when they arrive.

#![cfg(feature = "test-util")]

use std::time::{Duration, Instant};

mod common;

use common::*;
use osdns::testing::{
    CrashOutcome, DebugReconcile, FakeDns, FaultInjector, TxPoint, manager_for_testing_with_policy,
};
use osdns::{ConflictPolicy, RecoveryOutcome};

fn enforce_manager(tag: &str) -> Fixture {
    let dir = temp_dir(tag);
    let fake = FakeDns::new();
    let manager = manager_for_testing_with_policy(
        "io.osdns.test",
        &dir,
        &fake,
        Duration::from_secs(30),
        ConflictPolicy::Enforce,
    )
    .unwrap();
    Fixture { manager, fake, dir }
}

fn wait_until(predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("condition not reached within 5s");
}

#[test]
fn enforce_rebases_and_reapplies_on_external_change() {
    let fixture = enforce_manager("enforce-rebase");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let _watch = fixture.manager.watch(std::sync::Arc::new(|_| {})).unwrap();

    // Arrives immediately after our apply — inside any suppression window —
    // but state-aware reconciliation must still act on it.
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();

    wait_until(|| fixture.fake.current_state(IFACE1).unwrap() == Some(state_with("1.1.1.1")));

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "restore must return to the rebased external base, not the pre-lease state"
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn cooperative_still_reports_conflicts_without_reconciliation() {
    let fixture = new_fixture("enforce-coop");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let _watch = fixture.manager.watch(std::sync::Arc::new(|_| {})).unwrap();

    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    std::thread::sleep(Duration::from_millis(700));

    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "cooperative must never reapply"
    );
    let failure = lease.restore().unwrap_err();
    assert!(failure.error.is_external_modification());
}

#[test]
fn reconciled_lease_update_and_still_ours_are_stable() {
    let fixture = enforce_manager("enforce-still-ours");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let _watch = fixture.manager.watch(std::sync::Arc::new(|_| {})).unwrap();

    lease.update(&iface_config(1, "8.8.8.8")).unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("8.8.8.8"))
        .unwrap();

    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("8.8.8.8")),
        "an event matching the applied state must not trigger a reapply loop"
    );

    lease.restore().unwrap();
}

#[test]
fn reconciler_survives_without_watch() {
    let fixture = enforce_manager("enforce-nowatch");
    let _lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "without a watch there is no background worker and no reconciliation"
    );
}

#[test]
fn rebase_is_transactional_across_crash() {
    let fixture = enforce_manager("enforce-crash");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();

    let injector = FaultInjector::new();
    injector.crash_at(TxPoint::AfterApply);
    fixture.manager.install_fault_injector(injector.clone());

    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();

    // Synchronous reconcile: the crash lands after the overlay was applied
    // but before the `Applied` journal record was persisted. The journal
    // holds `Prepared` with the external base.
    let outcome =
        osdns::testing::catch_crash(|| fixture.manager.debug_reconcile("fake:interface:1"));
    injector.clear();
    assert!(matches!(outcome, CrashOutcome::Crashed));

    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1")),
        "the uncommitted overlay is on the OS"
    );
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Prepared");
    assert_eq!(
        record["before"]["data"]["Configured"]["nameservers"][0], "9.9.9.9",
        "the Prepared record must carry the external base, not the old one"
    );

    // Recovery (as a fresh process would do) must roll the uncommitted
    // overlay back to the external base — never to the old base.
    drop(lease);
    let outcomes = fixture.manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert!(matches!(&outcomes[0], RecoveryOutcome::Restored { .. }));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "recovery must restore the external base, never overwrite it"
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn rebase_journal_write_failure_defers_and_preserves_external_state() {
    let fixture = enforce_manager("enforce-journal-fail");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();

    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    fixture.manager.set_journal_fail_writes(true);

    let outcome = fixture.manager.debug_reconcile("fake:interface:1").unwrap();
    assert_eq!(outcome, DebugReconcile::Deferred);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "a journal failure must leave the external state untouched"
    );

    // The journal on disk still describes the original lease: the failed
    // write must not have replaced the old `before`/`applied` state.
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Applied");
    assert_eq!(
        record["applied"]["data"]["Configured"]["nameservers"][0],
        "1.1.1.1"
    );

    fixture.manager.set_journal_fail_writes(false);
    let outcome = fixture.manager.debug_reconcile("fake:interface:1").unwrap();
    assert_eq!(outcome, DebugReconcile::Rebased);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    let record = journal_record_json(&fixture.dir);
    assert_eq!(
        record["before"]["data"]["Configured"]["nameservers"][0],
        "9.9.9.9"
    );
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn failed_rebase_rollback_preserves_external_base(#[case] finalize_live: bool) {
    use osdns::testing::FakeOp;
    let fixture = enforce_manager("enforce-rollback-fail");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    // Allow both stability reads, then fail verification after apply.
    fixture
        .fake
        .inject_backend_failure_after(FakeOp::Readback, 2, 1, "verification read failed");
    fixture
        .fake
        .inject_backend_failure(FakeOp::Restore, 1, "rollback failed");
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Deferred
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Prepared");
    assert_eq!(
        record["before"]["data"]["Configured"]["nameservers"][0],
        "9.9.9.9"
    );

    if finalize_live {
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            DebugReconcile::StillOurs
        );
        lease.restore().unwrap();
    } else {
        drop(lease);
        drop(fixture.manager);
        let recovered = manager_for_testing(
            "io.osdns.test",
            &fixture.dir,
            &fixture.fake,
            Duration::from_secs(30),
        )
        .unwrap();
        let outcomes = recovered.recover_stale().unwrap();
        assert!(
            matches!(&outcomes[..], [RecoveryOutcome::Restored { .. }]),
            "{outcomes:?}"
        );
    }
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn events_during_defer_windows_are_pending_never_dropped() {
    let fixture = enforce_manager("enforce-defer");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();

    // Transitional churn: the interface disappears, then returns with an
    // external configuration. The first reconcile cannot read the resource
    // and defers; the second (after re-creation) must still act.
    assert!(fixture.fake.external_remove(IFACE1).unwrap());
    let outcome = fixture.manager.debug_reconcile("fake:interface:1").unwrap();
    assert_eq!(outcome, DebugReconcile::Deferred);

    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let outcome = fixture.manager.debug_reconcile("fake:interface:1").unwrap();
    assert_eq!(outcome, DebugReconcile::Rebased);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );

    // Two rapid external changes: the final journal base must be the last
    // external state, and the overlay must survive both rebases.
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    assert_eq!(
        fixture.manager.debug_reconcile("fake:interface:1").unwrap(),
        DebugReconcile::Rebased
    );
    fixture
        .fake
        .external_change(IFACE1, state_with("8.8.8.8"))
        .unwrap();
    assert_eq!(
        fixture.manager.debug_reconcile("fake:interface:1").unwrap(),
        DebugReconcile::Rebased
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    let record = journal_record_json(&fixture.dir);
    assert_eq!(
        record["before"]["data"]["Configured"]["nameservers"][0], "8.8.8.8",
        "the rebased journal base must track the latest external state"
    );

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("8.8.8.8"))
    );
}
