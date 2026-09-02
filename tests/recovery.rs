//! Crash recovery and compare-before-restore.
#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::testing::{CrashOutcome, FaultInjector, TxPoint};
use osdns::{Error, RecoveryOutcome};

fn crash_apply(fixture: &Fixture, point: TxPoint, ns: &str) {
    let injector = FaultInjector::new();
    injector.crash_at(point);
    fixture.manager.install_fault_injector(injector.clone());
    let outcome = osdns::testing::catch_crash(|| fixture.manager.apply(&iface_config(1, ns)));
    injector.clear();
    assert!(
        matches!(outcome, CrashOutcome::Crashed),
        "expected a simulated crash at {point:?}"
    );
}

#[test]
fn crash_before_mutation_recovers_by_clearing_journal() {
    let fixture = new_fixture("recovery-prepared");
    crash_apply(&fixture, TxPoint::AfterPrepared, "1.1.1.1");
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty),
        "mutation had not started yet"
    );
    assert_eq!(journal_files(&fixture.dir).len(), 1);

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(matches!(
        &outcomes[0],
        RecoveryOutcome::JournalCleared { .. }
    ));
    assert!(journal_files(&fixture.dir).is_empty());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}

#[test]
fn crash_after_apply_restores_original() {
    let fixture = new_fixture("recovery-applied");
    crash_apply(&fixture, TxPoint::AfterApply, "1.1.1.1");
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1")),
        "mutation happened but was never verified"
    );
    assert_eq!(journal_files(&fixture.dir).len(), 1);

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(matches!(&outcomes[0], RecoveryOutcome::Restored { .. }));
    assert!(journal_files(&fixture.dir).is_empty());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}

#[test]
fn crash_after_journal_applied_restores_original() {
    let fixture = new_fixture("recovery-journal-applied");
    crash_apply(&fixture, TxPoint::AfterApplied, "1.1.1.1");
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(matches!(&outcomes[0], RecoveryOutcome::Restored { .. }));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}

#[test]
fn crash_is_recovered_implicitly_by_next_apply() {
    let fixture = new_fixture("recovery-implicit");
    crash_apply(&fixture, TxPoint::AfterApply, "1.1.1.1");

    let lease = fixture.manager.apply(&iface_config(1, "8.8.8.8")).unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("8.8.8.8"))
    );
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn external_change_during_crash_window_is_never_overwritten() {
    let fixture = new_fixture("recovery-external");
    crash_apply(&fixture, TxPoint::AfterApply, "1.1.1.1");
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(matches!(
        &outcomes[0],
        RecoveryOutcome::ExternalConflict { .. }
    ));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "the external change must win"
    );
    assert_eq!(
        journal_files(&fixture.dir).len(),
        1,
        "conflicting journal is kept for forensics"
    );

    let err = fixture
        .manager
        .apply(&iface_config(1, "8.8.8.8"))
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Conflict {
            reason: osdns::ConflictReason::StaleJournalUnresolved { .. },
            ..
        }
    ));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );

    fixture
        .manager
        .abandon_journal(&resource_id(IFACE1))
        .unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
    fixture
        .manager
        .apply(&iface_config(1, "8.8.8.8"))
        .unwrap()
        .restore()
        .unwrap();
}

#[test]
fn crash_during_update_with_old_state_still_recorded() {
    let fixture = new_fixture("recovery-update-prepared");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();

    let injector = FaultInjector::new();
    injector.crash_at(TxPoint::AfterUpdatePrepared);
    fixture.manager.install_fault_injector(injector.clone());
    let outcome = osdns::testing::catch_crash(|| lease.update(&iface_config(1, "8.8.8.8")));
    injector.clear();
    assert!(matches!(outcome, CrashOutcome::Crashed));

    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1")),
        "the update mutation had not started"
    );

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(matches!(&outcomes[0], RecoveryOutcome::Restored { .. }));
    assert!(journal_files(&fixture.dir).is_empty());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}

#[test]
fn crash_during_update_after_mutation_restores_original() {
    let fixture = new_fixture("recovery-update-apply");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();

    let injector = FaultInjector::new();
    injector.crash_at(TxPoint::AfterUpdateApply);
    fixture.manager.install_fault_injector(injector.clone());
    let outcome = osdns::testing::catch_crash(|| lease.update(&iface_config(1, "8.8.8.8")));
    injector.clear();
    assert!(matches!(outcome, CrashOutcome::Crashed));

    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("8.8.8.8")),
        "the update mutation took effect but was never journaled as applied"
    );

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(matches!(&outcomes[0], RecoveryOutcome::Restored { .. }));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}

#[test]
fn recovery_is_serialized_per_resource() {
    let fixture = new_fixture("recovery-two-resources");
    crash_apply(&fixture, TxPoint::AfterApply, "1.1.1.1");
    let lease2 = fixture.manager.apply(&iface_config(2, "8.8.8.8")).unwrap();

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 2);
    let has_busy = outcomes.iter().any(
        |o| matches!(o, RecoveryOutcome::Busy { resource, .. } if resource == &resource_id(IFACE2)),
    );
    let has_restored = outcomes
        .iter()
        .any(|o| matches!(o, RecoveryOutcome::Restored { resource, .. } if resource == &resource_id(IFACE1)));
    assert!(has_busy, "leased resource must be skipped: {outcomes:?}");
    assert!(
        has_restored,
        "stale resource must be recovered: {outcomes:?}"
    );

    lease2.restore().unwrap();
}

#[test]
fn external_revert_of_applied_state_clears_journal() {
    let fixture = new_fixture("recovery-externally-reverted");
    crash_apply(&fixture, TxPoint::AfterApplied, "1.1.1.1");
    assert_eq!(journal_files(&fixture.dir).len(), 1);
    fixture
        .fake
        .external_change(IFACE1, osdns::testing::FakeState::Empty)
        .unwrap();

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(
        matches!(&outcomes[0], RecoveryOutcome::JournalCleared { .. }),
        "someone else reverted to the original state; nothing of ours is left: {outcomes:?}"
    );
    assert!(journal_files(&fixture.dir).is_empty());
}
