//! Crash recovery and guarded restoration: only verified state is ever
//! acted on, and ambiguous state is reported without being mutated.
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

/// A crash once the mutation may have run leaves ambiguous state: the
/// `Prepared` record carries no verified snapshot, and `current ==
/// desired` alone never proves we applied it (an external actor may have
/// independently produced the same state). Recovery reports a conflict
/// and mutates nothing instead of overwriting possibly-external state.
#[test]
fn crash_after_apply_is_ambiguous_and_never_overwritten() {
    let fixture = new_fixture("recovery-applied");
    crash_apply(&fixture, TxPoint::AfterApply, "1.1.1.1");
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1")),
        "mutation happened but was never verified"
    );
    assert_eq!(journal_files(&fixture.dir).len(), 1);

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(
        matches!(&outcomes[0], RecoveryOutcome::ExternalConflict { .. }),
        "{outcomes:?}"
    );
    assert_eq!(journal_files(&fixture.dir).len(), 1);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1")),
        "ambiguous state must be left untouched"
    );

    fixture
        .manager
        .abandon_journal(&resource_id(IFACE1))
        .unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn prepared_crash_with_matching_external_state_is_conflict() {
    let fixture = new_fixture("recovery-prepared-external");
    crash_apply(&fixture, TxPoint::AfterPrepared, "1.1.1.1");

    fixture
        .fake
        .external_change(IFACE1, state_with("1.1.1.1"))
        .unwrap();

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(
        matches!(&outcomes[..], [RecoveryOutcome::ExternalConflict { .. }]),
        "{outcomes:?}"
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1")),
        "the external state must win"
    );
    assert_eq!(journal_files(&fixture.dir).len(), 1);
    fixture
        .manager
        .abandon_journal(&resource_id(IFACE1))
        .unwrap();
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
fn crash_recovery_does_not_claim_equivalent_rewritten_generation() {
    let fixture = new_fixture("recovery-same-dns-gen");
    crash_apply(&fixture, TxPoint::AfterApplied, "1.1.1.1");
    let ours = fixture.fake.generation(IFACE1).unwrap().unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("1.1.1.1"))
        .unwrap();
    let external = fixture.fake.generation(IFACE1).unwrap().unwrap();
    assert!(external > ours);

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(
        matches!(&outcomes[0], RecoveryOutcome::ExternalConflict { .. }),
        "{outcomes:?}"
    );
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), Some(external));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    fixture
        .manager
        .abandon_journal(&resource_id(IFACE1))
        .unwrap();
}

#[test]
fn crash_is_recovered_implicitly_by_next_apply() {
    let fixture = new_fixture("recovery-implicit");
    // A pre-mutation crash is unambiguous (nothing of ours is on the OS),
    // so the next apply clears it implicitly.
    crash_apply(&fixture, TxPoint::AfterPrepared, "1.1.1.1");

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

/// A crash after an update mutation ran but before it verified leaves the
/// new state unverified: it matches `desired` but no verified snapshot, so
/// recovery reports a conflict instead of rolling back to the original and
/// possibly overwriting an external actor's identical state.
#[test]
fn crash_during_update_after_mutation_is_ambiguous() {
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
    assert!(
        matches!(&outcomes[0], RecoveryOutcome::ExternalConflict { .. }),
        "{outcomes:?}"
    );
    assert_eq!(journal_files(&fixture.dir).len(), 1);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("8.8.8.8")),
        "ambiguous update state must be left untouched"
    );
    fixture
        .manager
        .abandon_journal(&resource_id(IFACE1))
        .unwrap();
}

#[test]
fn recovery_is_serialized_per_resource() {
    let fixture = new_fixture("recovery-two-resources");
    // Pre-mutation crash: unambiguous, so the stale resource is cleared
    // while the live lease on the other resource is skipped.
    crash_apply(&fixture, TxPoint::AfterPrepared, "1.1.1.1");
    let lease2 = fixture.manager.apply(&iface_config(2, "8.8.8.8")).unwrap();

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 2);
    let has_busy = outcomes.iter().any(
        |o| matches!(o, RecoveryOutcome::Busy { resource, .. } if resource == &resource_id(IFACE2)),
    );
    let has_cleared = outcomes
        .iter()
        .any(|o| matches!(o, RecoveryOutcome::JournalCleared { resource, .. } if resource == &resource_id(IFACE1)));
    assert!(has_busy, "leased resource must be skipped: {outcomes:?}");
    assert!(
        has_cleared,
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

#[test]
fn vanished_resource_is_terminal_and_journal_is_removed_without_dns_read() {
    let fixture = new_fixture("recovery-gone");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    lease.debug_release_locks_keep_journal();
    assert!(fixture.fake.external_remove(IFACE1).unwrap());
    fixture.fake.inject_backend_failure(
        osdns::testing::FakeOp::Capture,
        1,
        "must not capture gone resource",
    );

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(
        matches!(&outcomes[..], [RecoveryOutcome::Gone { resource, .. }] if resource == &resource_id(IFACE1))
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn replacement_at_same_selector_is_never_read_or_restored() {
    let fixture = new_fixture("recovery-replaced");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    lease.debug_release_locks_keep_journal();
    fixture.fake.external_remove(IFACE1).unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    fixture.fake.inject_backend_failure(
        osdns::testing::FakeOp::Capture,
        1,
        "replacement DNS must not be read",
    );

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(
        matches!(&outcomes[..], [RecoveryOutcome::Replaced { resource, .. }] if resource == &resource_id(IFACE1))
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn one_gone_record_does_not_block_a_recoverable_record() {
    let fixture = new_fixture("recovery-forward-progress");
    fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap()
        .debug_release_locks_keep_journal();
    fixture
        .manager
        .apply(&iface_config(2, "8.8.8.8"))
        .unwrap()
        .debug_release_locks_keep_journal();
    fixture.fake.external_remove(IFACE1).unwrap();

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(outcomes.iter().any(
        |o| matches!(o, RecoveryOutcome::Gone { resource, .. } if resource == &resource_id(IFACE1))
    ));
    assert!(outcomes.iter().any(|o| matches!(o, RecoveryOutcome::Restored { resource, .. } if resource == &resource_id(IFACE2))));
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn explicit_restore_terminally_releases_a_gone_resource() {
    let fixture = new_fixture("restore-gone");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.fake.external_remove(IFACE1).unwrap();
    lease.restore().unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn drop_terminally_releases_a_gone_resource() {
    let fixture = new_fixture("drop-gone");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.fake.external_remove(IFACE1).unwrap();
    drop(lease);
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn gone_is_not_reported_as_cleaned_when_journal_removal_fails() {
    let fixture = new_fixture("gone-remove-failure");
    fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap()
        .debug_release_locks_keep_journal();
    fixture.fake.external_remove(IFACE1).unwrap();
    fixture.manager.set_journal_fail_removes(true);

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(
        matches!(&outcomes[..], [RecoveryOutcome::Failed { resource, .. }] if resource == &resource_id(IFACE1))
    );
    assert_eq!(journal_files(&fixture.dir).len(), 1);
}

#[test]
fn resource_scoped_platform_errors_carry_the_target_structurally() {
    let error = Error::ResourcePlatform {
        backend: osdns::BackendKind::Fake,
        resource: resource_id(IFACE1),
        message: "native failure".to_string(),
    };
    assert!(
        matches!(error, Error::ResourcePlatform { resource, .. } if resource == resource_id(IFACE1))
    );
}
