//! Destructive race tests: external actors changing DNS state mid-transaction
//! or mid-lease, including the DHCP delete/create replacement pattern that
//! replaces files instead of writing them in place.

#![cfg(feature = "test-util")]

use rstest::rstest;

mod common;

use common::*;
use osdns::testing::{CrashOutcome, FakeState, FaultInjector, TxPoint};
use osdns::{Error, Lease, RecoveryOutcome};

#[test]
fn external_change_during_capture_window_fails_transaction() {
    let fixture = new_fixture("race-capture");
    let injector = FaultInjector::new();
    injector.fail_at(TxPoint::AfterCapture, "simulated read-back hiccup");
    fixture.manager.install_fault_injector(injector.clone());

    let error = fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap_err();
    injector.clear();
    assert!(matches!(error, Error::Platform { .. }));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty)
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn external_change_between_apply_and_readback_is_rolled_back() {
    let fixture = new_fixture("race-apply");
    let injector = FaultInjector::new();
    injector.fail_at(TxPoint::AfterApply, "read-back unavailable");
    fixture.manager.install_fault_injector(injector.clone());

    let error = fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap_err();
    injector.clear();
    assert!(matches!(error, Error::Platform { .. }));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty),
        "a failed transaction must roll back to the captured base"
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn delete_then_recreate_interface_is_transitional_not_authoritative() {
    let fixture = new_fixture("race-delete-recreate");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();

    assert!(fixture.fake.external_remove(IFACE1).unwrap());
    assert!(matches!(
        lease.update(&iface_config(1, "8.8.8.8")).unwrap_err(),
        Error::Platform { .. } | Error::InvalidConfig(_)
    ));

    let _ = fixture.fake.external_change(IFACE1, state_with("9.9.9.9"));
    let failure = lease.restore().unwrap_err();
    assert!(
        failure.error.is_external_modification(),
        "{:?}",
        failure.error
    );
    failure.lease.abandon().unwrap();
}

#[test]
fn external_write_between_two_leases_is_never_overwritten() {
    let fixture = new_fixture("race-two-leases");
    let first = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    first.restore().unwrap();

    let second = fixture.manager.apply(&iface_config(1, "8.8.8.8")).unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let failure = second.restore().unwrap_err();
    assert!(
        failure.error.is_external_modification(),
        "{:?}",
        failure.error
    );
    let second = failure.lease;

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Busy { .. }))
    );
    second.abandon().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
}

/// Crash safety per phase: a crash before any mutation leaves a `Prepared`
/// record over untouched state (cleared); a crash once the mutation may
/// have run leaves ambiguous state (an external actor could independently
/// have produced the same desired state), so recovery reports a conflict
/// and mutates nothing instead of overwriting possibly-external state.
#[rstest]
#[case(TxPoint::AfterPrepared, true)]
#[case(TxPoint::AfterApply, false)]
#[case(TxPoint::AfterReadback, false)]
#[case(TxPoint::AfterVerify, false)]
fn crash_at_every_mutation_phase_leaves_recoverable_state(
    #[case] point: TxPoint,
    #[case] expect_cleared: bool,
) {
    use osdns::RecoveryOutcome;
    let fixture = new_fixture("race-crash-phases");
    let injector = FaultInjector::new();
    injector.crash_at(point);
    fixture.manager.install_fault_injector(injector.clone());

    let outcome =
        osdns::testing::catch_crash(|| fixture.manager.apply(&iface_config(1, "1.1.1.1")));
    injector.clear();
    assert!(matches!(outcome, CrashOutcome::Crashed));

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    if expect_cleared {
        assert!(
            matches!(&outcomes[0], RecoveryOutcome::JournalCleared { .. }),
            "{outcomes:?}"
        );
        assert!(journal_files(&fixture.dir).is_empty(), "{outcomes:?}");
        assert_eq!(
            fixture.fake.current_state(IFACE1).unwrap(),
            Some(FakeState::Empty),
            "a pre-mutation crash must clear the journal without touching the system"
        );
    } else {
        // Ambiguous: the mutation may have run, but `current == desired`
        // alone never proves we applied it.
        assert!(
            matches!(&outcomes[0], RecoveryOutcome::ExternalConflict { .. }),
            "{outcomes:?}"
        );
        assert_eq!(
            journal_files(&fixture.dir).len(),
            1,
            "ambiguous journals are kept for forensics: {outcomes:?}"
        );
        assert_eq!(
            fixture.fake.current_state(IFACE1).unwrap(),
            Some(state_with("1.1.1.1")),
            "recovery must not overwrite ambiguous state"
        );
        // The claim can still be explicitly abandoned.
        fixture
            .manager
            .abandon_journal(&resource_id(IFACE1))
            .unwrap();
        assert!(journal_files(&fixture.dir).is_empty());
    }
}

#[test]
fn lease_keeps_working_after_recover_attempt_on_live_resource() {
    let fixture = new_fixture("race-live-recover");
    let lease: Lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(matches!(&outcomes[0], RecoveryOutcome::Busy { .. }));
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty)
    );
}

#[test]
fn restore_refuses_concurrent_external_change() {
    let fixture = new_fixture("race-restore-guard");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();

    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let failure = lease.restore().unwrap_err();
    assert!(failure.error.is_external_modification());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "the concurrent change must survive"
    );
    failure.lease.abandon().unwrap();
}

#[test]
fn update_refuses_concurrent_external_change() {
    let fixture = new_fixture("race-update-guard");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let err = lease.update(&iface_config(1, "8.8.8.8")).unwrap_err();
    assert!(err.is_external_modification(), "{err:?}");
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "the concurrent change must survive the refused update"
    );
    lease.abandon().unwrap();
}

#[test]
fn cas_rejection_does_not_rollback_over_external_state() {
    let fixture = new_fixture("race-cas-reject");
    fixture
        .fake
        .inject_external_before_guarded(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let err = fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap_err();
    assert!(err.is_external_modification(), "{err:?}");
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "a CAS rejection must leave the external state untouched"
    );
}

#[test]
fn partial_mutation_then_external_change_is_not_rolled_over() {
    let fixture = new_fixture("race-partial-then-external");
    fixture.fake.inject_partial_apply_failure(1);
    fixture
        .fake
        .inject_external_after_guarded_mutation(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let err = fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap_err();
    assert!(matches!(err, Error::Platform { .. }), "{err:?}");
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "rollback must not overwrite an external write that landed after our partial mutation"
    );
}

#[test]
fn indeterminate_apply_without_proof_does_not_rollback() {
    let fixture = new_fixture("race-indeterminate-no-proof");
    fixture.fake.inject_backend_failure(
        osdns::testing::FakeOp::Apply,
        1,
        "apply failed before mutating",
    );
    let err = fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap_err();
    assert!(matches!(err, Error::Platform { .. }), "{err:?}");
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty)
    );
}

#[test]
fn same_dns_generation_bump_is_not_ours_on_update_or_restore() {
    let fixture = new_fixture("race-same-dns-gen");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let ours = fixture.fake.generation(IFACE1).unwrap().unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("1.1.1.1"))
        .unwrap();
    let external = fixture.fake.generation(IFACE1).unwrap().unwrap();
    assert!(external > ours);

    let err = lease.update(&iface_config(1, "8.8.8.8")).unwrap_err();
    assert!(err.is_external_modification(), "{err:?}");
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), Some(external));
    assert_eq!(
        journal_record_json(&fixture.dir)["applied"]["data"]["generation"],
        serde_json::json!(ours)
    );

    let failure = lease.restore().unwrap_err();
    assert!(
        failure.error.is_external_modification(),
        "{:?}",
        failure.error
    );
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), Some(external));
    failure.lease.abandon().unwrap();
}

#[test]
fn mutation_proof_is_not_replaced_by_equivalent_readback() {
    let fixture = new_fixture("race-readback-identity");
    fixture
        .fake
        .inject_external_after_guarded_mutation(IFACE1, state_with("1.1.1.1"))
        .unwrap();
    let err = fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap_err();
    assert!(err.is_external_modification(), "{err:?}");
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    if journal_files(&fixture.dir).is_empty() {
        return;
    }
    let record = journal_record_json(&fixture.dir);
    assert!(
        record["applied"].is_null()
            || record["applied"]["data"]["generation"]
                != serde_json::json!(fixture.fake.generation(IFACE1).unwrap().unwrap())
    );
    fixture
        .manager
        .abandon_journal(&resource_id(IFACE1))
        .unwrap();
}

#[test]
fn same_dns_rewrite_blocks_rollback_of_earlier_resource() {
    let fixture = new_multi_fixture("race-rollback-same-dns");
    let lease = fixture
        .manager
        .apply(&routing_config(&["corp.example"]))
        .unwrap();
    fixture
        .fake
        .inject_external_before_nth_guarded(1, IFACE1, state_with("8.8.8.8"))
        .unwrap();
    fixture.fake.inject_backend_failure_after(
        osdns::testing::FakeOp::Apply,
        1,
        1,
        "later resource apply failed",
    );
    let updated = osdns::DnsConfig::builder(iface_scope(1))
        .nameserver(ip("8.8.8.8"))
        .routing_domain("corp.example")
        .build()
        .unwrap();
    let err = lease.update(&updated).unwrap_err();
    assert!(
        matches!(err, Error::Platform { .. }) || err.is_external_modification(),
        "{err:?}"
    );
    let generation = fixture.fake.generation(IFACE1).unwrap().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("8.8.8.8"))
    );
    let retry = lease.update(&updated);
    assert!(retry.is_err(), "{retry:?}");
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), Some(generation));
    lease.abandon().unwrap();
}
