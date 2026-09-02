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

#[rstest]
#[case(TxPoint::AfterPrepared)]
#[case(TxPoint::AfterApply)]
#[case(TxPoint::AfterReadback)]
#[case(TxPoint::AfterVerify)]
fn crash_at_every_mutation_phase_leaves_recoverable_state(#[case] point: TxPoint) {
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
    assert!(journal_files(&fixture.dir).is_empty(), "{outcomes:?}");
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty),
        "after recovery the system must be back at the captured base"
    );
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
