//! Enforce-policy reconciliation tests: external base changes are rebased
//! and the desired overlay reapplied; restore then returns to the external
//! base. Cooperative policy must keep the old conflict behavior.

#![cfg(feature = "test-util")]

use std::time::{Duration, Instant};

mod common;

use common::*;
use osdns::ConflictPolicy;
use osdns::testing::{FakeDns, manager_for_testing_with_policy};

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

#[test]
fn enforce_rebases_and_reapplies_on_external_change() {
    let fixture = enforce_manager("enforce-rebase");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();

    let _watch = fixture.manager.watch(std::sync::Arc::new(|_| {})).unwrap();

    std::thread::sleep(Duration::from_millis(600));
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if fixture.fake.current_state(IFACE1).unwrap() == Some(state_with("1.1.1.1")) {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1")),
        "the overlay must be reapplied over the external change"
    );

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "restore must return to the rebased external base, not the pre-lease state"
    );
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
