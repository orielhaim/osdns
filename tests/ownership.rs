//! Resource locking and ownership exclusivity.
#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::testing::manager_for_testing;
use osdns::{ConflictReason, Error};
use std::time::Duration;

#[test]
fn lease_excludes_same_resource_in_process() {
    let fixture = new_fixture("locks-leased");
    let first = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();

    let err = fixture
        .manager
        .apply(&iface_config(1, "8.8.8.8"))
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Conflict {
            reason: ConflictReason::AlreadyLeasedInProcess,
            ..
        }
    ));

    first.restore().unwrap();
    let second = fixture.manager.apply(&iface_config(1, "8.8.8.8"));
    assert!(second.is_ok());
    second.unwrap().restore().unwrap();
}

#[test]
fn different_resources_are_independent() {
    let fixture = new_fixture("locks-parallel");
    let lease1 = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let lease2 = fixture.manager.apply(&iface_config(2, "8.8.8.8")).unwrap();
    lease1.restore().unwrap();
    lease2.restore().unwrap();
}

#[test]
fn second_manager_on_same_state_dir_conflicts() {
    let dir = temp_dir("locks-two-managers");
    let fake = osdns::testing::FakeDns::new();
    let manager_a =
        manager_for_testing("io.osdns.a", &dir, &fake, Duration::from_secs(30)).unwrap();
    let manager_b =
        manager_for_testing("io.osdns.b", &dir, &fake, Duration::from_millis(120)).unwrap();

    let lease = manager_a.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let err = manager_b.apply(&iface_config(1, "8.8.8.8")).unwrap_err();
    assert!(
        matches!(err, Error::Conflict { .. } | Error::Timeout { .. }),
        "unexpected error: {err:?}"
    );
    drop(lease);
    drop(manager_a);

    manager_b
        .apply(&iface_config(1, "8.8.8.8"))
        .unwrap()
        .restore()
        .unwrap();
}

#[test]
fn recover_stale_reports_busy_for_leased_resource() {
    let fixture = new_fixture("locks-busy");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let outcomes = fixture.manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0],
        osdns::RecoveryOutcome::Busy {
            resource: resource_id(IFACE1)
        }
    );
    lease.restore().unwrap();
    assert!(fixture.manager.recover_stale().unwrap().is_empty());
}

#[test]
fn resource_ids_validate() {
    assert!(
        "linux:resolved:ifindex:7"
            .parse::<osdns::ResourceId>()
            .is_ok()
    );
    assert!(
        "windows:interface:6f4a1b2c"
            .parse::<osdns::ResourceId>()
            .is_ok()
    );
    assert!("".parse::<osdns::ResourceId>().is_err());
    assert!("UPPER:case".parse::<osdns::ResourceId>().is_err());
    assert!("double::colon".parse::<osdns::ResourceId>().is_err());
    assert!("space jam".parse::<osdns::ResourceId>().is_err());
    assert!("trailing:".parse::<osdns::ResourceId>().is_err());
}
