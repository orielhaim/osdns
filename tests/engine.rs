//! Transaction engine behavior: apply, update, restore, watch.
#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::WatchHandle;
use osdns::testing::{FakeOp, FakeState};
use osdns::{DnsConfig, Error, RecoveryOutcome};
use std::sync::{Arc, Mutex};

fn config(index: u32, ns: &str) -> DnsConfig {
    iface_config(index, ns)
}

#[test]
fn apply_snapshot_restore_roundtrip() {
    let fixture = new_fixture("engine-roundtrip");
    let lease = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap();
    assert!(!lease.is_noop());
    assert_eq!(lease.resources(), &[resource_id(IFACE1)]);

    let snapshot = fixture.manager.snapshot(&iface_scope(1)).unwrap();
    assert_eq!(snapshot.nameservers(), &[ip("1.1.1.1")]);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty)
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn global_scope_works() {
    let fixture = new_fixture("engine-global");
    let config = DnsConfig::builder(osdns::DnsScope::Global)
        .nameserver(ip("127.0.0.1"))
        .build()
        .unwrap();
    let lease = fixture.manager.apply(&config).unwrap();
    assert_eq!(
        fixture.fake.current_state(GLOBAL).unwrap(),
        Some(state_with("127.0.0.1"))
    );
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(GLOBAL).unwrap(),
        Some(FakeState::Empty)
    );
}

#[test]
fn semantic_noop_apply_owns_nothing() {
    let fixture = new_fixture("engine-noop");
    fixture
        .fake
        .external_change(IFACE1, state_with("1.1.1.1"))
        .unwrap();

    let lease = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap();
    assert!(lease.is_noop());
    assert!(lease.lease_id().is_none());
    assert!(journal_files(&fixture.dir).is_empty());

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1")),
        "no-op lease restore must not change anything"
    );
}

#[test]
fn update_keeps_original_before_state() {
    let fixture = new_fixture("engine-update");
    let lease = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap();
    lease.update(&config(1, "8.8.8.8")).unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("8.8.8.8"))
    );

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty),
        "restore must return to the pre-lease state, not the last update"
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn update_back_to_original_state_still_restores_cleanly() {
    let fixture = new_fixture("engine-update-back");
    let lease = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap();
    let empty = DnsConfig::builder(iface_scope(1)).build().unwrap();
    lease.update(&empty).unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty)
    );

    lease.restore().unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn update_rejects_scope_change() {
    let fixture = new_fixture("engine-update-scope");
    let lease = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap();
    let other = DnsConfig::builder(iface_scope(2))
        .nameserver(ip("1.1.1.1"))
        .build()
        .unwrap();
    let err = lease.update(&other).unwrap_err();
    match err {
        Error::UpdateRequiresRebind { owned, requested } => {
            assert_eq!(owned, vec![resource_id(IFACE1)]);
            assert_eq!(requested, vec![resource_id(IFACE2)]);
        }
        other => panic!("expected UpdateRequiresRebind, got {other:?}"),
    }
    lease.restore().unwrap();
}

#[test]
fn update_detects_external_modification() {
    let fixture = new_fixture("engine-update-external");
    let lease = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();

    let err = lease.update(&config(1, "8.8.8.8")).unwrap_err();
    assert!(err.is_external_modification());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "external change must survive"
    );

    let failure = lease.restore().unwrap_err();
    assert!(failure.error.is_external_modification());
    let lease = failure.lease;

    assert_eq!(journal_files(&fixture.dir).len(), 1);
    lease.abandon().unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "abandon must not mutate the system"
    );
}

#[test]
fn restore_is_noop_when_external_reverted_to_before() {
    let fixture = new_fixture("engine-reverted");
    let lease = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap();
    fixture
        .fake
        .external_change(IFACE1, FakeState::Empty)
        .unwrap();

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty)
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn drop_restores_best_effort() {
    let fixture = new_fixture("engine-drop-clean");
    {
        let _lease = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap();
    }
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty)
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn drop_keeps_journal_on_external_modification() {
    let fixture = new_fixture("engine-drop-conflict");
    {
        let _lease = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap();
        fixture
            .fake
            .external_change(IFACE1, state_with("9.9.9.9"))
            .unwrap();
    }
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "best-effort drop restore must not overwrite external changes"
    );
    assert_eq!(journal_files(&fixture.dir).len(), 1);

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 1);
    assert!(
        matches!(&outcomes[0], RecoveryOutcome::ExternalConflict { resource, .. } if resource == &resource_id(IFACE1)),
        "unexpected outcome: {:?}",
        outcomes[0]
    );

    fixture
        .manager
        .abandon_journal(&resource_id(IFACE1))
        .unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn backend_failure_rolls_back_and_removes_journal() {
    let fixture = new_fixture("engine-apply-fail");
    fixture
        .fake
        .inject_backend_failure(FakeOp::Apply, 1, "simulated OS rejection");
    let err = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap_err();
    assert!(matches!(err, Error::Platform { .. }));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty)
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn readback_failure_rolls_back_to_before() {
    let fixture = new_fixture("engine-readback-fail");
    fixture
        .fake
        .inject_backend_failure(FakeOp::Readback, 1, "read-back unavailable");
    let err = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap_err();
    assert!(matches!(err, Error::Platform { .. }));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty),
        "rollback must have restored the original state"
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn lying_readback_fails_verification_and_rolls_back() {
    let fixture = new_fixture("engine-verify-fail");
    fixture
        .fake
        .lie_once_on_readback(state_with("203.0.113.99"));
    let err = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap_err();
    assert!(matches!(err, Error::VerificationFailed { .. }));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty),
        "rollback after verification failure must restore the original state"
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn watch_delivers_events_until_stopped() {
    let fixture = new_fixture("engine-watch");
    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let handle: WatchHandle = fixture
        .manager
        .watch(Arc::new(move |event| {
            let name = match event {
                osdns::DnsEvent::ResourceChanged { resource } => {
                    format!("changed:{resource}")
                }
                osdns::DnsEvent::ResourceRemoved { resource } => {
                    format!("removed:{resource}")
                }
                _ => "other".to_string(),
            };
            sink.lock().unwrap().push(name);
        }))
        .unwrap();

    let _lease = fixture.manager.apply(&config(1, "1.1.1.1")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(600));
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    wait_for(&events, &format!("changed:{IFACE1}"));

    handle.stop();
    fixture
        .fake
        .external_change(IFACE1, state_with("8.8.8.8"))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(150));
    let count = events.lock().unwrap().len();
    fixture
        .fake
        .external_change(IFACE1, state_with("7.7.7.7"))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(events.lock().unwrap().len(), count, "no events after stop");
}

fn wait_for(events: &Arc<Mutex<Vec<String>>>, expected: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if events.lock().unwrap().iter().any(|e| e == expected) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("event {expected:?} was not delivered in time");
}

#[test]
fn removed_interface_is_reported() {
    let fixture = new_fixture("engine-remove");
    assert!(fixture.fake.external_remove(IFACE2).unwrap());
    let missing = fixture.manager.snapshot(&iface_scope(2)).unwrap_err();
    assert!(matches!(missing, Error::InvalidConfig(_)));
}
