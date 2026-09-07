//! Journal durability and fail-closed parsing.
#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::Error;
use osdns::testing::{FaultInjector, TxPoint};
use serde_json::json;

#[test]
fn prepared_record_persisted_before_mutation() {
    let fixture = new_fixture("journal-prepared");
    let injector = FaultInjector::new();
    injector.crash_at(TxPoint::AfterPrepared);
    fixture.manager.install_fault_injector(injector.clone());

    let outcome =
        osdns::testing::catch_crash(|| fixture.manager.apply(&iface_config(1, "1.1.1.1")));
    assert!(matches!(outcome, osdns::testing::CrashOutcome::Crashed));
    injector.clear();

    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["schema_version"], 3);
    assert_eq!(record["owner"], "io.osdns.test");
    assert_eq!(record["resource"], IFACE1);
    assert_eq!(record["backend"], "fake");
    assert_eq!(record["identity"]["resource"], IFACE1);
    assert_eq!(record["phase"], "Prepared");
    assert!(record["applied"].is_null());
    assert_eq!(record["desired"]["nameservers"][0], "1.1.1.1");
}

#[test]
fn applied_record_persisted_after_verification() {
    let fixture = new_fixture("journal-applied");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Applied");
    assert_eq!(
        record["applied"]["data"]["state"]["Configured"]["nameservers"][0],
        "1.1.1.1"
    );
    lease.restore().unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn corrupt_record_fails_closed() {
    let fixture = new_fixture("journal-corrupt");
    std::fs::write(
        fixture.dir.join("journal").join("bogus.json"),
        b"{ this is not json",
    )
    .unwrap();

    let err = fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap_err();
    assert!(matches!(err, Error::JournalCorrupt(_)));

    let err = fixture.manager.recover_stale().unwrap_err();
    assert!(matches!(err, Error::JournalCorrupt(_)));

    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}

#[test]
fn unknown_schema_fails_closed() {
    let fixture = new_fixture("journal-schema");
    let record = json!({
        "schema_version": 99,
        "owner": "someone.else",
        "lease_id": "11111111-2222-3333-4444-555555555555",
        "resource": IFACE1,
        "backend": "fake",
        "phase": "Prepared",
        "before": { "backend": "fake", "resource": IFACE1, "data": {} },
        "desired": { "nameservers": ["1.1.1.1"], "search_domains": [], "routing_domains": [], "default_route": null },
        "applied": null
    });
    std::fs::write(
        fixture.dir.join("journal").join("future-schema.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();

    let err = fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap_err();
    assert!(matches!(
        err,
        Error::UnsupportedJournalVersion {
            found: 99,
            supported: 3,
            ..
        }
    ));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty),
        "unknown journal schema must not be guessed at"
    );
}

#[test]
fn published_schema_1_reports_an_intentional_incompatible_upgrade() {
    let fixture = new_fixture("journal-schema-1");
    std::fs::write(
        fixture.dir.join("journal").join("published-v1.json"),
        include_bytes!("fixtures/journal-schema-1.json"),
    )
    .unwrap();

    let error = fixture.manager.recover_stale().unwrap_err();
    assert!(matches!(
        error,
        Error::UnsupportedJournalVersion {
            found: 1,
            supported: 3,
            ..
        }
    ));
    let error = fixture.manager.recover_stale().unwrap_err();
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("unsupported journal schema version 1"));
    assert!(diagnostic.contains("clear or reset"));
    assert!(!diagnostic.contains("missing field `identity`"));
}

#[test]
fn unknown_phase_fails_closed() {
    let fixture = new_fixture("journal-phase");
    let record = json!({
        "schema_version": 3,
        "owner": "someone.else",
        "lease_id": "11111111-2222-3333-4444-555555555555",
        "resource": IFACE1,
        "backend": "fake",
        "identity": {
            "backend": "fake",
            "resource": IFACE1,
            "data": { "incarnation": 1 }
        },
        "phase": "HalfDone",
        "before": { "backend": "fake", "resource": IFACE1, "data": {} },
        "desired": { "nameservers": ["1.1.1.1"], "search_domains": [], "routing_domains": [], "default_route": null },
        "applied": null
    });
    std::fs::write(
        fixture.dir.join("journal").join("weird-phase.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();

    let err = fixture.manager.recover_stale().unwrap_err();
    assert!(matches!(err, Error::JournalCorrupt(_)));
}

#[test]
fn cross_backend_and_cross_resource_records_fail_closed() {
    let fixture = new_fixture("journal-cross-field");
    fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap()
        .debug_release_locks_keep_journal();
    let file = journal_files(&fixture.dir).pop().unwrap();
    let path = fixture.dir.join("journal").join(file);
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["before"]["resource"] = serde_json::Value::String(IFACE2.to_string());
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

    assert!(matches!(
        fixture.manager.recover_stale(),
        Err(Error::JournalCorrupt(_))
    ));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
}

#[test]
fn malformed_backend_identity_cannot_trigger_destructive_recovery() {
    let fixture = new_fixture("journal-invalid-identity");
    fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap()
        .debug_release_locks_keep_journal();
    let file = journal_files(&fixture.dir).pop().unwrap();
    let path = fixture.dir.join("journal").join(file);
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["identity"]["data"] = json!({ "incarnation": "not-a-number" });
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert!(matches!(
        &outcomes[..],
        [osdns::RecoveryOutcome::Failed { .. }]
    ));
    assert_eq!(journal_files(&fixture.dir).len(), 1);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
}
