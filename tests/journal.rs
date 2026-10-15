//! Journal durability and fail-closed parsing.
#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::Error;
use osdns::testing::{FaultInjector, TxPoint};
use rstest::rstest;
use serde_json::json;

#[rstest]
#[case("filename")]
#[case("applied_missing")]
#[case("invalid_owner")]
#[case("duplicate")]
fn inconsistent_record_claims_fail_before_native_mutation(#[case] corruption: &str) {
    let fixture = new_fixture("journal-claims");
    fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap()
        .debug_release_locks_keep_journal();
    let path = fixture
        .dir
        .join("journal")
        .join(journal_files(&fixture.dir).pop().unwrap());
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    match corruption {
        "filename" => std::fs::rename(&path, path.with_file_name("wrong.json")).unwrap(),
        "applied_missing" => {
            record["applied"] = json!(null);
            write_journal(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        }
        "invalid_owner" => {
            record["owner"] = json!("invalid owner");
            write_journal(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        }
        "duplicate" => {
            write_journal(
                path.with_file_name("duplicate.json"),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        }
        _ => unreachable!(),
    }
    assert!(matches!(
        fixture.manager.recover_stale(),
        Err(Error::JournalCorrupt(_))
    ));
    assert!(matches!(
        fixture.manager.apply(&iface_config(2, "8.8.8.8")),
        Err(Error::JournalCorrupt(_))
    ));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    assert_eq!(
        fixture.fake.current_state(IFACE2).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}

#[test]
fn oversized_record_is_rejected_before_parsing_or_mutation() {
    let fixture = new_fixture("journal-large");
    write_journal(
        fixture.dir.join("journal/large.json"),
        vec![b' '; 16 * 1024 * 1024 + 1],
    )
    .unwrap();
    assert!(matches!(
        fixture.manager.recover_stale(),
        Err(Error::JournalCorrupt(_))
    ));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}

#[test]
fn another_application_owner_cannot_recover_or_abandon_a_journal() {
    let fixture = new_fixture("journal-owner");
    fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap()
        .debug_release_locks_keep_journal();
    let other = manager_for_testing(
        "io.other",
        &fixture.dir,
        &fixture.fake,
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    assert!(matches!(
        other.recover_stale().unwrap().as_slice(),
        [osdns::RecoveryOutcome::ForeignOwner { .. }]
    ));
    assert!(matches!(
        other.abandon_journal(&resource_id(IFACE1)),
        Err(Error::Conflict { .. })
    ));
    assert!(matches!(
        other.apply(&iface_config(1, "8.8.8.8")),
        Err(Error::Conflict { .. })
    ));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    fixture.manager.recover_stale().unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
}

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
    assert_eq!(record["schema_version"], 4);
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
    write_journal(
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
    write_journal(
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
            supported: 4,
            ..
        }
    ));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty),
        "unknown journal schema must not be guessed at"
    );
}

#[rstest]
#[case(1, include_bytes!("fixtures/journal-schema-1.json").as_slice())]
#[case(3, include_bytes!("fixtures/journal-openresolv-0.2-applied.json").as_slice())]
fn incompatible_published_schemas_are_retained_without_mutation(
    #[case] version: u32,
    #[case] bytes: &[u8],
) {
    let fixture = new_fixture("journal-upgrade");
    let path = fixture.dir.join("journal").join("incompatible.json");
    write_journal(&path, bytes).unwrap();
    assert!(
        matches!(fixture.manager.recover_stale(), Err(Error::UnsupportedJournalVersion { found, supported: 4, .. }) if found == version)
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn unknown_phase_fails_closed() {
    let fixture = new_fixture("journal-phase");
    let record = json!({
        "schema_version": 4,
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
    write_journal(
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
    write_journal(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

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
    write_journal(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

    assert!(matches!(
        fixture.manager.recover_stale(),
        Err(Error::JournalCorrupt(_))
    ));
    assert_eq!(journal_files(&fixture.dir).len(), 1);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
}

#[test]
fn journal_transactions_remain_bound_to_the_acquired_directory() {
    let fixture = new_fixture("journal-capability");
    let journal = fixture.dir.join("journal");
    let retained = fixture.dir.join("retained-journal");
    std::fs::rename(&journal, &retained).unwrap();
    private_fs::PrivateDir::ensure(&journal).unwrap();
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    assert_eq!(
        std::fs::read_dir(&retained)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            .count(),
        1
    );
    assert_eq!(std::fs::read_dir(&journal).unwrap().count(), 0);
    lease.restore().unwrap();
    assert_eq!(std::fs::read_dir(&retained).unwrap().count(), 0);
}

#[cfg(unix)]
#[rstest]
#[case(false)]
#[case(true)]
fn insufficiently_private_existing_state_is_retained_without_repair(#[case] directory: bool) {
    use std::os::unix::fs::PermissionsExt;
    let fixture = new_fixture("journal-old-permissions");
    fixture
        .manager
        .apply(&iface_config(1, "1.1.1.1"))
        .unwrap()
        .debug_release_locks_keep_journal();
    let record = fixture
        .dir
        .join("journal")
        .join(journal_files(&fixture.dir).pop().unwrap());
    let bytes = std::fs::read(&record).unwrap();
    let target = if directory {
        fixture.dir.join("journal")
    } else {
        record.clone()
    };
    let mode = if directory { 0o755 } else { 0o644 };
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
    assert!(matches!(
        fixture.manager.recover_stale(),
        Err(Error::UnsafeFilesystem(_))
    ));
    assert_eq!(std::fs::read(&record).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        mode
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
}

#[test]
fn possibly_published_preparation_is_cleaned_without_dns_mutation() {
    let fixture = new_fixture("journal-uncertain-publish");
    fixture.manager.set_journal_fail_after_io(true);
    assert!(matches!(fixture.manager.apply(&iface_config(1, "1.1.1.1")),
        Err(Error::TransactionFailed { primary, .. }) if matches!(*primary, Error::JournalPublication { may_have_published: true, .. })));
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
    fixture.manager.set_journal_fail_after_io(false);
    assert!(fixture.manager.recover_stale().unwrap().is_empty());
}

#[rstest]
#[case(false)]
#[case(true)]
fn possibly_removed_journal_keeps_teardown_retryable(#[case] abandon: bool) {
    let fixture = new_fixture("journal-uncertain-remove");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.set_journal_fail_after_io(true);
    let failure = if abandon {
        lease.abandon()
    } else {
        lease.restore()
    }
    .unwrap_err();
    assert!(matches!(
        failure.error,
        Error::JournalRemoval {
            may_have_removed: true,
            ..
        }
    ));
    assert!(journal_files(&fixture.dir).is_empty());
    let failure = if abandon {
        failure.lease.abandon()
    } else {
        failure.lease.restore()
    }
    .unwrap_err();
    assert!(matches!(
        failure.error,
        Error::JournalRemoval {
            may_have_removed: true,
            ..
        }
    ));
    fixture.manager.set_journal_fail_after_io(false);
    if abandon {
        failure.lease.abandon().unwrap();
    } else {
        failure.lease.restore().unwrap();
    }
    assert!(journal_files(&fixture.dir).is_empty());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(if abandon {
            state_with("1.1.1.1")
        } else {
            osdns::testing::FakeState::Empty
        })
    );
    assert_eq!(
        std::fs::read_dir(fixture.dir.join("journal"))
            .unwrap()
            .count(),
        0
    );
}
