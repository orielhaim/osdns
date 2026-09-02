//! Multi-resource lease tests: a single lease spanning a service resource
//! plus one resolver resource per routing domain, mirroring the macOS backend
//! shape, driven through the fake backend.

#![cfg(feature = "test-util")]

use rstest::rstest;

mod common;

use common::*;
use osdns::testing::{CrashOutcome, FaultInjector, TxPoint};
use osdns::{DnsConfig, Error, RecoveryOutcome};

fn resolver_id(domain: &str) -> osdns::ResourceId {
    format!("fake:resolver:{domain}").parse().unwrap()
}

#[rstest]
#[case(1)]
#[case(3)]
fn apply_spans_service_and_resolver_resources(#[case] domain_count: usize) {
    let domains: Vec<String> = (0..domain_count).map(|i| format!("d{i}.example")).collect();
    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let fixture = new_multi_fixture("multi-apply");
    let lease = fixture
        .manager
        .apply(&routing_config(&domain_refs))
        .unwrap();
    assert!(!lease.is_noop());

    let resources = lease.resources();
    assert_eq!(resources.len(), 1 + domain_count);
    assert_eq!(resources[0], resource_id(IFACE1));
    for (index, domain) in domains.iter().enumerate() {
        assert_eq!(resources[1 + index], resolver_id(domain));
    }
    assert_eq!(journal_files(&fixture.dir).len(), 1 + domain_count);

    lease.restore().unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn restore_is_per_resource_on_external_modification() {
    let fixture = new_multi_fixture("multi-external");
    let lease = fixture
        .manager
        .apply(&routing_config(&["corp.example"]))
        .unwrap();

    fixture
        .fake
        .external_change("fake:resolver:corp.example", state_with("9.9.9.9"))
        .unwrap();

    let failure = lease.restore().unwrap_err();
    assert!(failure.error.is_external_modification());
    let lease = failure.lease;

    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty),
        "the untouched resource must still be restored"
    );
    assert_eq!(
        fixture
            .fake
            .current_state("fake:resolver:corp.example")
            .unwrap(),
        Some(state_with("9.9.9.9")),
        "the externally modified resource must win"
    );

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 1);
    assert!(
        matches!(&outcomes[0], RecoveryOutcome::Busy { resource } if *resource == resolver_id("corp.example")),
        "the still-live lease holds the lock, so recovery must skip the resource: {outcomes:?}"
    );

    lease.abandon().unwrap();
    assert!(fixture.manager.recover_stale().unwrap().is_empty());
}

#[rstest]
#[case(TxPoint::AfterPrepared)]
#[case(TxPoint::AfterApply)]
#[case(TxPoint::AfterApplied)]
fn crash_between_resources_recovers_every_resource(#[case] point: TxPoint) {
    let fixture = new_multi_fixture("multi-crash");
    let injector = FaultInjector::new();
    injector.crash_at(point);
    fixture.manager.install_fault_injector(injector.clone());

    let outcome = osdns::testing::catch_crash(|| {
        fixture
            .manager
            .apply(&routing_config(&["corp.example", "vpn.example"]))
    });
    injector.clear();
    assert!(matches!(outcome, CrashOutcome::Crashed));
    assert_eq!(journal_files(&fixture.dir).len(), 3);

    let outcomes = fixture.manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 3, "unexpected outcomes: {outcomes:?}");
    let restored = outcomes
        .iter()
        .filter(|o| matches!(o, RecoveryOutcome::Restored { .. }))
        .count();
    let cleared = outcomes
        .iter()
        .filter(|o| matches!(o, RecoveryOutcome::JournalCleared { .. }))
        .count();
    match point {
        TxPoint::AfterPrepared => {
            assert_eq!((restored, cleared), (0, 3), "{outcomes:?}")
        }
        TxPoint::AfterApply => {
            assert_eq!((restored, cleared), (1, 2), "{outcomes:?}")
        }
        TxPoint::AfterApplied => {
            assert_eq!((restored, cleared), (3, 0), "{outcomes:?}")
        }
        _ => unreachable!("apply crash phase"),
    }
    assert!(journal_files(&fixture.dir).is_empty());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}

#[test]
fn partial_apply_failure_rolls_back_completed_resources() {
    let fixture = new_multi_fixture("multi-partial");
    let lease = fixture
        .manager
        .apply(&routing_config(&["corp.example"]))
        .unwrap();
    lease.restore().unwrap();

    let injector = FaultInjector::new();
    injector.fail_at(TxPoint::AfterApply, "second resource exploded");
    fixture.manager.install_fault_injector(injector.clone());

    let error = fixture
        .manager
        .apply(&routing_config(&["corp.example", "vpn.example"]))
        .unwrap_err();
    injector.clear();
    assert!(matches!(error, Error::Platform { .. }));
    assert!(
        journal_files(&fixture.dir).is_empty(),
        "rolled-back transactions must not keep journals"
    );
}

#[test]
fn update_touches_every_resource() {
    let fixture = new_multi_fixture("multi-update");
    let lease = fixture
        .manager
        .apply(&routing_config(&["corp.example"]))
        .unwrap();

    let updated = DnsConfig::builder(iface_scope(1))
        .nameserver(ip("8.8.8.8"))
        .routing_domain("corp.example")
        .build()
        .unwrap();
    lease.update(&updated).unwrap();

    for resource in lease.resources() {
        let state = fixture.fake.current_state(resource.as_str()).unwrap();
        let osdns::testing::FakeState::Configured { nameservers, .. } = state.unwrap() else {
            panic!("resource {resource} has no configured state");
        };
        assert_eq!(nameservers, vec![ip("8.8.8.8")]);
    }

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}
