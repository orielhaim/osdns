//! Semantic contract tests: every explicitly requested semantic is either
//! faithfully represented or rejected before mutation; `None` preserves.
//!
//! Covers `default_route` preservation, the `default_route` capability,
//! `UpdateRequiresRebind`, transactional multi-resource updates with fault
//! injection at every resource position, and the NetworkManager root-domain
//! contract (via the shared text-config helpers exercised in unit tests).

#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::testing::{FakeOp, FakeState};
use osdns::{BackendKind, Capabilities, DnsConfig, DnsScope, Error, InterfaceSelector};

fn scope1() -> DnsScope {
    DnsScope::Interface(InterfaceSelector::Index(1))
}

fn config_with_default(ns: &str, default_route: Option<bool>) -> DnsConfig {
    let mut builder = DnsConfig::builder(scope1()).nameserver(ip(ns));
    if let Some(enabled) = default_route {
        builder = builder.default_route(enabled);
    }
    builder.build().unwrap()
}

fn fake_state(ns: &str, default_route: Option<bool>) -> FakeState {
    FakeState::Configured {
        nameservers: vec![ip(ns)],
        search_domains: vec![],
        routing_domains: vec![],
        default_route,
    }
}

// ---- 1. default_route = None preserves; Some sets ----

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn unspecified_default_route_preserves_current_value(#[case] enabled: bool) {
    let fixture = new_fixture("sem-dr-preserve");
    fixture
        .fake
        .external_change(IFACE1, fake_state("9.9.9.9", Some(enabled)))
        .unwrap();
    let lease = fixture
        .manager
        .apply(&config_with_default("1.1.1.1", None))
        .unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(fake_state("1.1.1.1", Some(enabled)))
    );
    lease.update(&config_with_default("8.8.8.8", None)).unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(fake_state("8.8.8.8", Some(enabled)))
    );
    lease.update(&config_with_default("8.8.8.8", None)).unwrap();
    assert_eq!(
        fixture.manager.snapshot(&scope1()).unwrap().default_route(),
        Some(enabled)
    );
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(fake_state("9.9.9.9", Some(enabled)))
    );
}

#[test]
fn explicit_default_route_sets_value() {
    let fixture = new_fixture("sem-dr-explicit");
    let lease = fixture
        .manager
        .apply(&config_with_default("1.1.1.1", Some(false)))
        .unwrap();
    lease
        .update(&config_with_default("1.1.1.1", Some(true)))
        .unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(fake_state("1.1.1.1", Some(true)))
    );
    lease
        .update(&config_with_default("1.1.1.1", Some(false)))
        .unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(fake_state("1.1.1.1", Some(false)))
    );
    lease.restore().unwrap();
}

// ---- 2. capability matrix: unsupported fails before mutation ----

#[test]
fn unsupported_default_route_fails_before_mutation() {
    let dir = temp_dir("sem-unsupported-dr");
    let fake = osdns::testing::FakeDns::with_capabilities(
        Capabilities::new(BackendKind::Fake)
            .with_read(true)
            .with_global_dns(true)
            .with_per_interface_dns(true)
            .with_search_domains(true)
            .with_split_dns(true)
            .with_watch(true)
            .with_cache_flush(true),
    );
    let manager = osdns::testing::manager_for_testing(
        "io.osdns.test",
        &dir,
        &fake,
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    let config = config_with_default("1.1.1.1", Some(true));
    let err = manager.validate(&config).unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
    let err = manager.apply(&config).unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
    assert_eq!(
        fake.current_state(IFACE1).unwrap(),
        Some(FakeState::Empty),
        "rejected validation must mutate nothing"
    );
    // None still passes without the capability.
    manager
        .validate(&config_with_default("1.1.1.1", None))
        .unwrap();
}

#[test]
fn unsupported_split_dns_fails_before_mutation() {
    let dir = temp_dir("sem-unsupported-split");
    let caps = Capabilities::new(BackendKind::Fake)
        .with_read(true)
        .with_global_dns(true)
        .with_per_interface_dns(true)
        .with_search_domains(true)
        .with_split_dns(false)
        .with_default_route(true)
        .with_watch(true)
        .with_cache_flush(true);
    let fake = osdns::testing::FakeDns::with_capabilities(caps);
    let manager = osdns::testing::manager_for_testing(
        "io.osdns.test",
        &dir,
        &fake,
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    let config = DnsConfig::builder(scope1())
        .nameserver(ip("1.1.1.1"))
        .routing_domain("corp.example")
        .build()
        .unwrap();
    assert!(matches!(
        manager.validate(&config).unwrap_err(),
        Error::Unsupported { .. }
    ));
    assert!(matches!(
        manager.apply(&config).unwrap_err(),
        Error::Unsupported { .. }
    ));
    assert_eq!(fake.current_state(IFACE1).unwrap(), Some(FakeState::Empty));
}

#[test]
fn supported_semantics_validate_and_match_exactly() {
    let fixture = new_fixture("sem-supported");
    let config = DnsConfig::builder(scope1())
        .nameserver(ip("1.1.1.1"))
        .search_domain("example.com")
        .routing_domain("corp.example")
        .default_route(true)
        .build()
        .unwrap();
    fixture.manager.validate(&config).unwrap();
    let lease = fixture.manager.apply(&config).unwrap();
    let snapshot = fixture.manager.snapshot(&scope1()).unwrap();
    assert_eq!(snapshot.nameservers(), config.nameservers());
    assert_eq!(snapshot.search_domains(), config.search_domains());
    assert_eq!(snapshot.routing_domains(), config.routing_domains());
    assert_eq!(snapshot.default_route(), config.default_route());
    lease.restore().unwrap();
}

// ---- 5. typed rebind error ----

#[test]
fn update_to_different_resource_set_requires_rebind() {
    let fixture = new_multi_fixture("sem-rebind");
    let lease = fixture
        .manager
        .apply(&routing_config(&["a.example"]))
        .unwrap();
    let before: Vec<_> = lease
        .resources()
        .iter()
        .map(|r| r.as_str().to_string())
        .collect();
    let expanded = routing_config(&["a.example", "b.example"]);
    let err = lease.update(&expanded).unwrap_err();
    match &err {
        Error::UpdateRequiresRebind { owned, requested } => {
            assert_eq!(owned.len(), 2);
            assert_eq!(requested.len(), 3);
        }
        other => panic!("expected UpdateRequiresRebind, got {other:?}"),
    }
    // Nothing was mutated and the lease is still usable.
    assert_eq!(
        lease
            .resources()
            .iter()
            .map(|r| r.as_str().to_string())
            .collect::<Vec<_>>(),
        before
    );
    assert_eq!(journal_files(&fixture.dir).len(), 2);
    lease.restore().unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
}

// ---- 4. transactional multi-resource update, fault at every position ----

fn three_resource_lease() -> (Fixture, osdns::Lease) {
    let fixture = new_multi_fixture("sem-tx-update");
    let lease = fixture
        .manager
        .apply(&routing_config(&["a.example", "b.example"]))
        .unwrap();
    assert_eq!(lease.resources().len(), 3);
    (fixture, lease)
}

fn updated_three(ns: &str) -> DnsConfig {
    let mut builder = DnsConfig::builder(iface_scope(1)).nameserver(ip(ns));
    for domain in ["a.example", "b.example"] {
        builder = builder.routing_domain(domain);
    }
    builder.build().unwrap()
}

fn configured_nameservers(state: Option<FakeState>) -> Vec<std::net::IpAddr> {
    match state.unwrap() {
        FakeState::Configured { nameservers, .. } => nameservers,
        FakeState::Empty => vec![],
    }
}

#[rstest::rstest]
#[case::first_mutation(FakeOp::Apply, 0)]
#[case::second_mutation(FakeOp::Apply, 1)]
#[case::third_mutation(FakeOp::Apply, 2)]
#[case::mutation_readback(FakeOp::Readback, 3)]
fn update_failure_restores_previous_state_and_keeps_lease_usable(
    #[case] operation: FakeOp,
    #[case] skip: u32,
) {
    let (fixture, lease) = three_resource_lease();
    fixture
        .fake
        .inject_backend_failure_after(operation, skip, 1, "update failure");
    let err = lease.update(&updated_three("8.8.8.8")).unwrap_err();
    assert!(matches!(err, Error::Platform { .. }), "{err:?}");
    for resource in lease.resources() {
        assert_eq!(
            configured_nameservers(fixture.fake.current_state(resource.as_str()).unwrap()),
            vec![ip("1.1.1.1")],
            "resource {resource}"
        );
    }
    assert_eq!(journal_files(&fixture.dir).len(), 3);
    lease.update(&updated_three("8.8.8.8")).unwrap();
    for resource in lease.resources() {
        assert_eq!(
            configured_nameservers(fixture.fake.current_state(resource.as_str()).unwrap()),
            vec![ip("8.8.8.8")],
            "resource {resource}"
        );
    }
    lease.restore().unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn update_failure_during_rollback_keeps_recoverable_journal() {
    let (fixture, lease) = three_resource_lease();
    fixture
        .fake
        .inject_backend_failure_after(FakeOp::Apply, 1, 1, "fail during B");
    fixture
        .fake
        .inject_backend_failure(FakeOp::Restore, 1, "rollback failed");
    let err = lease.update(&updated_three("8.8.8.8")).unwrap_err();
    assert!(matches!(err, Error::TransactionFailed { .. }), "{err:?}");
    // The retained ownership proof describes the state that actually remains.
    assert_eq!(journal_files(&fixture.dir).len(), 3);
    for name in journal_files(&fixture.dir) {
        let bytes = std::fs::read(fixture.dir.join("journal").join(name)).unwrap();
        let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record["phase"], "Applied");
        assert_eq!(
            record["applied"]["data"]["state"]["Configured"]["nameservers"][0],
            if record["resource"] == IFACE1 {
                "8.8.8.8"
            } else {
                "1.1.1.1"
            }
        );
    }
    // A failed rollback retains the new state and can still restore its original base.
    let first = lease.resources()[0].as_str().to_string();
    assert_eq!(
        configured_nameservers(fixture.fake.current_state(&first).unwrap()),
        vec![ip("8.8.8.8")]
    );
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn update_failure_during_journal_transition_changes_nothing() {
    let (fixture, lease) = three_resource_lease();
    fixture.manager.set_journal_fail_writes(true);
    let err = lease.update(&updated_three("8.8.8.8")).unwrap_err();
    assert!(matches!(err, Error::TransactionFailed { .. }), "{err:?}");
    fixture.manager.set_journal_fail_writes(false);
    for resource in lease.resources() {
        assert_eq!(
            configured_nameservers(fixture.fake.current_state(resource.as_str()).unwrap()),
            vec![ip("1.1.1.1")],
            "resource {resource} must keep the old configuration"
        );
    }
    assert_eq!(journal_files(&fixture.dir).len(), 3);
    lease.restore().unwrap();
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn failed_abandon_retains_a_retryable_lease_without_restoration(#[case] drop_after_retry: bool) {
    let (fixture, lease) = three_resource_lease();
    let resources = lease.resources().to_vec();
    fixture.manager.set_journal_fail_removes(true);
    let failure = lease.abandon().unwrap_err();
    assert!(matches!(
        failure.lease.update(&updated_three("8.8.8.8")),
        Err(Error::LeaseEnding)
    ));
    assert!(fixture.manager.apply(&updated_three("8.8.8.8")).is_err());
    fixture.manager.set_journal_fail_removes(false);
    if drop_after_retry {
        drop(failure.lease);
    } else {
        failure.lease.abandon().unwrap();
    }
    assert!(journal_files(&fixture.dir).is_empty());
    for resource in resources {
        assert_eq!(
            configured_nameservers(fixture.fake.current_state(resource.as_str()).unwrap()),
            vec![ip("1.1.1.1")]
        );
    }
}

#[test]
fn partial_preparation_failure_cleans_all_unmutated_records() {
    let fixture = new_multi_fixture("partial-prepare");
    fixture.manager.set_journal_fail_writes_after(1);
    assert!(fixture.manager.apply(&updated_three("1.1.1.1")).is_err());
    assert!(journal_files(&fixture.dir).is_empty());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}
