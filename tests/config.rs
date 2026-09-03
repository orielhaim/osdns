//! Configuration model, builders, and capability validation.
#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::capability::BackendKind;
use osdns::testing::{FakeDns, manager_for_testing};
use osdns::{
    Capabilities, ConflictReason, DnsConfig, DnsManager, DnsScope, Error, InterfaceSelector,
};
use std::time::Duration;

#[test]
fn builder_produces_valid_configs() {
    let config = DnsConfig::builder(iface_scope(1))
        .nameserver(ip("1.1.1.1"))
        .nameservers([ip("8.8.8.8")])
        .search_domain("Example.COM")
        .search_domains(["corp.example"])
        .routing_domain("internal.example")
        .default_route(true)
        .build()
        .unwrap();
    assert_eq!(config.nameservers(), &[ip("1.1.1.1"), ip("8.8.8.8")]);
    assert_eq!(config.search_domains().len(), 2);
    assert_eq!(config.search_domains()[0].as_str(), "example.com");
    assert_eq!(config.routing_domains().len(), 1);
    assert_eq!(config.default_route(), Some(true));
}

#[test]
fn builder_dedupes_preserving_order() {
    let config = DnsConfig::builder(iface_scope(1))
        .nameserver(ip("1.1.1.1"))
        .nameserver(ip("8.8.8.8"))
        .nameserver(ip("1.1.1.1"))
        .search_domain("a.example")
        .search_domain("a.example")
        .build()
        .unwrap();
    assert_eq!(config.nameservers(), &[ip("1.1.1.1"), ip("8.8.8.8")]);
    assert_eq!(config.search_domains().len(), 1);
}

#[test]
fn builder_rejects_unspecified_nameservers() {
    let result = DnsConfig::builder(DnsScope::Global)
        .nameserver("0.0.0.0".parse().unwrap())
        .build();
    assert!(matches!(result, Err(Error::InvalidConfig(_))));
    let result = DnsConfig::builder(DnsScope::Global)
        .nameserver("::".parse().unwrap())
        .build();
    assert!(matches!(result, Err(Error::InvalidConfig(_))));
}

#[test]
fn builder_rejects_global_scope_misuse() {
    let result = DnsConfig::builder(DnsScope::Global)
        .nameserver(ip("1.1.1.1"))
        .routing_domain("internal.example")
        .build();
    assert!(matches!(result, Err(Error::InvalidConfig(_))));

    let result = DnsConfig::builder(DnsScope::Global)
        .nameserver(ip("1.1.1.1"))
        .default_route(true)
        .build();
    assert!(matches!(result, Err(Error::InvalidConfig(_))));
}

#[test]
fn resolves_interface_selectors() {
    let fixture = new_fixture("selectors");
    let info = fixture.manager.interfaces().unwrap();
    assert_eq!(info.len(), 2);

    let by_index = fixture
        .manager
        .snapshot(&DnsScope::Interface(InterfaceSelector::Index(1)))
        .unwrap();
    let by_name = fixture
        .manager
        .snapshot(&DnsScope::Interface(InterfaceSelector::Name("eth0".into())))
        .unwrap();
    let by_default = fixture
        .manager
        .snapshot(&DnsScope::Interface(InterfaceSelector::Default))
        .unwrap();
    assert_eq!(by_index.nameservers(), by_name.nameservers());
    assert_eq!(by_index.search_domains(), by_name.search_domains());
    assert_eq!(by_index.nameservers(), by_default.nameservers());
    assert_eq!(by_index.search_domains(), by_default.search_domains());

    let missing = fixture
        .manager
        .snapshot(&DnsScope::Interface(InterfaceSelector::Index(9)));
    assert!(matches!(missing, Err(Error::InvalidConfig(_))));
    let missing = fixture
        .manager
        .snapshot(&DnsScope::Interface(InterfaceSelector::Name(
            "does-not-exist".into(),
        )));
    assert!(matches!(missing, Err(Error::InvalidConfig(_))));
}

#[test]
fn capability_gaps_fail_before_mutation() {
    let dir = temp_dir("caps");
    let caps = Capabilities::new(BackendKind::Fake)
        .with_read(true)
        .with_global_dns(true)
        .with_per_interface_dns(true);
    let fake = FakeDns::with_capabilities(caps);
    let manager =
        manager_for_testing("io.osdns.test", &dir, &fake, Duration::from_secs(30)).unwrap();

    let with_routing = DnsConfig::builder(iface_scope(1))
        .nameserver(ip("1.1.1.1"))
        .routing_domain("internal.example")
        .build()
        .unwrap();
    let err = manager.validate(&with_routing).unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }));
    let err = manager.apply(&with_routing).unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }));

    let with_search = DnsConfig::builder(iface_scope(1))
        .nameserver(ip("1.1.1.1"))
        .search_domain("corp.example")
        .build()
        .unwrap();
    let err = manager.apply(&with_search).unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }));

    let with_default_route = DnsConfig::builder(iface_scope(1))
        .nameserver(ip("1.1.1.1"))
        .default_route(true)
        .build()
        .unwrap();
    let err = manager.validate(&with_default_route).unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }));
    let err = manager.apply(&with_default_route).unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }));

    assert_eq!(
        fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty),
        "failed validation must not touch the system"
    );
}

#[test]
fn update_after_defunct_lease_conflicts() {
    let fixture = new_fixture("terminated");
    let config = iface_config(1, "1.1.1.1");
    let lease = fixture.manager.apply(&config).unwrap();

    let injector = osdns::testing::FaultInjector::new();
    injector.crash_at(osdns::testing::TxPoint::AfterUpdatePrepared);
    fixture.manager.install_fault_injector(injector.clone());
    let outcome = osdns::testing::catch_crash(|| lease.update(&iface_config(1, "8.8.8.8")));
    injector.clear();
    assert!(matches!(outcome, osdns::testing::CrashOutcome::Crashed));

    let err = lease.update(&config).unwrap_err();
    assert!(matches!(
        err,
        Error::Conflict {
            reason: ConflictReason::LeaseNotActive,
            ..
        }
    ));
}

#[test]
#[cfg(target_os = "macos")]
fn default_backend_is_macos_system_configuration() {
    let manager = DnsManager::builder()
        .owner("io.osdns.test")
        .state_dir(temp_dir("default-backend"))
        .build()
        .unwrap();
    assert_eq!(
        manager.capabilities().unwrap().backend,
        BackendKind::MacosSystemConfiguration
    );
}

#[test]
fn builder_requires_owner() {
    let err = DnsManager::builder()
        .state_dir(temp_dir("no-owner"))
        .build()
        .unwrap_err();
    assert!(matches!(err, Error::InvalidConfig(_)));
}

#[test]
fn builder_rejects_bad_owner() {
    let err = DnsManager::builder()
        .owner("has spaces")
        .state_dir(temp_dir("bad-owner"))
        .build()
        .unwrap_err();
    assert!(matches!(err, Error::InvalidConfig(_)));
}
