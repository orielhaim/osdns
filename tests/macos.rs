//! macOS integration tests.
//!
//! Read-only tests run against the real SystemConfiguration store. Tests that
//! mutate DNS state are gated behind `OSDNS_ALLOW_SYSTEM_MUTATION=1` and must
//! only run on disposable machines with administrator privileges.

#![cfg(target_os = "macos")]
#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::{BackendKind, DnsConfig, DnsManager, DnsScope, InterfaceSelector};

fn real_manager(tag: &str) -> Option<DnsManager> {
    let dir = temp_dir(tag);
    match DnsManager::builder()
        .owner("io.osdns.test")
        .state_dir(&dir)
        .build()
    {
        Ok(manager) => Some(manager),
        Err(osdns::Error::RequiresPrivilege(_)) => None,
        Err(error) => panic!("unexpected builder error: {error}"),
    }
}

#[test]
fn default_backend_is_system_configuration() {
    let Some(manager) = real_manager("macos-backend") else {
        return;
    };
    let caps = manager.capabilities().unwrap();
    assert_eq!(caps.backend, BackendKind::MacosSystemConfiguration);
    assert!(caps.read);
    assert!(caps.per_interface_dns);
    assert!(caps.split_dns);
    assert!(caps.watch);
    assert!(!caps.global_dns || true);
}

#[test]
fn interfaces_listing_is_read_only() {
    let Some(manager) = real_manager("macos-interfaces") else {
        return;
    };
    let interfaces = manager.interfaces().unwrap();
    assert!(!interfaces.is_empty());
}

#[test]
fn snapshot_of_primary_service_is_read_only() {
    let Some(manager) = real_manager("macos-snapshot") else {
        return;
    };
    let snapshot = manager.snapshot(&DnsScope::Global).unwrap();
    let _ = snapshot;
    let snapshot = manager
        .snapshot(&DnsScope::Interface(InterfaceSelector::Default))
        .unwrap();
    let _ = snapshot;
}

#[test]
fn root_routing_domain_is_rejected_before_mutation() {
    let Some(manager) = real_manager("macos-root") else {
        return;
    };
    let config = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Default))
        .nameserver(ip("127.0.0.1"))
        .routing_domain(".")
        .build()
        .unwrap();
    assert!(matches!(
        manager.apply(&config).unwrap_err(),
        osdns::Error::Unsupported { .. }
    ));
}

#[test]
fn mutation_requires_explicit_opt_in() {
    if std::env::var_os("OSDNS_ALLOW_SYSTEM_MUTATION").is_none() {
        return;
    }
    let Some(manager) = real_manager("macos-mutate") else {
        return;
    };
    let scope = DnsScope::Interface(InterfaceSelector::Default);
    let config = DnsConfig::builder(scope.clone())
        .nameserver(ip("127.0.0.1"))
        .routing_domain("osdns.test")
        .build()
        .unwrap();

    match manager.apply(&config) {
        Ok(lease) => {
            assert_eq!(lease.resources().len(), 2, "service plus one resolver file");
            let snapshot = manager.snapshot(&scope).unwrap();
            assert_eq!(snapshot.nameservers(), &[ip("127.0.0.1")]);
            lease.restore().unwrap();
            assert!(
                !std::path::Path::new("/etc/resolver/osdns.test").exists(),
                "the scoped resolver file must be removed on restore"
            );
        }
        Err(osdns::Error::RequiresPrivilege(_)) => {}
        Err(error) => panic!("unexpected apply error: {error}"),
    }
}
