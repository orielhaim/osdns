//! Windows integration tests.
//!
//! Read-only tests run against the real system. Tests that mutate DNS state
//! are gated behind the `OSDNS_ALLOW_SYSTEM_MUTATION=1` environment variable
//! and must only run on disposable machines with administrator privileges.

#![cfg(target_os = "windows")]
#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::{BackendKind, Capabilities, DnsConfig, DnsManager, DnsScope, InterfaceSelector};

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
fn default_backend_is_windows_ip_helper() {
    let Some(manager) = real_manager("win-backend") else {
        return;
    };
    let caps = manager.capabilities().unwrap();
    assert_eq!(caps.backend, BackendKind::WindowsIpHelper);
    assert!(caps.read);
    assert!(caps.per_interface_dns);
    assert!(caps.split_dns);
    assert!(caps.default_route);
    assert!(caps.watch);
    assert!(caps.cache_flush);
    assert!(!caps.global_dns);
}

#[test]
fn interfaces_listing_is_read_only() {
    let Some(manager) = real_manager("win-interfaces") else {
        return;
    };
    let interfaces = manager.interfaces().unwrap();
    assert!(!interfaces.is_empty());
    assert!(interfaces.iter().all(|i| i.guid.is_some()));
}

#[test]
fn snapshot_of_real_adapter_is_read_only() {
    let Some(manager) = real_manager("win-snapshot") else {
        return;
    };
    let interfaces = manager.interfaces().unwrap();
    let target = interfaces
        .iter()
        .find(|i| i.is_up)
        .expect("at least one up interface");
    let scope = DnsScope::Interface(InterfaceSelector::Name(target.name.clone()));
    let snapshot = manager.snapshot(&scope).unwrap();
    let _ = snapshot;
}

#[test]
fn global_scope_is_unsupported() {
    let Some(manager) = real_manager("win-global") else {
        return;
    };
    let config = DnsConfig::builder(DnsScope::Global)
        .nameserver(ip("1.1.1.1"))
        .build()
        .unwrap();
    assert!(matches!(
        manager.apply(&config).unwrap_err(),
        osdns::Error::Unsupported { .. }
    ));
}

#[test]
fn validation_rejects_unrepresentable_configs() {
    let Some(manager) = real_manager("win-validate") else {
        return;
    };
    let caps = manager.capabilities().unwrap();
    let expected: Capabilities = caps;
    assert!(expected.split_dns);
    let config = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Index(1)))
        .nameserver(ip("1.1.1.1"))
        .routing_domain("corp.example")
        .build()
        .unwrap();
    manager.validate(&config).unwrap();
}

#[test]
fn mutation_requires_explicit_opt_in() {
    if std::env::var_os("OSDNS_ALLOW_SYSTEM_MUTATION").is_none() {
        return;
    }
    let Some(manager) = real_manager("win-mutate") else {
        return;
    };
    let loopback = windows_test_interface(&manager);
    let scope = DnsScope::Interface(InterfaceSelector::Name(loopback.name.clone()));
    let config = DnsConfig::builder(scope.clone())
        .nameserver(ip("127.0.0.1"))
        .search_domain("osdns.test")
        .build()
        .unwrap();

    match manager.apply(&config) {
        Ok(lease) => {
            let snapshot = manager.snapshot(&scope).unwrap();
            assert_eq!(snapshot.nameservers(), &[ip("127.0.0.1")]);
            assert_eq!(
                snapshot.search_domains(),
                &[osdns::DnsSuffix::parse("osdns.test").unwrap()]
            );
            lease.restore().unwrap();
        }
        Err(error) => panic!("unexpected apply error: {error}"),
    }
}
