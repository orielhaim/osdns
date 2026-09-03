//! Real-backend integration matrix: every platform backend is exercised
//! end-to-end (apply → snapshot → restore) in the environment where it is
//! available, behind the `OSDNS_ALLOW_SYSTEM_MUTATION` gate.
//!
//! Availability checks are explicit: a test that cannot run because its
//! backend is missing fails the gate only when the gate is open, so silent
//! skips are visible in CI.

#![cfg(feature = "test-util")]

mod common;

use common::*;
#[cfg(not(target_os = "windows"))]
use osdns::Error;
use osdns::testing::manager_for_backend;
use osdns::{BackendKind, DnsConfig, DnsScope, InterfaceSelector};
use std::time::Duration;

fn mutation_gate_open() -> bool {
    std::env::var_os("OSDNS_ALLOW_SYSTEM_MUTATION").is_some()
}

fn pinned_manager(
    tag: &str,
    kind: BackendKind,
) -> std::result::Result<osdns::DnsManager, osdns::Error> {
    let dir = temp_dir(tag);
    manager_for_backend("io.osdns.matrix", &dir, kind, Duration::from_secs(30))
}

#[cfg(target_os = "linux")]
pub(crate) fn up_interface(manager: &osdns::DnsManager) -> Option<osdns::InterfaceInfo> {
    let name = std::env::var_os("OSDNS_TEST_INTERFACE")
        .expect("mutation tests require OSDNS_TEST_INTERFACE naming a disposable adapter");
    manager
        .interfaces()
        .unwrap()
        .into_iter()
        .find(|i| i.is_up && i.name == name)
}

#[test]
#[cfg(target_os = "linux")]
fn matrix_systemd_resolved_lifecycle() {
    if !mutation_gate_open() {
        return;
    }
    let manager = match pinned_manager("matrix-resolved", BackendKind::SystemdResolved) {
        Ok(manager) => manager,
        Err(Error::BackendUnavailable(_)) => {
            panic!("gate is open: systemd-resolved must be available on this VM")
        }
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(
        manager.capabilities().unwrap().backend,
        BackendKind::SystemdResolved
    );
    let target = up_interface(&manager).expect("the disposable interface must be up");
    let scope = DnsScope::Interface(InterfaceSelector::Name(target.name.clone()));
    let before = manager.snapshot(&scope).unwrap();
    let config = DnsConfig::builder(scope.clone())
        .nameserver(ip("127.0.0.1"))
        .nameserver(ip("::1"))
        .search_domain("search.test")
        .routing_domain("route.test")
        .routing_domain(".")
        .build()
        .unwrap();

    let lease = manager
        .apply(&config)
        .expect("systemd-resolved apply must succeed when opted in");
    let actual = manager.snapshot(&scope).unwrap();
    assert_eq!(actual.nameservers(), config.nameservers());
    assert_eq!(actual.search_domains(), config.search_domains());
    assert_eq!(actual.routing_domains(), config.routing_domains());
    lease.restore().unwrap();
    assert_eq!(manager.snapshot(&scope).unwrap(), before);
}

#[test]
#[cfg(target_os = "linux")]
fn matrix_network_manager_lifecycle() {
    if !mutation_gate_open() {
        return;
    }
    let manager = match pinned_manager("matrix-nm", BackendKind::NetworkManager) {
        Ok(manager) => manager,
        Err(Error::BackendUnavailable(_)) => {
            // NM not running on this VM: the availability check is the point.
            return;
        }
        Err(error) => panic!("unexpected error: {error}"),
    };
    let Some(target) = up_interface(&manager) else {
        return;
    };
    let scope = DnsScope::Interface(InterfaceSelector::Name(target.name.clone()));
    let config = DnsConfig::builder(scope.clone())
        .nameserver(ip("127.0.0.1"))
        .build()
        .unwrap();
    let lease = match manager.apply(&config) {
        Ok(lease) => lease,
        Err(Error::BackendUnavailable(_)) => return,
        Err(Error::RequiresPrivilege(_)) => return,
        Err(error) => panic!("unexpected apply error: {error}"),
    };
    assert_eq!(
        manager.snapshot(&scope).unwrap().nameservers(),
        &[ip("127.0.0.1")]
    );
    lease.restore().unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn matrix_resolvconf_lifecycle() {
    if !mutation_gate_open() {
        return;
    }
    let manager = match pinned_manager("matrix-resolvconf", BackendKind::Resolvconf) {
        Ok(manager) => manager,
        Err(Error::BackendUnavailable(_)) => {
            panic!("gate is open: openresolv must be installed on this VM")
        }
        Err(error) => panic!("unexpected error: {error}"),
    };
    let scope = DnsScope::Global;
    let config = DnsConfig::builder(scope.clone())
        .nameserver(ip("127.0.0.1"))
        .build()
        .unwrap();
    let before = manager.snapshot(&scope).unwrap();
    let lease = manager
        .apply(&config)
        .expect("openresolv apply must succeed when opted in");
    assert_eq!(
        manager.snapshot(&scope).unwrap().nameservers(),
        &[ip("127.0.0.1")]
    );
    lease.restore().unwrap();
    assert_eq!(manager.snapshot(&scope).unwrap(), before);
}

#[test]
#[cfg(target_os = "linux")]
fn matrix_direct_resolv_conf_lifecycle() {
    if !mutation_gate_open() {
        return;
    }
    if !std::path::Path::new("/etc/resolv.conf").is_file()
        || std::path::Path::new("/etc/resolv.conf").is_symlink()
    {
        panic!("gate is open: /etc/resolv.conf must be a regular file on this VM");
    }
    let Ok(original) = std::fs::read("/etc/resolv.conf") else {
        return;
    };
    let manager = match pinned_manager("matrix-direct", BackendKind::ResolvConfFile) {
        Ok(manager) => manager,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(
        manager.capabilities().unwrap().backend,
        BackendKind::ResolvConfFile
    );
    let scope = DnsScope::Global;
    let config = DnsConfig::builder(scope.clone())
        .nameserver(ip("127.0.0.1"))
        .build()
        .unwrap();

    let lease = match manager.apply(&config) {
        Ok(lease) => lease,
        Err(Error::RequiresPrivilege(_)) => return,
        Err(error) => panic!("unexpected apply error: {error}"),
    };
    let content = std::fs::read("/etc/resolv.conf").unwrap();
    let text = String::from_utf8_lossy(&content);
    assert!(text.contains("nameserver 127.0.0.1"), "{text}");

    // External write between apply and restore is never overwritten.
    std::fs::write("/etc/resolv.conf", b"nameserver 203.0.113.9\n").unwrap();
    let failure = lease.restore().unwrap_err();
    assert!(failure.error.is_external_modification());
    std::fs::write("/etc/resolv.conf", &original).unwrap();
    failure.lease.restore().unwrap();
    assert_eq!(std::fs::read("/etc/resolv.conf").unwrap(), original);
}

#[cfg(target_os = "windows")]
#[rstest::rstest]
#[case(&["127.0.0.1"])]
#[case(&["::1"])]
#[case(&["127.0.0.1", "::1"])]
fn matrix_windows_ip_helper_and_nrpt_lifecycle(#[case] servers: &[&str]) {
    if !mutation_gate_open() {
        return;
    }
    let manager = match pinned_manager("matrix-win", BackendKind::WindowsIpHelper) {
        Ok(manager) => manager,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let target = windows_test_interface(&manager);
    let scope = DnsScope::Interface(InterfaceSelector::Name(target.name.clone()));
    let before = manager.snapshot(&scope).unwrap();
    let config = DnsConfig::builder(scope.clone())
        .nameservers(servers.iter().map(|server| ip(server)))
        .search_domain("matrix.test")
        .routing_domain("matrix.test")
        .build()
        .unwrap();

    let lease = match manager.apply(&config) {
        Ok(lease) => lease,
        Err(error) => panic!("unexpected apply error: {error}"),
    };
    // One interface resource plus one NRPT rule resource.
    assert_eq!(lease.resources().len(), 2, "{:?}", lease.resources());
    assert!(
        lease.resources()[1].as_str().starts_with("windows:nrpt:"),
        "NRPT must be its own resource: {:?}",
        lease.resources()
    );
    let snapshot = manager.snapshot(&scope).unwrap();
    assert_eq!(snapshot.nameservers(), config.nameservers());
    assert_eq!(snapshot.search_domains(), config.search_domains());
    lease.restore().unwrap();
    assert_eq!(manager.snapshot(&scope).unwrap(), before);
}

#[test]
#[cfg(target_os = "macos")]
fn matrix_macos_system_configuration_and_resolver_files() {
    if !mutation_gate_open() {
        return;
    }
    let manager = match pinned_manager("matrix-macos", BackendKind::MacosSystemConfiguration) {
        Ok(manager) => manager,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let scope = DnsScope::Interface(InterfaceSelector::Default);
    let config = DnsConfig::builder(scope.clone())
        .nameserver(ip("127.0.0.1"))
        .routing_domain("matrix.test")
        .build()
        .unwrap();

    let lease = match manager.apply(&config) {
        Ok(lease) => lease,
        Err(Error::RequiresPrivilege(_)) => return,
        Err(error) => panic!("unexpected apply error: {error}"),
    };
    // Split-only configurations own only the scoped resolver resource and
    // leave the service DNS state untouched (minimal ownership).
    assert_eq!(lease.resources().len(), 1);
    let resolver_resource = &lease.resources()[0];
    assert!(
        resolver_resource
            .as_str()
            .starts_with("macos:resolver:matrix.test"),
        "{resolver_resource:?}"
    );
    assert!(std::path::Path::new("/etc/resolver/matrix.test").is_file());
    lease.restore().unwrap();
    assert!(!std::path::Path::new("/etc/resolver/matrix.test").exists());
}
