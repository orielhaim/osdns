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
    assert!(caps.default_route);
    assert!(caps.watch);
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
    let service_before = manager.snapshot(&scope).unwrap();

    match manager.apply(&config) {
        Ok(lease) => {
            // Split-only configurations own just the scoped resolver
            // resource; the service DNS state is left untouched (minimal
            // ownership), so the service snapshot must not carry our
            // nameserver.
            assert_eq!(lease.resources().len(), 1, "one resolver file only");
            assert!(
                lease.resources()[0]
                    .as_str()
                    .starts_with("macos:resolver:osdns.test"),
                "{:?}",
                lease.resources()
            );
            let content = std::fs::read("/etc/resolver/osdns.test").unwrap();
            let text = String::from_utf8_lossy(&content);
            assert!(
                text.contains("nameserver 127.0.0.1"),
                "scoped resolver file: {text}"
            );
            let snapshot = manager.snapshot(&scope).unwrap();
            assert_eq!(
                snapshot.nameservers(),
                service_before.nameservers(),
                "the untouched service must keep its pre-lease nameservers"
            );
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

#[test]
fn watchers_start_and_stop_cleanly() {
    let Some(manager) = real_manager("macos-watch") else {
        return;
    };
    let handle = manager.watch(std::sync::Arc::new(|_| {})).unwrap();
    handle.stop();
}

#[test]
fn resolver_file_watch_reports_external_changes() {
    if std::env::var_os("OSDNS_ALLOW_SYSTEM_MUTATION").is_none() {
        return;
    }
    let Some(manager) = real_manager("macos-watch-resolver") else {
        return;
    };
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    let events: StdArc<StdMutex<Vec<String>>> = StdArc::new(StdMutex::new(Vec::new()));
    let sink = events.clone();
    let handle = manager
        .watch(StdArc::new(move |event| match event {
            osdns::DnsEvent::ResourceChanged { resource } => {
                sink.lock().unwrap().push(format!("changed:{resource}"))
            }
            osdns::DnsEvent::ResourceRemoved { resource } => {
                sink.lock().unwrap().push(format!("removed:{resource}"))
            }
            _ => {}
        }))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));

    std::fs::create_dir_all("/etc/resolver").unwrap();
    std::fs::write("/etc/resolver/watch-probe.test", b"nameserver 127.0.0.1\n").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.contains("watch-probe.test"))
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    handle.stop();
    let _ = std::fs::remove_file("/etc/resolver/watch-probe.test");
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.contains("watch-probe.test")),
        "external resolver file changes must be reported"
    );
}
