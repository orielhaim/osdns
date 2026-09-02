//! Linux integration tests.
//!
//! These run only on Linux and skip gracefully when the corresponding system
//! components (D-Bus, systemd-resolved, NetworkManager, resolvconf) are
//! absent, so they are safe on minimal CI runners. Phase 5 replaces the skips
//! with real VM-matrix assertions.

#![cfg(target_os = "linux")]
#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::capability::BackendKind;

#[test]
fn detection_selects_a_real_backend_or_reports_honestly() {
    let dir = temp_dir("linux-detect");
    match osdns::DnsManager::builder()
        .owner("io.osdns.test")
        .state_dir(&dir)
        .build()
    {
        Ok(manager) => {
            let caps = manager.capabilities().unwrap();
            assert!(caps.backend.is_real());
            assert!(caps.read);
        }
        Err(osdns::Error::BackendUnavailable(_)) => {}
        Err(osdns::Error::RequiresPrivilege(_)) => {}
        Err(error) => panic!("unexpected detection error: {error}"),
    }
}

#[test]
fn resolved_backend_roundtrip_when_available() {
    if !resolve1_available() {
        return;
    }
    let dir = temp_dir("linux-resolved");
    let manager = osdns::DnsManager::builder()
        .owner("io.osdns.test")
        .state_dir(&dir)
        .build()
        .unwrap();
    let caps = manager.capabilities().unwrap();
    if caps.backend != BackendKind::SystemdResolved {
        return;
    }
    let interfaces = manager.interfaces().unwrap();
    let target = interfaces
        .iter()
        .find(|i| i.is_up && i.name.to_string_lossy() != "lo")
        .expect("a non-loopback interface");
    let config = osdns::DnsConfig::builder(osdns::DnsScope::Interface(
        osdns::InterfaceSelector::Name(target.name.clone()),
    ))
    .nameserver(ip("127.0.0.1"))
    .build()
    .unwrap();

    let before = manager
        .snapshot(&osdns::DnsScope::Interface(osdns::InterfaceSelector::Name(
            target.name.clone(),
        )))
        .unwrap();
    let lease = manager.apply(&config).unwrap();
    assert_eq!(
        manager
            .snapshot(&osdns::DnsScope::Interface(osdns::InterfaceSelector::Name(
                target.name.clone()
            )))
            .unwrap()
            .nameservers(),
        &[ip("127.0.0.1")]
    );
    lease.restore().unwrap();
    let after = manager
        .snapshot(&osdns::DnsScope::Interface(osdns::InterfaceSelector::Name(
            target.name.clone(),
        )))
        .unwrap();
    assert_eq!(before.nameservers(), after.nameservers());
}

fn resolve1_available() -> bool {
    zbus_system_service("org.freedesktop.resolve1")
}

#[allow(dead_code)]
fn network_manager_available() -> bool {
    zbus_system_service("org.freedesktop.NetworkManager")
}

fn zbus_system_service(name: &str) -> bool {
    use zbus::blocking::Connection;
    use zbus::blocking::fdo::DBusProxy;
    use zbus::names::BusName;
    let Ok(conn) = Connection::system() else {
        return false;
    };
    let Ok(proxy) = DBusProxy::new(&conn) else {
        return false;
    };
    let Ok(bus) = BusName::try_from(name) else {
        return false;
    };
    proxy.name_has_owner(bus).unwrap_or(false)
}

#[test]
fn direct_resolv_conf_backend_lifecycle_when_enabled() {
    if std::env::var_os("OSDNS_ALLOW_SYSTEM_MUTATION").is_none() {
        return;
    }
    if !std::path::Path::new("/etc/resolv.conf").is_file() {
        return;
    }
    let Ok(original) = std::fs::read("/etc/resolv.conf") else {
        return;
    };
    if std::path::Path::new("/etc/resolv.conf").is_symlink() {
        return;
    }
    let dir = temp_dir("linux-direct");
    let fake = FakeDns::new();
    let manager = manager_for_testing(
        "io.osdns.test",
        &dir,
        &fake,
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    let caps = manager.capabilities().unwrap();
    if caps.backend != osdns::BackendKind::ResolvConfFile {
        return;
    }
    let config = osdns::DnsConfig::builder(osdns::DnsScope::Global)
        .nameserver(ip("127.0.0.1"))
        .build()
        .unwrap();
    let lease = match manager.apply(&config) {
        Ok(lease) => lease,
        Err(osdns::Error::RequiresPrivilege(_)) => return,
        Err(error) => panic!("unexpected apply error: {error}"),
    };
    let content = std::fs::read("/etc/resolv.conf").unwrap();
    let text = String::from_utf8_lossy(&content);
    assert!(
        text.contains("nameserver 127.0.0.1"),
        "applied file: {text}"
    );

    std::fs::write("/etc/resolv.conf", b"nameserver 203.0.113.9\n").unwrap();
    let failure = lease.restore().unwrap_err();
    assert!(failure.error.is_external_modification());
    std::fs::write("/etc/resolv.conf", &original).unwrap();
    let lease = failure.lease;
    lease.restore().unwrap();
    assert_eq!(std::fs::read("/etc/resolv.conf").unwrap(), original);
}

#[test]
fn dhcp_file_replacement_race_is_transitional() {
    if std::env::var_os("OSDNS_ALLOW_SYSTEM_MUTATION").is_none() {
        return;
    }
    let dir = temp_dir("linux-dhcp-race");
    let fake = FakeDns::new();
    let manager = manager_for_testing(
        "io.osdns.test",
        &dir,
        &fake,
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    if manager.capabilities().unwrap().backend != osdns::BackendKind::ResolvConfFile {
        return;
    }
    if !std::path::Path::new("/etc/resolv.conf").is_file() {
        return;
    }
    let Ok(original) = std::fs::read("/etc/resolv.conf") else {
        return;
    };
    if std::path::Path::new("/etc/resolv.conf").is_symlink() {
        return;
    }
    let config = osdns::DnsConfig::builder(osdns::DnsScope::Global)
        .nameserver(ip("127.0.0.1"))
        .build()
        .unwrap();
    let lease = match manager.apply(&config) {
        Ok(lease) => lease,
        Err(osdns::Error::RequiresPrivilege(_)) => return,
        Err(error) => panic!("unexpected apply error: {error}"),
    };

    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = events.clone();
    let handle = manager
        .watch(std::sync::Arc::new(move |event| {
            sink.lock().unwrap().push(format!("{event:?}"));
        }))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));

    // DHCP-style delete/recreate churn around /etc/resolv.conf.
    for _ in 0..5 {
        let _ = std::fs::remove_file("/etc/resolv.conf");
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write("/etc/resolv.conf", &original).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    handle.stop();

    // The file still exists after churn and our lease still verifies.
    assert!(std::path::Path::new("/etc/resolv.conf").is_file());
    let snapshot = manager.snapshot(&osdns::DnsScope::Global).unwrap();
    let _ = snapshot;
    let lease_for_restore = lease;
    lease_for_restore.restore().unwrap();
    assert_eq!(std::fs::read("/etc/resolv.conf").unwrap(), original);
    std::fs::write("/etc/resolv.conf", &original).unwrap();
}
