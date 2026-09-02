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
