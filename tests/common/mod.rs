#![cfg(feature = "test-util")]
#![allow(dead_code)]

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub use osdns::testing::{FakeDns, manager_for_testing};
use osdns::{BackendKind, Capabilities, DnsConfig, DnsManager, DnsScope, InterfaceSelector};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn temp_dir(tag: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("osdns-{tag}-{}-{nanos}-{id}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

pub struct Fixture {
    pub manager: DnsManager,
    pub fake: FakeDns,
    pub dir: PathBuf,
}

pub fn new_fixture(tag: &str) -> Fixture {
    let dir = temp_dir(tag);
    let fake = FakeDns::new();
    let manager =
        manager_for_testing("io.osdns.test", &dir, &fake, Duration::from_secs(30)).unwrap();
    Fixture { manager, fake, dir }
}

pub fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

#[cfg(target_os = "windows")]
pub fn windows_test_interface(manager: &DnsManager) -> osdns::InterfaceInfo {
    let name = std::env::var_os("OSDNS_TEST_INTERFACE")
        .expect("mutation tests require OSDNS_TEST_INTERFACE naming a disposable adapter");
    manager
        .interfaces()
        .unwrap()
        .into_iter()
        .find(|i| i.name == name)
        .expect("the disposable test adapter must exist")
}

pub const GLOBAL: &str = "fake:global";
pub const IFACE1: &str = "fake:interface:1";
pub const IFACE2: &str = "fake:interface:2";

pub fn iface_scope(index: u32) -> DnsScope {
    DnsScope::Interface(InterfaceSelector::Index(index))
}

pub fn iface_config(index: u32, ns: &str) -> DnsConfig {
    DnsConfig::builder(iface_scope(index))
        .nameserver(ip(ns))
        .build()
        .unwrap()
}

pub fn resource_id(value: &str) -> osdns::ResourceId {
    value.parse().unwrap()
}

pub fn journal_files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir.join("journal")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") {
                out.push(name);
            }
        }
    }
    out.sort();
    out
}

pub fn journal_record_json(dir: &Path) -> serde_json::Value {
    let files = journal_files(dir);
    assert_eq!(files.len(), 1, "expected exactly one journal record");
    let bytes = fs::read(dir.join("journal").join(&files[0])).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

pub fn state_with(ns: &str) -> osdns::testing::FakeState {
    osdns::testing::FakeState::Configured {
        nameservers: vec![ip(ns)],
        search_domains: vec![],
        routing_domains: vec![],
        default_route: None,
    }
}

pub fn new_multi_fixture(tag: &str) -> Fixture {
    let dir = temp_dir(tag);
    let caps = Capabilities::new(BackendKind::Fake)
        .with_read(true)
        .with_global_dns(true)
        .with_per_interface_dns(true)
        .with_search_domains(true)
        .with_split_dns(true)
        .with_watch(true)
        .with_cache_flush(true);
    let fake = FakeDns::with_multi_resource(caps);
    let manager =
        manager_for_testing("io.osdns.test", &dir, &fake, Duration::from_secs(30)).unwrap();
    Fixture { manager, fake, dir }
}

pub fn routing_config(domains: &[&str]) -> DnsConfig {
    let mut builder = DnsConfig::builder(iface_scope(1)).nameserver(ip("1.1.1.1"));
    for domain in domains {
        builder = builder.routing_domain(domain);
    }
    builder.build().unwrap()
}
