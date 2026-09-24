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
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use osdns::InterfaceSelector;
use osdns::testing::manager_for_backend;
use osdns::{BackendKind, DnsConfig, DnsScope};
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
use std::net::IpAddr;
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
use std::sync::Arc;
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
use std::time::Instant;
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

fn mutation_gate_open() -> bool {
    std::env::var_os("OSDNS_ALLOW_SYSTEM_MUTATION").is_some()
}

fn pinned_manager(
    tag: &str,
    kind: BackendKind,
) -> std::result::Result<(osdns::DnsManager, TestDir), osdns::Error> {
    let dir = temp_dir(tag);
    let manager = manager_for_backend("io.osdns.matrix", &dir, kind, Duration::from_secs(30))?;
    Ok((manager, dir))
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
fn bsd_system_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(target_os = "linux")]
fn linux_resolvconf_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
fn resolvconf_binary() -> PathBuf {
    ["/sbin/resolvconf", "/usr/sbin/resolvconf"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("openresolv resolvconf must be installed")
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
fn resolvconf_owner_tag() -> String {
    const NAMESPACE: u128 = 0x6f73_646e_7372_6573_6f6c_7600_0001;
    let owner = "io.osdns.matrix";
    let readable = owner;
    let hash = uuid::Uuid::new_v5(&uuid::Uuid::from_u128(NAMESPACE), owner.as_bytes()).simple();
    format!("{readable}-{hash}.osdns.global")
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
fn run_resolvconf(args: &[&str], input: Option<&[u8]>) -> Output {
    let mut command = Command::new(resolvconf_binary());
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn().expect("spawn resolvconf");
    if let Some(input) = input {
        child
            .stdin
            .take()
            .expect("resolvconf stdin")
            .write_all(input)
            .expect("write resolvconf stdin");
    }
    let output = child.wait_with_output().expect("wait for resolvconf");
    assert!(
        output.status.success(),
        "resolvconf {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
fn resolvconf_key_exists(tag: &str) -> bool {
    let output = run_resolvconf(&["-i"], None);
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .any(|key| key == tag)
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
fn active_nameserver() -> IpAddr {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap();
    text.lines()
        .filter_map(|line| line.strip_prefix("nameserver "))
        .filter_map(|address| address.trim().parse::<IpAddr>().ok())
        .find(|address| !address.is_unspecified() && !address.is_loopback())
        .expect("active libc configuration must contain a non-local nameserver")
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
struct BsdResolvconfTagGuard {
    tag: String,
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
impl BsdResolvconfTagGuard {
    fn new() -> Self {
        let tag = resolvconf_owner_tag();
        assert!(
            !resolvconf_key_exists(&tag),
            "test osdns key already exists"
        );
        Self { tag }
    }
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
impl Drop for BsdResolvconfTagGuard {
    fn drop(&mut self) {
        let _ = Command::new(resolvconf_binary())
            .args(["-d", &self.tag, "-f"])
            .output();
    }
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
fn wait_for_event(receiver: &std::sync::mpsc::Receiver<osdns::DnsEvent>, resource: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = receiver.recv_timeout(remaining).expect("watch event");
        let event_resource = match &event {
            osdns::DnsEvent::ResourceChanged { resource }
            | osdns::DnsEvent::ResourceRemoved { resource } => resource,
            _ => continue,
        };
        if event_resource.as_str() == resource {
            return;
        }
    }
    panic!("watch event was not delivered before the deadline");
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
struct BsdResolvFileGuard {
    target: PathBuf,
    backup: PathBuf,
    _directory: tempfile::TempDir,
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
impl BsdResolvFileGuard {
    fn new() -> Self {
        let target = PathBuf::from("/etc/resolv.conf");
        let directory = tempfile::tempdir().unwrap();
        let backup = directory.path().join("resolv.conf");
        let output = Command::new("cp")
            .arg("-p")
            .arg(&target)
            .arg(&backup)
            .output()
            .expect("run cp");
        assert!(output.status.success(), "copy /etc/resolv.conf: {output:?}");
        let output = Command::new("chflags")
            .arg("0")
            .arg(&target)
            .output()
            .expect("clear resolv.conf flags");
        assert!(
            output.status.success(),
            "clear resolv.conf flags: {output:?}"
        );
        Self {
            target,
            backup,
            _directory: directory,
        }
    }

    fn restore(&self) {
        let _ = Command::new("chflags")
            .arg("0")
            .arg(self.target.to_str().unwrap())
            .output();
        let _ = std::fs::remove_file(&self.target);
        let output = Command::new("cp")
            .arg("-p")
            .arg(&self.backup)
            .arg(&self.target)
            .output()
            .expect("run cp");
        assert!(
            output.status.success(),
            "restore /etc/resolv.conf: {output:?}"
        );
    }
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
impl Drop for BsdResolvFileGuard {
    fn drop(&mut self) {
        self.restore();
        let _ = std::fs::remove_file(&self.backup);
    }
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
fn metric_for_tag(tag: &str) -> Option<i64> {
    for directory in ["/var/run/resolvconf/metrics", "/run/resolvconf/metrics"] {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(metric) = name.strip_suffix(&format!(" {tag}")) {
                return metric.parse().ok();
            }
        }
    }
    None
}

#[test]
fn pinned_manager_retains_its_state_directory() {
    let (manager, state_dir) = pinned_manager("matrix-state-dir", BackendKind::Fake).unwrap();
    assert!(state_dir.is_dir());
    let config = DnsConfig::builder(DnsScope::Global)
        .nameserver(ip("127.0.0.1"))
        .build()
        .unwrap();
    manager.apply(&config).unwrap().restore().unwrap();
}

#[cfg(target_os = "linux")]
fn active_nameserver() -> IpAddr {
    ip("192.0.2.1")
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
    let (manager, _state_dir) =
        match pinned_manager("matrix-resolved", BackendKind::SystemdResolved) {
            Ok(pair) => pair,
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
    let (manager, _state_dir) = match pinned_manager("matrix-nm", BackendKind::NetworkManager) {
        Ok(pair) => pair,
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
    let _guard = linux_resolvconf_guard();
    let (manager, _state_dir) = match pinned_manager("matrix-resolvconf", BackendKind::Resolvconf) {
        Ok(pair) => pair,
        Err(Error::BackendUnavailable(_)) => {
            panic!("gate is open: openresolv must be installed on this VM")
        }
        Err(error) => panic!("unexpected error: {error}"),
    };
    let capabilities = manager.capabilities().unwrap();
    assert_eq!(capabilities.backend, BackendKind::Resolvconf);
    assert!(!capabilities.per_interface_dns);
    assert!(!capabilities.split_dns);
    let scope = DnsScope::Global;
    let config = DnsConfig::builder(scope.clone())
        .nameserver(active_nameserver())
        .build()
        .unwrap();
    let before = manager.snapshot(&scope).unwrap();
    let lease = manager
        .apply(&config)
        .expect("openresolv apply must succeed when opted in");
    assert!(
        manager
            .snapshot(&scope)
            .unwrap()
            .nameservers()
            .contains(&config.nameservers()[0])
    );
    lease.restore().unwrap();
    assert_eq!(manager.snapshot(&scope).unwrap(), before);
}

#[test]
#[cfg(target_os = "linux")]
fn matrix_legacy_openresolv_journal_clears_without_mutation() {
    if !mutation_gate_open() {
        return;
    }
    let _guard = linux_resolvconf_guard();
    let tag = resolvconf_owner_tag();
    assert!(!resolvconf_key_exists(&tag));
    let (manager, state_dir) = pinned_manager("matrix-legacy-openresolv", BackendKind::Resolvconf)
        .expect("construct openresolv backend");
    let config = DnsConfig::builder(DnsScope::Global)
        .nameserver(ip("127.0.0.1"))
        .build()
        .unwrap();
    let lease = manager.apply(&config).expect("apply openresolv record");
    lease.debug_release_locks_keep_journal();
    let file = journal_files(&state_dir).pop().unwrap();
    let path = state_dir.join("journal").join(file);
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let original = b"nameserver 192.0.2.10\n";
    record["before"]["data"] = serde_json::json!({"content": original.to_vec()});
    record["applied"]["data"] = serde_json::json!({"content": b"nameserver 127.0.0.1\n".to_vec()});
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    run_resolvconf(&["-d", &tag, "-f"], None);
    run_resolvconf(&["-a", &tag, "-m", "17"], Some(original));

    let outcomes = manager.recover_stale().unwrap();
    assert!(matches!(
        outcomes.as_slice(),
        [osdns::RecoveryOutcome::JournalCleared { .. }]
    ));
    assert!(journal_files(&state_dir).is_empty());
    assert!(resolvconf_key_exists(&tag));
    run_resolvconf(&["-d", &tag, "-f"], None);

    let (manager, state_dir) = pinned_manager(
        "matrix-legacy-openresolv-unresolved",
        BackendKind::Resolvconf,
    )
    .expect("construct openresolv backend");
    let lease = manager.apply(&config).expect("apply openresolv record");
    lease.debug_release_locks_keep_journal();
    let file = journal_files(&state_dir).pop().unwrap();
    let path = state_dir.join("journal").join(file);
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["before"]["data"] = serde_json::json!({"content": original.to_vec()});
    record["applied"]["data"] = serde_json::json!({"content": b"nameserver 127.0.0.1\n".to_vec()});
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

    let outcomes = manager.recover_stale().unwrap();
    assert!(matches!(
        outcomes.as_slice(),
        [osdns::RecoveryOutcome::Failed { detail, .. }]
            if detail.contains("lacks key attributes")
    ));
    assert_eq!(journal_files(&state_dir).len(), 1);
    assert!(resolvconf_key_exists(&tag));
    run_resolvconf(&["-d", &tag, "-f"], None);
}

#[test]
#[cfg(target_os = "linux")]
fn matrix_classic_resolvconf_is_rejected() {
    if std::env::var_os("OSDNS_EXPECT_CLASSIC_RESOLVCONF").is_none() {
        return;
    }
    let state = temp_dir("matrix-classic-resolvconf");
    let error = manager_for_backend(
        "io.osdns.classic-resolvconf",
        &state,
        BackendKind::Resolvconf,
        Duration::from_secs(10),
    )
    .unwrap_err();
    match error {
        Error::BackendUnavailable(detail) => assert!(
            detail.contains("openresolv"),
            "classic resolvconf rejection was not explicit: {detail}"
        ),
        error => panic!("unexpected error: {error}"),
    }
}

#[test]
#[cfg(target_os = "linux")]
fn matrix_openresolv_passthrough_is_rejected() {
    if std::env::var_os("OSDNS_EXPECT_OPENRESOLV_PASSTHROUGH").is_none() {
        return;
    }
    let error = osdns::DnsManager::builder()
        .owner("io.osdns.openresolv-passthrough")
        .build()
        .unwrap_err();
    match error {
        Error::BackendUnavailable(detail) => assert!(
            detail.contains("Openresolv"),
            "passthrough rejection was not explicit: {detail}"
        ),
        error => panic!("unexpected error: {error}"),
    }
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
    let (manager, _state_dir) = match pinned_manager("matrix-direct", BackendKind::ResolvConfFile) {
        Ok(pair) => pair,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let capabilities = manager.capabilities().unwrap();
    assert_eq!(capabilities.backend, BackendKind::ResolvConfFile);
    assert!(!capabilities.per_interface_dns);
    assert!(!capabilities.split_dns);
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

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
#[test]
fn matrix_bsd_detection_capabilities_and_resolver_limits() {
    if !mutation_gate_open() {
        return;
    }
    let _guard = bsd_system_guard();
    let state = temp_dir("matrix-bsd-detect");
    let manager = osdns::DnsManager::builder()
        .owner("io.osdns.detect")
        .state_dir(&state)
        .build()
        .expect("openresolv must own /etc/resolv.conf in this VM");
    let capabilities = manager.capabilities().unwrap();
    assert_eq!(capabilities.backend, BackendKind::Resolvconf);
    assert!(capabilities.read);
    assert!(capabilities.global_dns);
    assert!(!capabilities.per_interface_dns);
    assert!(capabilities.search_domains);
    assert!(!capabilities.split_dns);
    assert!(!capabilities.default_route);
    assert!(capabilities.watch);
    assert!(!capabilities.cache_flush);
    assert!(!manager.interfaces().unwrap().is_empty());

    let too_many_servers = DnsConfig::builder(DnsScope::Global)
        .nameservers([
            ip("192.0.2.1"),
            ip("192.0.2.2"),
            ip("192.0.2.3"),
            ip("192.0.2.4"),
        ])
        .build()
        .unwrap();
    assert!(manager.validate(&too_many_servers).is_err());
    let too_many_searches = DnsConfig::builder(DnsScope::Global)
        .nameserver(active_nameserver())
        .search_domains([
            "a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test",
        ])
        .build()
        .unwrap();
    assert!(manager.validate(&too_many_searches).is_err());
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
#[test]
fn matrix_bsd_custom_openresolv_state_is_refused() {
    if std::env::var_os("OSDNS_BSD_CUSTOM_STATE").is_none() {
        return;
    }
    let state = temp_dir("matrix-bsd-custom-state");
    let error = manager_for_backend(
        "io.osdns.custom-state",
        &state,
        BackendKind::Resolvconf,
        Duration::from_secs(10),
    )
    .unwrap_err();
    assert!(matches!(error, Error::BackendUnavailable(_)), "{error:?}");
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
#[test]
fn matrix_bsd_openresolv_lifecycle_watch_and_external_modification() {
    if !mutation_gate_open() {
        return;
    }
    let _guard = bsd_system_guard();
    let _tag = BsdResolvconfTagGuard::new();
    let original_live = std::fs::read("/etc/resolv.conf").unwrap();
    let (manager, _state_dir) = pinned_manager("matrix-bsd-openresolv", BackendKind::Resolvconf)
        .expect("construct openresolv backend");
    let scope = DnsScope::Global;
    let config = DnsConfig::builder(scope.clone())
        .nameserver(active_nameserver())
        .search_domain("matrix.test")
        .build()
        .unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let watch = manager
        .watch(Arc::new(move |event| {
            let _ = sender.send(event.clone());
        }))
        .unwrap();
    let lease = manager.apply(&config).expect("apply openresolv record");
    let resource = lease.resources()[0].clone();
    assert!(
        resource
            .as_str()
            .starts_with(&format!("{}:resolvconf:tag:", std::env::consts::OS))
    );
    let actual = manager.snapshot(&scope).unwrap();
    assert!(actual.nameservers().contains(&config.nameservers()[0]));
    assert!(
        actual
            .search_domains()
            .contains(&config.search_domains()[0])
    );
    std::thread::sleep(Duration::from_millis(600));
    run_resolvconf(
        &["-a", &resolvconf_owner_tag(), "-m", "0"],
        Some(b"nameserver 192.0.2.250\n"),
    );
    wait_for_event(&receiver, resource.as_str());
    let failure = lease.restore().unwrap_err();
    assert!(failure.error.is_external_modification());
    run_resolvconf(&["-d", &resolvconf_owner_tag(), "-f"], None);
    failure.lease.restore().unwrap();
    assert!(!resolvconf_key_exists(&resolvconf_owner_tag()));
    assert_eq!(std::fs::read("/etc/resolv.conf").unwrap(), original_live);
    watch.stop();
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
#[test]
fn matrix_bsd_openresolv_restores_preexisting_key_and_metric() {
    if !mutation_gate_open() {
        return;
    }
    let _guard = bsd_system_guard();
    let _tag = BsdResolvconfTagGuard::new();
    let original_live = std::fs::read("/etc/resolv.conf").unwrap();
    run_resolvconf(
        &["-a", &resolvconf_owner_tag(), "-m", "17"],
        Some(b"nameserver 192.0.2.251\n"),
    );
    assert_eq!(metric_for_tag(&resolvconf_owner_tag()), Some(17));
    let (manager, _state_dir) =
        pinned_manager("matrix-bsd-existing", BackendKind::Resolvconf).unwrap();
    let active = active_nameserver();
    let config = DnsConfig::builder(DnsScope::Global)
        .nameserver(active)
        .build()
        .unwrap();
    let lease = manager.apply(&config).unwrap();
    lease.restore().unwrap();
    let restored_nameservers = manager
        .snapshot(&DnsScope::Global)
        .unwrap()
        .nameservers()
        .to_vec();
    assert!(restored_nameservers.contains(&ip("192.0.2.251")));
    assert!(restored_nameservers.contains(&active));
    assert_eq!(metric_for_tag(&resolvconf_owner_tag()), Some(17));
    let restored_live = std::fs::read("/etc/resolv.conf").unwrap();
    let restored_text = String::from_utf8_lossy(&restored_live);
    for line in String::from_utf8_lossy(&original_live).lines() {
        if !line.trim().is_empty() {
            assert!(restored_text.lines().any(|candidate| candidate == line));
        }
    }
    assert!(
        restored_text
            .lines()
            .any(|line| line == "nameserver 192.0.2.251")
    );
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
#[test]
fn bsd_openresolv_child_process_helper() {
    let Ok(state) = std::env::var("OSDNS_BSD_CHILD_STATE") else {
        return;
    };
    let server = std::env::var("OSDNS_BSD_CHILD_SERVER").unwrap();
    let manager = manager_for_backend(
        "io.osdns.matrix",
        std::path::Path::new(&state),
        BackendKind::Resolvconf,
        Duration::from_secs(30),
    )
    .unwrap();
    let config = DnsConfig::builder(DnsScope::Global)
        .nameserver(ip(&server))
        .build()
        .unwrap();
    let _lease = manager.apply(&config).unwrap();
    std::fs::write(PathBuf::from(state).join("bsd-child-applied"), b"").unwrap();
    std::process::exit(0);
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
#[test]
fn matrix_bsd_openresolv_crash_recovery() {
    if !mutation_gate_open() {
        return;
    }
    let _guard = bsd_system_guard();
    let _tag = BsdResolvconfTagGuard::new();
    let original_live = std::fs::read("/etc/resolv.conf").unwrap();
    let state = temp_dir("matrix-bsd-recovery");
    let server = active_nameserver().to_string();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "bsd_openresolv_child_process_helper",
            "--test-threads=1",
        ])
        .env("OSDNS_BSD_CHILD_STATE", &state)
        .env("OSDNS_BSD_CHILD_SERVER", &server)
        .spawn()
        .unwrap();
    let ready = state.join("bsd-child-applied");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() && Instant::now() < deadline {
        assert!(
            child.try_wait().unwrap().is_none(),
            "BSD child exited before apply"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(ready.exists(), "BSD child did not finish apply");
    child.wait().unwrap();
    let manager = manager_for_backend(
        "io.osdns.matrix",
        &state,
        BackendKind::Resolvconf,
        Duration::from_secs(30),
    )
    .unwrap();
    let outcomes = manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert!(
        matches!(outcomes[0], osdns::RecoveryOutcome::Restored { .. }),
        "{outcomes:?}"
    );
    assert!(!resolvconf_key_exists(&resolvconf_owner_tag()));
    assert_eq!(std::fs::read("/etc/resolv.conf").unwrap(), original_live);
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
#[test]
fn matrix_bsd_direct_resolv_conf_lifecycle_and_metadata() {
    if !mutation_gate_open() {
        return;
    }
    let _guard = bsd_system_guard();
    let file = BsdResolvFileGuard::new();
    let original = std::fs::read(&file.target).unwrap();
    let original_metadata = std::fs::metadata(&file.target).unwrap();
    let (manager, _state_dir) =
        pinned_manager("matrix-bsd-direct", BackendKind::ResolvConfFile).unwrap();
    let config = DnsConfig::builder(DnsScope::Global)
        .nameserver(ip("192.0.2.10"))
        .search_domain("matrix.test")
        .build()
        .unwrap();
    let lease = manager.apply(&config).unwrap();
    assert!(
        lease.resources()[0]
            .as_str()
            .starts_with(&format!("{}:resolv-conf", std::env::consts::OS))
    );
    let applied = std::fs::metadata(&file.target).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(applied.uid(), original_metadata.uid());
    assert_eq!(applied.gid(), original_metadata.gid());
    assert_eq!(applied.mode() & 0o7777, original_metadata.mode() & 0o7777);
    assert_eq!(applied.nlink(), 1);
    lease.restore().unwrap();
    assert_eq!(std::fs::read(&file.target).unwrap(), original);
    let restored = std::fs::metadata(&file.target).unwrap();
    assert_eq!(restored.uid(), original_metadata.uid());
    assert_eq!(restored.gid(), original_metadata.gid());
    assert_eq!(restored.mode(), original_metadata.mode());
    assert_eq!(restored.nlink(), original_metadata.nlink());
    assert_eq!(
        restored.modified().unwrap(),
        original_metadata.modified().unwrap()
    );
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
#[test]
fn matrix_bsd_direct_resolv_conf_watch_and_external_modification() {
    if !mutation_gate_open() {
        return;
    }
    let _guard = bsd_system_guard();
    let file = BsdResolvFileGuard::new();
    let (manager, _state_dir) =
        pinned_manager("matrix-bsd-direct-watch", BackendKind::ResolvConfFile).unwrap();
    let config = DnsConfig::builder(DnsScope::Global)
        .nameserver(ip("192.0.2.12"))
        .build()
        .unwrap();
    let lease = manager.apply(&config).unwrap();
    let resource = lease.resources()[0].clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let watch = manager
        .watch(Arc::new(move |event| {
            let _ = sender.send(event.clone());
        }))
        .unwrap();
    std::thread::sleep(Duration::from_millis(600));
    std::fs::write(&file.target, b"nameserver 192.0.2.250\n").unwrap();
    #[cfg(target_os = "freebsd")]
    {
        let output = Command::new("chflags")
            .arg("0")
            .arg(&file.target)
            .output()
            .unwrap();
        assert!(output.status.success(), "clear external flags: {output:?}");
    }
    wait_for_event(&receiver, resource.as_str());
    let failure = lease.restore().unwrap_err();
    assert!(failure.error.is_external_modification());
    failure.lease.abandon().unwrap();
    file.restore();
    watch.stop();
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
#[test]
fn matrix_bsd_direct_resolv_conf_refusals_and_absent_restore() {
    if !mutation_gate_open() {
        return;
    }
    let _guard = bsd_system_guard();
    let file = BsdResolvFileGuard::new();
    let (manager, _state_dir) =
        pinned_manager("matrix-bsd-direct-refuse", BackendKind::ResolvConfFile).unwrap();
    let config = DnsConfig::builder(DnsScope::Global)
        .nameserver(ip("192.0.2.11"))
        .build()
        .unwrap();

    std::fs::remove_file(&file.target).unwrap();
    std::os::unix::fs::symlink(&file.backup, &file.target).unwrap();
    let error = manager.apply(&config).unwrap_err();
    assert!(matches!(error, Error::Unsupported { .. }), "{error:?}");
    std::fs::remove_file(&file.target).unwrap();

    file.restore();
    std::fs::write(&file.target, b"# Generated by custom-manager\n").unwrap();
    let error = manager.apply(&config).unwrap_err();
    assert!(matches!(error, Error::Unsupported { .. }), "{error:?}");

    file.restore();
    let flag = if cfg!(target_os = "netbsd") {
        "uappnd"
    } else {
        "uarch"
    };
    let output = Command::new("chflags")
        .args([flag, file.target.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "chflags {flag} failed: {output:?}");
    let error = manager.apply(&config).unwrap_err();
    assert!(matches!(error, Error::Unsupported { .. }), "{error:?}");
    let output = Command::new("chflags")
        .arg("0")
        .arg(file.target.to_str().unwrap())
        .output()
        .unwrap();
    assert!(output.status.success(), "chflags clear failed: {output:?}");

    file.restore();
    std::fs::remove_file(&file.target).unwrap();
    let lease = manager.apply(&config).unwrap();
    lease.restore().unwrap();
    assert!(!file.target.exists());
    file.restore();
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
    let (manager, _state_dir) = match pinned_manager("matrix-win", BackendKind::WindowsIpHelper) {
        Ok(pair) => pair,
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
    let (manager, _state_dir) =
        match pinned_manager("matrix-macos", BackendKind::MacosSystemConfiguration) {
            Ok(pair) => pair,
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
