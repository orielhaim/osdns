//! Multi-process ownership tests: real OS processes contending for the same
//! resource locks and journals.
//!
//! Child scenarios run in the same test binary via `--exact`, selected with
//! `OSDNS_CHILD_CASE`; children exit through `std::process::exit` so no Drop
//! cleanup runs, simulating a crashed agent.

#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::testing::manager_for_testing;
use osdns::{DnsManager, RecoveryOutcome};
use std::process::Command;
use std::time::Duration;

fn spawn_child(case: &str, state_dir: &std::path::Path) -> std::process::Child {
    let exe = std::env::current_exe().unwrap();
    Command::new(exe)
        .args(["--exact", "child_process_helper", "--test-threads=1"])
        .env("OSDNS_CHILD_CASE", case)
        .env("OSDNS_STATE_DIR", state_dir)
        .spawn()
        .expect("spawn child process")
}

fn child_mode() -> Option<String> {
    std::env::var("OSDNS_CHILD_CASE").ok()
}

fn child_manager(state_dir: &std::path::Path) -> DnsManager {
    let fake = FakeDns::new();
    manager_for_testing("io.osdns.child", state_dir, &fake, Duration::from_secs(10)).unwrap()
}

#[test]
fn child_process_helper() {
    let Some(case) = child_mode() else { return };
    let dir = std::path::PathBuf::from(std::env::var("OSDNS_STATE_DIR").unwrap());
    let manager = child_manager(&dir);
    match case.as_str() {
        "crash" => {
            let _lease = manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
            std::fs::write(dir.join("child-applied"), b"").unwrap();
            std::process::exit(0);
        }
        "hold" => {
            let _lease = manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
            std::fs::write(dir.join("child-applied"), b"").unwrap();
            std::thread::sleep(Duration::from_secs(2));
            drop(_lease);
            std::process::exit(0);
        }
        _ => panic!("unknown child case {case}"),
    }
}

fn wait_for_file(dir: &std::path::Path, name: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if dir.join(name).exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("child never signalled readiness ({name})");
}

#[test]
fn crashed_process_journal_survives_and_recovers() {
    let dir = temp_dir("mp-crash");
    let mut child = spawn_child("crash", &dir);
    wait_for_file(&dir, "child-applied");
    let _ = child.wait();

    let fake = FakeDns::new();
    let manager =
        manager_for_testing("io.osdns.parent", &dir, &fake, Duration::from_secs(30)).unwrap();
    let outcomes = manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert!(
        matches!(&outcomes[0], RecoveryOutcome::JournalCleared { .. }),
        "the journal written by the crashed child must survive the process exit \
         and be cleared: the parent's OS state matches the child's recorded before-state, \
         so nothing of the child's overlay exists here: {outcomes:?}"
    );
    assert_eq!(
        fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
    assert!(journal_files(&dir).is_empty());
}

#[test]
fn live_process_excludes_other_processes() {
    let dir = temp_dir("mp-hold");
    let mut child = spawn_child("hold", &dir);
    wait_for_file(&dir, "child-applied");
    std::thread::sleep(Duration::from_millis(200));

    let fake = FakeDns::new();
    let manager =
        manager_for_testing("io.osdns.parent", &dir, &fake, Duration::from_millis(300)).unwrap();
    let error = manager.apply(&iface_config(1, "8.8.8.8")).unwrap_err();
    assert!(
        matches!(
            error,
            osdns::Error::Timeout { .. } | osdns::Error::Conflict { .. }
        ),
        "the child's live lease must exclude the parent: {error:?}"
    );

    let outcomes = manager.recover_stale().unwrap();
    assert!(
        outcomes.iter().any(
            |o| matches!(o, RecoveryOutcome::Busy { resource } if *resource == resource_id(IFACE1))
        ),
        "a live lease must be reported as busy, never touched: {outcomes:?}"
    );

    let _ = child.wait();
    let lease = manager.apply(&iface_config(1, "8.8.8.8")).unwrap();
    lease.restore().unwrap();
}

#[test]
fn concurrent_starts_serialize_across_processes() {
    let dir = temp_dir("mp-race");
    let mut children = Vec::new();
    for _ in 0..2 {
        children.push(spawn_child("hold", &dir));
    }
    std::thread::sleep(Duration::from_millis(300));

    let fake = FakeDns::new();
    let manager =
        manager_for_testing("io.osdns.parent", &dir, &fake, Duration::from_millis(250)).unwrap();
    let error = manager.apply(&iface_config(1, "1.1.1.1")).unwrap_err();
    assert!(matches!(
        error,
        osdns::Error::Timeout { .. } | osdns::Error::Conflict { .. }
    ));
    for child in &mut children {
        let _ = child.wait();
    }
    let lease = manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    lease.restore().unwrap();
}
