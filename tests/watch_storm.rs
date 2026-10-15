//! Watcher and event-storm tests: high-frequency external change bursts must
//! be coalesced without loss of the final state, without deadlocks, and our
//! own apply events must stay suppressed.

#![cfg(feature = "test-util")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

mod common;

use common::*;

#[test]
fn concurrent_storms_from_many_threads_never_deadlock() {
    let fixture = new_fixture("storm-threads");
    let (sender, receiver) = std::sync::mpsc::channel();
    let handle = fixture
        .manager
        .watch(Arc::new(move |_event| {
            sender.send(()).unwrap();
        }))
        .unwrap();

    let mut threads = Vec::new();
    for t in 0..4 {
        let fake = fixture.fake.clone();
        threads.push(std::thread::spawn(move || {
            for i in 0..100 {
                let ns = format!("10.{t}.0.{}", 1 + (i % 200));
                fake.external_change(IFACE1, state_with(&ns)).unwrap();
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }

    receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    handle.stop();
}

#[test]
fn own_apply_and_restore_events_are_suppressed() {
    let fixture = new_fixture("watch-suppress");
    let (sender, receiver) = std::sync::mpsc::channel();
    let handle = fixture
        .manager
        .watch(Arc::new(move |event| {
            sender.send(event.clone()).unwrap();
        }))
        .unwrap();
    for _ in 0..5 {
        let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
        lease.restore().unwrap();
    }
    fixture
        .fake
        .external_change(IFACE2, state_with("9.9.9.9"))
        .unwrap();
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
        osdns::DnsEvent::ResourceChanged {
            resource: resource_id(IFACE2)
        }
    );
    assert!(
        receiver.recv_timeout(Duration::from_millis(200)).is_err(),
        "own events must be suppressed"
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
    handle.stop();
}

#[test]
fn stop_waits_for_an_in_flight_callback() {
    let fixture = new_fixture("storm-stop-in-flight");
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release_rx = Arc::new(Mutex::new(release_rx));
    let handle = fixture
        .manager
        .watch(Arc::new(move |_| {
            let _ = entered_tx.send(());
            let _ = release_rx.lock().unwrap().recv();
        }))
        .unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let (stopped_tx, stopped_rx) = std::sync::mpsc::channel();
    let stopper = std::thread::spawn(move || {
        handle.stop();
        stopped_tx.send(()).unwrap();
    });
    assert!(stopped_rx.recv_timeout(Duration::from_millis(100)).is_err());
    release_tx.send(()).unwrap();
    stopped_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    stopper.join().unwrap();
}
#[test]
fn external_change_during_a_recent_mutation_is_visible() {
    let fixture = new_fixture("watch-recent-external");
    let (sender, receiver) = std::sync::mpsc::channel();
    let watch = fixture
        .manager
        .watch(Arc::new(move |event| {
            sender.send(event.clone()).unwrap();
        }))
        .unwrap();
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let event = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(
        matches!(event, osdns::DnsEvent::ResourceChanged { resource } if resource.as_str() == IFACE1)
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
    watch.stop();
    lease.abandon().unwrap();
}

#[test]
fn callback_can_stop_its_own_subscription() {
    let fixture = new_fixture("watch-self-stop");
    let holder = Arc::new(Mutex::new(None::<osdns::WatchHandle>));
    let callback_holder = Arc::clone(&holder);
    let (done, completed) = std::sync::mpsc::channel();
    let watch = fixture
        .manager
        .watch(Arc::new(move |_| {
            if let Some(handle) = callback_holder.lock().unwrap().take() {
                handle.stop();
                done.send(()).unwrap();
            }
        }))
        .unwrap();
    *holder.lock().unwrap() = Some(watch);
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    completed.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(holder.lock().unwrap().is_none());
}
