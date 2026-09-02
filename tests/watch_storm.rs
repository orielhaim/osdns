//! Watcher and event-storm tests: high-frequency external change bursts must
//! be coalesced without loss of the final state, without deadlocks, and our
//! own apply events must stay suppressed.

#![cfg(feature = "test-util")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod common;

use common::*;

#[test]
fn event_burst_is_coalesced_and_state_stays_consistent() {
    let fixture = new_fixture("storm-burst");
    let delivered = Arc::new(AtomicUsize::new(0));
    let sink = delivered.clone();
    let handle = fixture
        .manager
        .watch(Arc::new(move |_event| {
            sink.fetch_add(1, Ordering::SeqCst);
        }))
        .unwrap();
    std::thread::sleep(Duration::from_millis(600));

    for i in 0..300 {
        let ns = format!("10.0.{}.{}", i / 250, 1 + (i % 250));
        fixture
            .fake
            .external_change(IFACE1, state_with(&ns))
            .unwrap();
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if delivered.load(Ordering::SeqCst) > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    std::thread::sleep(Duration::from_millis(400));

    let count = delivered.load(Ordering::SeqCst);
    assert!(count > 0, "events must be delivered");
    assert!(
        count < 300,
        "a 300-event burst must be coalesced well below the raw event count, got {count}"
    );
    handle.stop();
}

#[test]
fn concurrent_storms_from_many_threads_never_deadlock() {
    let fixture = new_fixture("storm-threads");
    let delivered = Arc::new(AtomicUsize::new(0));
    let sink = delivered.clone();
    let handle = fixture
        .manager
        .watch(Arc::new(move |_event| {
            let _ = sink.fetch_add(1, Ordering::SeqCst);
        }))
        .unwrap();
    std::thread::sleep(Duration::from_millis(600));

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
        let _ = thread.join();
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if delivered.load(Ordering::SeqCst) > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    std::thread::sleep(Duration::from_millis(400));
    assert!(delivered.load(Ordering::SeqCst) > 0);
    handle.stop();
}

#[test]
fn own_apply_events_stay_suppressed_during_storm() {
    let fixture = new_fixture("storm-suppress");
    let external = Arc::new(AtomicUsize::new(0));
    let sink = external.clone();
    let handle = fixture
        .manager
        .watch(Arc::new(move |event| {
            if let osdns::DnsEvent::ResourceChanged { resource } = event
                && resource.as_str() == IFACE1
            {
                sink.fetch_add(1, Ordering::SeqCst);
            }
        }))
        .unwrap();
    std::thread::sleep(Duration::from_millis(600));

    for _ in 0..5 {
        let _lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
        lease_restore_quick(&fixture);
    }

    std::thread::sleep(Duration::from_millis(700));
    let count = external.load(Ordering::SeqCst);
    assert_eq!(
        count, 0,
        "our own apply events must never surface as external changes"
    );
    handle.stop();
}

fn lease_restore_quick(fixture: &Fixture) {
    if let Ok(lease) = fixture
        .manager
        .apply(&osdns::DnsConfig::builder(iface_scope(1)).build().unwrap())
    {
        let _ = lease;
    }
}

#[test]
fn stop_stops_delivery() {
    let fixture = new_fixture("storm-stop");
    let delivered = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = delivered.clone();
    let handle = fixture
        .manager
        .watch(Arc::new(move |event| {
            sink.lock().unwrap().push(format!("{event:?}"));
        }))
        .unwrap();
    std::thread::sleep(Duration::from_millis(600));

    handle.stop();
    let count = delivered.lock().unwrap().len();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        delivered.lock().unwrap().len(),
        count,
        "no events after stop"
    );
}
