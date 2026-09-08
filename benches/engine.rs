//! Control-plane benchmarks: snapshot, no-op apply, full apply+verify, and
//! restore cycles against the fake backend. DNS configuration is an
//! infrequent control plane, so these measure low-overhead determinism, not
//! packet throughput.

#![cfg(feature = "test-util")]
#![allow(missing_docs)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

use osdns::testing::{FakeDns, manager_for_testing};
use osdns::{DnsConfig, DnsScope, InterfaceSelector};

fn bench_manager(dir: &std::path::Path) -> osdns::DnsManager {
    let fake = FakeDns::new();
    manager_for_testing("io.osdns.bench", dir, &fake, Duration::from_secs(30)).unwrap()
}

fn config(ns: &str) -> DnsConfig {
    DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Index(1)))
        .nameserver(ns.parse().unwrap())
        .build()
        .unwrap()
}

fn bench_snapshot(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let manager = bench_manager(dir.path());
    c.bench_function("snapshot", |b| {
        b.iter(|| {
            let state = manager.snapshot(&DnsScope::Interface(InterfaceSelector::Index(1)));
            black_box(state).unwrap();
        })
    });
}

fn bench_noop_apply(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let manager = bench_manager(dir.path());
    let config = config("1.1.1.1");
    {
        let lease = manager.apply(&config).unwrap();
        lease.restore().unwrap();
    }
    c.bench_function("noop_apply", |b| {
        b.iter(|| {
            let lease = manager.apply(black_box(&config)).unwrap();
            black_box(lease.is_noop());
        })
    });
}

fn bench_apply_verify_restore(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let manager = bench_manager(dir.path());
    c.bench_function("apply_verify_restore", |b| {
        b.iter(|| {
            let lease = manager.apply(black_box(&config("1.1.1.1"))).unwrap();
            black_box(&lease);
            lease.restore().unwrap();
        })
    });
}

fn bench_alternating_updates(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let manager = bench_manager(dir.path());
    let lease = manager.apply(&config("1.1.1.1")).unwrap();
    let mut toggle = false;
    c.bench_function("alternating_update", |b| {
        b.iter(|| {
            toggle = !toggle;
            let next = if toggle { "8.8.8.8" } else { "1.1.1.1" };
            lease.update(black_box(&config(next))).unwrap();
        })
    });
    lease.restore().unwrap();
}

criterion_group!(
    benches,
    bench_snapshot,
    bench_noop_apply,
    bench_apply_verify_restore,
    bench_alternating_updates
);
criterion_main!(benches);
