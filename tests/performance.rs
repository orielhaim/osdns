//! Allocation-budget tests: repeated control-plane operations must not grow
//! allocations over time, and per-operation allocation counts must stay
//! within generous fixed budgets that catch gross regressions.
//!
//! The counting allocator is process-global, so every test serializes on a
//! shared mutex to keep counts isolated from concurrently running tests.

#![cfg(feature = "test-util")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::SeqCst);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::SeqCst);
        // SAFETY: forwards to the system allocator with the caller's layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the pointer was produced by System.alloc with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn count_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

mod common;

use common::*;

fn count<F: FnOnce()>(f: F) -> (usize, usize) {
    let before_calls = ALLOC_CALLS.load(Ordering::SeqCst);
    let before_bytes = ALLOC_BYTES.load(Ordering::SeqCst);
    f();
    (
        ALLOC_CALLS.load(Ordering::SeqCst) - before_calls,
        ALLOC_BYTES.load(Ordering::SeqCst) - before_bytes,
    )
}

#[test]
fn snapshot_allocation_budget() {
    let _isolation = count_lock();
    let fixture = new_fixture("perf-snapshot");
    let _lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let (calls, bytes) = count(|| {
        for _ in 0..100 {
            let _ = fixture.manager.snapshot(&iface_scope(1)).unwrap();
        }
    });
    let per_op_calls = calls / 100;
    let per_op_bytes = bytes / 100;
    assert!(
        per_op_calls < 2_000,
        "snapshot allocates {per_op_calls} calls per op (budget 2000)"
    );
    assert!(
        per_op_bytes < 200_000,
        "snapshot allocates {per_op_bytes} bytes per op (budget 200k)"
    );
}

#[test]
fn noop_apply_allocation_budget() {
    let _isolation = count_lock();
    let fixture = new_fixture("perf-noop");
    fixture
        .fake
        .external_change(IFACE1, state_with("1.1.1.1"))
        .unwrap();
    let config = iface_config(1, "1.1.1.1");
    let (calls, bytes) = count(|| {
        for _ in 0..100 {
            let lease = fixture.manager.apply(&config).unwrap();
            assert!(lease.is_noop());
        }
    });
    let per_op_calls = calls / 100;
    let per_op_bytes = bytes / 100;
    assert!(
        per_op_calls < 2_000,
        "no-op apply allocates {per_op_calls} calls per op (budget 2000)"
    );
    assert!(
        per_op_bytes < 200_000,
        "no-op apply allocates {per_op_bytes} bytes per op (budget 200k)"
    );
}

#[test]
fn repeated_real_updates_stay_in_budget() {
    let _isolation = count_lock();
    let fixture = new_fixture("perf-update");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let (_, first_bytes) = count(|| lease.update(&iface_config(1, "8.8.8.8")).unwrap());
    for i in 0..50 {
        let ns = if i % 2 == 0 { "1.1.1.1" } else { "8.8.8.8" };
        let (calls, bytes) = count(|| lease.update(&iface_config(1, ns)).unwrap());
        assert!(
            calls < 20_000,
            "update allocates {calls} calls per op (budget 20000)"
        );
        assert!(
            bytes < 2_000_000,
            "update allocates {bytes} bytes per op (budget 2MB, journal JSON dominates)"
        );
        let _ = first_bytes;
    }
    lease.restore().unwrap();
}
