//! Watch DNS changes with native platform notifications and stop cleanly.
//!
//! The callback only enqueues; mutating APIs must never run inside it.
//! Exits honestly when the backend has no watch support.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use osdns::DnsManager;

fn main() -> osdns::Result<()> {
    let manager = DnsManager::builder().owner("io.example.watch").build()?;

    let caps = manager.capabilities()?;
    println!("backend: {}", caps.backend);
    if !caps.watch {
        println!("change notifications are not supported on this backend; exiting");
        return Ok(());
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let watch = manager.watch(Arc::new(move |event| {
        sink.lock().unwrap().push(format!("{event:?}"));
    }))?;

    // Observe for a moment; external DNS changes during this window surface
    // through the callback. Our own mutations are suppressed.
    std::thread::sleep(Duration::from_secs(2));

    watch.stop();
    println!("observed {} event(s)", events.lock().unwrap().len());
    Ok(())
}
