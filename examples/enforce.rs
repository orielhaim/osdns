//! Enforce mode: reconcile external changes while watching is active.
//!
//! Reconciliation only operates while `watch()` is active. Without a watch,
//! `ConflictPolicy::Enforce` behaves like `Cooperative`: conflicts surface as
//! `Error::ExternalModification` and nothing is overwritten. Requires
//! elevated privileges like any mutation.

use std::sync::Arc;
use std::time::Duration;

use osdns::{ConflictPolicy, DnsConfig, DnsManager, DnsScope, InterfaceSelector};

fn main() -> osdns::Result<()> {
    let manager = DnsManager::builder()
        .owner("io.example.enforce")
        .conflict_policy(ConflictPolicy::Enforce)
        .build()?;

    let caps = manager.capabilities()?;
    println!("backend: {}", caps.backend);
    if !caps.per_interface_dns {
        println!("per-interface DNS is not supported on this backend; exiting");
        return Ok(());
    }

    let config = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Default))
        .nameserver("127.0.0.1".parse().unwrap())
        .build()?;
    manager.validate(&config)?;

    // The watch must stay alive for reconciliation to run.
    let _watch = if caps.watch {
        Some(manager.watch(Arc::new(|event| println!("event: {event:?}")))?)
    } else {
        println!("watch unsupported; continuing without reconciliation");
        None
    };

    match manager.apply(&config) {
        Ok(lease) => {
            println!("applied under Enforce; resources: {:?}", lease.resources());
            std::thread::sleep(Duration::from_secs(1));
            match lease.restore() {
                Ok(()) => println!("restored"),
                Err(failure) if failure.error.is_external_modification() => {
                    println!("externally modified; abandoning ownership claim");
                    failure.lease.abandon()?;
                }
                Err(failure) => return Err(failure.error),
            }
        }
        Err(osdns::Error::RequiresPrivilege(detail)) => {
            println!("requires elevated privileges: {detail}");
        }
        Err(error) => return Err(error),
    }
    Ok(())
}
