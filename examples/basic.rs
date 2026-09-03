//! Basic usage: inspect capabilities, apply DNS, restore the lease.
//!
//! Run with whatever privileges the platform requires for DNS mutation.
//! Without them, `apply` returns `Error::RequiresPrivilege` and nothing is
//! mutated.

use osdns::{DnsConfig, DnsManager, DnsScope, InterfaceSelector};

fn main() -> osdns::Result<()> {
    let manager = DnsManager::builder().owner("io.example.basic").build()?;

    let caps = manager.capabilities()?;
    println!("backend: {}", caps.backend);

    if !caps.per_interface_dns && !caps.global_dns {
        println!("no configurable DNS scope on this backend; exiting");
        return Ok(());
    }

    // Prefer per-interface configuration where supported; fall back to the
    // global scope on backends without it.
    let scope = if caps.per_interface_dns {
        DnsScope::Interface(InterfaceSelector::Default)
    } else {
        DnsScope::Global
    };

    let current = manager.snapshot(&scope)?;
    println!("current nameservers: {:?}", current.nameservers());

    let config = DnsConfig::builder(scope)
        .nameserver("127.0.0.1".parse().unwrap())
        .build()?;
    manager.validate(&config)?;

    match manager.apply(&config) {
        Ok(lease) => {
            println!("applied; owned resources: {:?}", lease.resources());
            lease.restore()?;
            println!("restored");
        }
        Err(osdns::Error::RequiresPrivilege(detail)) => {
            println!("requires elevated privileges: {detail}");
        }
        Err(osdns::Error::Unsupported { backend, reason }) => {
            println!("unsupported on {backend}: {reason}");
        }
        Err(error) => return Err(error),
    }
    Ok(())
}
