//! Split DNS: route selected domains through our nameserver.
//!
//! Checks `Capabilities::split_dns` first and exits honestly on backends
//! without split-DNS support. Requires elevated privileges like any mutation.

use osdns::{DnsConfig, DnsManager, DnsScope, InterfaceSelector};

fn main() -> osdns::Result<()> {
    let manager = DnsManager::builder()
        .owner("io.example.split-dns")
        .build()?;

    let caps = manager.capabilities()?;
    println!("backend: {}", caps.backend);

    if !caps.split_dns {
        println!("split DNS is not supported on this backend; exiting");
        return Ok(());
    }
    if !caps.per_interface_dns {
        println!("per-interface DNS is not supported on this backend; exiting");
        return Ok(());
    }

    let config = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Default))
        .nameserver("100.64.0.53".parse().unwrap())
        .routing_domain("corp.example")
        .routing_domain("internal.example")
        .build()?;
    manager.validate(&config)?;

    match manager.apply(&config) {
        Ok(lease) => {
            println!("split DNS applied; resources: {:?}", lease.resources());
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
