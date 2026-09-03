# osdns

Transactional control of operating-system DNS configuration.

`osdns` provides a Rust API for reading, applying, watching, reconciling, and restoring host DNS configuration on Linux, Windows, and macOS.

It is intended for VPNs, mesh networks, local DNS proxies, tunnels, security agents, and other software that needs to modify the host resolver without taking ownership of unrelated system state.

`osdns` is not a DNS resolver, DNS server, or DNS protocol implementation.

## Principle

The central invariant is:

> Never overwrite DNS state that is not demonstrably ours.

DNS configuration is shared mutable state. DHCP clients, NetworkManager, systemd-resolved, VPNs, administrators, MDM software, and other processes may modify it while an application is running.

`osdns` therefore treats DNS changes as owned transactions rather than plain setter calls.

A mutation is:

1. locked per resource;
2. captured;
3. journaled;
4. applied;
5. read back and verified;
6. restored only while ownership can still be established.

If another actor changes the resource, `osdns` does not blindly restore an old snapshot.

## Supported platforms

| Platform | Backend                 | DNS                     | Split DNS         | Watching                           |
| -------- | ----------------------- | ----------------------- | ----------------- | ---------------------------------- |
| Linux    | systemd-resolved        | per-link                | routing domains   | D-Bus                              |
| Linux    | NetworkManager          | per-interface           | backend-dependent | D-Bus                              |
| Linux    | resolvconf / openresolv | global                  | limited           | native integration                 |
| Linux    | `/etc/resolv.conf`      | global                  | no                | inotify                            |
| Windows  | IP Helper               | per-interface IPv4/IPv6 | NRPT              | IP Helper + registry notifications |
| macOS    | SystemConfiguration     | per-service             | `/etc/resolver`   | SCDynamicStore + FSEvents          |

Linux backend selection is based on the component that actually owns DNS configuration, not simply on which programs are installed.

Platform capabilities are exposed at runtime through `DnsManager::capabilities()`.

## Usage

```toml
[dependencies]
osdns = "0.1"
```

Create a manager with an application-specific owner identifier:

```rust
use osdns::{DnsManager, DnsScope, InterfaceSelector};

fn main() -> osdns::Result<()> {
    let dns = DnsManager::builder()
        .owner("io.example.agent")
        .build()?;

    let caps = dns.capabilities()?;

    println!("backend: {}", caps.backend);

    let current = dns.snapshot(&DnsScope::Interface(
        InterfaceSelector::Default,
    ))?;

    println!("{current:?}");

    Ok(())
}
```

### Apply DNS configuration

```rust
use osdns::{
    DnsConfig,
    DnsManager,
    DnsScope,
    InterfaceSelector,
};

fn main() -> osdns::Result<()> {
    let dns = DnsManager::builder()
        .owner("io.example.agent")
        .build()?;

    let config = DnsConfig::builder(DnsScope::Interface(
        InterfaceSelector::Default,
    ))
    .nameserver("127.0.0.1".parse().unwrap())
    .build()?;

    dns.validate(&config)?;

    let lease = dns.apply(&config)?;

    // The DNS configuration remains owned by this lease.

    lease.restore()?;

    Ok(())
}
```

`apply()` returns a `Lease`. The lease owns every OS resource modified by that operation and holds the corresponding inter-process locks for its lifetime.

`restore()` is explicit and is the preferred way to release a lease.

Dropping a lease performs best-effort restoration, but correctness does not depend on `Drop`.

## Split DNS

Routing domains are part of the platform-neutral configuration model:

```rust
let config = DnsConfig::builder(DnsScope::Interface(
    InterfaceSelector::Default,
))
.nameserver("100.64.0.53".parse()?)
.routing_domain("corp.example")
.routing_domain("internal.example")
.build()?;
```

The exact mechanism depends on the active backend:

* systemd-resolved routing domains on Linux;
* NetworkManager DNS routing where supported;
* NRPT rules on Windows;
* scoped `/etc/resolver/<domain>` resolvers on macOS.

Unsupported configurations are rejected before mutation.

## Restoring safely

Consider the following sequence:

```text
original:   1.1.1.1
osdns:      127.0.0.1
external:   9.9.9.9
```

A naive DNS manager may restore `1.1.1.1` and destroy the external change.

`osdns` compares the current state with the exact state applied by the lease.

If the current state is no longer ours, restoration fails with `Error::ExternalModification` and does not modify the resource.

```rust
match lease.restore() {
    Ok(()) => {}

    Err(failure) if failure.error.is_external_modification() => {
        // The machine has been changed by another actor.
        //
        // Keep the lease to retry restoration, or abandon our ownership
        // claim and leave the external state untouched.
        failure.lease.abandon()?;
    }

    Err(failure) => return Err(failure.error),
}
```

## Crash recovery

Mutations are backed by a durable journal.

The transaction order is:

```text
capture
  ↓
write Prepared
  ↓
fsync
  ↓
apply
  ↓
read back
  ↓
verify
  ↓
write Applied
  ↓
fsync
```

A process crash may release an OS lock without removing its journal.

Stale transactions can be inspected and recovered with:

```rust
let outcomes = dns.recover_stale()?;

for outcome in outcomes {
    println!("{outcome:?}");
}
```

Recovery never guesses ownership.

If current state no longer matches either side of a recorded transaction, the resource is reported as an external conflict and left untouched.

Unknown or corrupt journal formats fail closed.

## External changes

Two conflict policies are available.

### Cooperative

The default.

```rust
use osdns::ConflictPolicy;

let dns = DnsManager::builder()
    .owner("io.example.agent")
    .conflict_policy(ConflictPolicy::Cooperative)
    .build()?;
```

External modifications are never automatically overwritten.

### Enforce

For software such as active VPN, mesh, and tunnel agents:

```rust
let dns = DnsManager::builder()
    .owner("io.example.agent")
    .conflict_policy(ConflictPolicy::Enforce)
    .build()?;
```

When watching is active, external changes to resources owned by a live lease are reconciled.

The reconciler:

* waits for stable authoritative state;
* coalesces repeated events;
* distinguishes our own changes from external changes by read-back;
* rebases the lease onto the new external state;
* reapplies the desired overlay transactionally;
* updates the durable journal;
* uses bounded retries and a feedback-loop circuit breaker.

Restoring a rebased lease returns to the new external base, not the state that existed when the original lease was created.

Reconciliation only runs when `watch()` is active.

## Watching

```rust
use std::sync::Arc;

let watch = dns.watch(Arc::new(|event| {
    println!("{event:?}");
}))?;

// ...

watch.stop();
```

Watchers use native platform notifications.

`osdns` does not poll DNS configuration.

Events generated by our own mutations are suppressed from the user callback path. Under `ConflictPolicy::Enforce`, reconciliation still receives the event and verifies authoritative state before deciding whether it is ours.

## Updating a lease

A live lease can change its desired configuration without releasing ownership:

```rust
let lease = dns.apply(&first)?;

lease.update(&second)?;

lease.restore()?;
```

An update cannot silently change the set of OS resources owned by the lease.

## Capabilities

Platform behavior is not artificially flattened.

```rust
let caps = dns.capabilities()?;

if caps.split_dns {
    // routing domains are available on this backend
}
```

Available capability flags include:

```text
read
global_dns
per_interface_dns
search_domains
split_dns
watch
cache_flush
```

Applications should use capabilities when behavior depends on a platform-specific facility.

## Privileges

Changing system DNS usually requires elevated privileges.

`osdns` never attempts privilege escalation.

Insufficient permissions are returned as:

```rust
Error::RequiresPrivilege(...)
```

The caller is responsible for running the process with the appropriate OS privileges.

## Runtime

`osdns` has no async runtime dependency.

It does not require Tokio or async-std.

Configuration changes are control-plane operations. Native blocking APIs are used where appropriate, and native watcher threads are started only when watching is requested.

Primary backends do not shell out.

The `resolvconf` / `openresolv` fallback invokes the corresponding utility directly when that backend is selected.

## Features

The default feature set is empty.

```toml
osdns = { version = "0.1", features = ["tracing"] }
```

### `tracing`

Enables integration with the `tracing` ecosystem.

### `test-util`

Exposes the in-memory backend and fault-injection utilities used to test applications built on `osdns`.

It is intended for tests, not production builds.

## Testing

The transaction engine is tested independently of the OS through an in-memory backend with failure injection.

The test suite covers, among other cases:

* crashes between transaction phases;
* journal write failures;
* failed rollback;
* external modification during a lease;
* multi-process ownership;
* stale lease recovery;
* concurrent resource acquisition;
* event storms;
* DHCP-style file replacement;
* reconciliation rebasing;
* watcher suppression;
* Windows NRPT ownership;
* macOS scoped resolver lifecycle.

Real backend integration tests run on Linux, Windows, and macOS.

CI also checks:

```text
cargo test
cargo clippy
cargo fmt
cargo doc
cargo audit
cargo deny
cargo hack
```

The declared MSRV is tested separately.

## MSRV

The minimum supported Rust version is:

```text
1.89
```

The crate uses Rust edition 2024.

## Safety

Platform FFI is isolated in platform-specific modules.

The crate enables:

```rust
#![deny(unsafe_op_in_unsafe_fn)]
```

Unsafe operations require explicit safety justification.

DNS configuration alone is not a DNS leak-prevention mechanism. Applications that require enforced traffic isolation must separately control routing and firewall policy.

## License

Licensed under either of:

* Apache License, Version 2.0
* MIT License

at your option.
