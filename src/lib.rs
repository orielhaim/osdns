#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![warn(clippy::all)]

//! `osdns` is a transaction and ownership engine that can safely control
//! host DNS state on real operating systems while coexisting with every
//! other actor on the machine.
//!
//! # The ownership invariant
//!
//! > We never destroy DNS state that we do not own.
//!
//! Every mutation belongs to an explicit owner, lease, and resource. Every
//! mutation is journaled before it happens, verified by read-back, and can
//! be undone — unless an external actor (DHCP, NetworkManager, another VPN,
//! the user) changed the state in the meantime, in which case nothing is
//! touched and [`Error::ExternalModification`] is returned.
//!
//! # Example shape
//!
//! ```no_run
//! use osdns::{DnsConfig, DnsManager, DnsScope};
//!
//! # fn main() -> osdns::Result<()> {
//! let manager = DnsManager::builder()
//!     .owner("io.tunnet.agent")
//!     .build()?;
//!
//! let caps = manager.capabilities()?;
//! let current = manager.snapshot(&DnsScope::Global)?;
//!
//! let config = DnsConfig::builder(DnsScope::Global)
//!     .nameserver("127.0.0.1".parse().unwrap())
//!     .search_domains(["corp.example"])
//!     .build()?;
//! manager.validate(&config)?;
//!
//! let lease = manager.apply(&config)?;
//! // ... later, when the tunnel goes down:
//! lease.restore()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Status
//!
//! **Phase 1 — the core state engine** — is complete: the configuration
//! model, normalization, capability model, resource locking, durable
//! journal, transaction state machine, compare-before-restore, crash
//! recovery, and failure injection, proven against an in-memory backend
//! (`test-util` feature).
//!
//! **Phase 2 — Linux** — adds real backends for systemd-resolved (per-link
//! DNS, routing domains, default route via `org.freedesktop.resolve1`),
//! NetworkManager (transient `GetAppliedConnection`/`Reapply` of DNS fields
//! only), resolvconf/openresolv (owner-tagged records), and direct
//! `/etc/resolv.conf` (symlink refusal, exact-byte snapshots), with
//! ownership-based backend detection and native D-Bus/inotify watchers.
//!
//! **Phase 3 — Windows** — adds the modern IP Helper backend
//! (`GetInterfaceDnsSettings`/`SetInterfaceDnsSettings`, Windows 10 19041+)
//! with explicit IPv4/IPv6 stacks, additive owner-marked NRPT rules with
//! deterministic registry keys, `NotifyIpInterfaceChange` and
//! `RegNotifyChangeKeyValue` watchers, and best-effort `DnsFlushResolverCache`.
//!
//! **Phase 4 — macOS** — adds the SystemConfiguration backend (runtime
//! `State:` DNS dictionaries with full-dictionary capture and preservation)
//! plus scoped `/etc/resolver/<domain>` files, one journal resource per
//! routing domain, with exact per-file ownership markers: a resolver file
//! written by another owner is never overwritten. Watchers use
//! `SCDynamicStore` notifications on a dedicated run-loop thread. All three
//! primary platforms are now supported.
//!
//! **Phase 5 — hardening** — completes the architecture: `ConflictPolicy::Enforce`
//! reconciliation (stability detection, rate limiting, a feedback-loop
//! circuit breaker, journal rebasing), Windows NRPT rules as their own
//! transactionally-owned resources, native FSEvents watching of
//! `/etc/resolver`, multi-process crash/lock tests, destructive race tests,
//! event-storm and allocation-budget tests, criterion benchmarks, and the
//! CI matrix (fmt/clippy/test/doc on all three OSes, cross-target checks,
//! feature powerset, cargo-deny, cargo-audit).

#[macro_use]
mod macros;

/// Backend capability model: what each platform backend can guarantee.
pub mod capability;
/// Platform-neutral DNS configuration model with validated builders.
pub mod config;
/// The typed error model.
pub mod error;
/// Network interface information.
pub mod interface;
/// Leases: exclusive, transactional ownership over DNS state.
pub mod lease;
/// The [`DnsManager`] entry point and builder.
pub mod manager;
/// [`DnsSuffix`] normalization and the normalized configuration form.
pub mod normalize;
/// Resource identifiers and inter-process resource locking.
pub mod ownership;
/// Watch events and handles.
pub mod watch;

#[cfg(feature = "test-util")]
pub mod testing;

mod fault;
mod fsutil;
mod journal;
mod platform;
mod reconciliation;

pub use capability::{BackendKind, Capabilities};
pub use config::{DnsConfig, DnsConfigBuilder, DnsScope, InterfaceSelector};
pub use error::{ConflictReason, Error, Result};
pub use interface::InterfaceInfo;
pub use lease::{Lease, RestoreFailure};
pub use manager::{ConflictPolicy, DnsManager, DnsManagerBuilder, RecoveryOutcome};
pub use normalize::DnsSuffix;
pub use ownership::ResourceId;
pub use watch::{DnsEvent, WatchCallback, WatchHandle};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DnsManager>();
        assert_send_sync::<Lease>();
        assert_send_sync::<Error>();
        assert_send_sync::<DnsConfig>();
        assert_send_sync::<DnsSuffix>();
        assert_send_sync::<ResourceId>();
    }
}
