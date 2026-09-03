#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![warn(clippy::all)]

//! `osdns` provides transactional, ownership-safe control over host
//! operating-system DNS configuration on Linux, Windows, and macOS.
//!
//! It is intended for VPN clients, mesh networks, local DNS proxies, tunnels,
//! security agents, and other software that must modify the host resolver
//! without taking ownership of unrelated system state.
//!
//! `osdns` is not a DNS resolver, DNS server, or DNS protocol library. It
//! configures the operating system's resolver; it does not implement DNS
//! itself.
//!
//! # Ownership invariant
//!
//! > Never overwrite DNS state that is not demonstrably ours.
//!
//! DNS configuration is shared mutable state. DHCP clients, NetworkManager,
//! systemd-resolved, other VPN software, administrators, and device-management
//! tooling may change it at any time.
//!
//! Every mutation therefore belongs to an explicit owner and [`Lease`], is
//! journaled before it happens, is verified by read-back, and is restored
//! only while ownership can still be established. When another actor has
//! changed the state, restoration fails with
//! [`Error::ExternalModification`] and nothing is mutated.
//!
//! # Basic usage
//!
//! ```no_run
//! use osdns::{DnsConfig, DnsManager, DnsScope, InterfaceSelector};
//!
//! # fn main() -> osdns::Result<()> {
//! let manager = DnsManager::builder()
//!     .owner("io.example.agent")
//!     .build()?;
//!
//! let config = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Default))
//!     .nameserver("127.0.0.1".parse().unwrap())
//!     .build()?;
//!
//! manager.validate(&config)?;
//! let lease = manager.apply(&config)?;
//!
//! // The configuration stays in effect while the lease is alive.
//! lease.restore()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Leases
//!
//! [`DnsManager::apply`] returns a [`Lease`]. The lease owns every OS resource
//! modified by that operation and holds the corresponding inter-process locks
//! for its lifetime.
//!
//! [`Lease::restore`] is the canonical way to end a lease. Dropping a lease
//! performs best-effort restoration, but correctness never depends on `Drop`:
//! a crashed process is recovered through
//! [`DnsManager::recover_stale`].
//!
//! A live lease can move to a new desired configuration with
//! [`Lease::update`] without releasing ownership. An update cannot silently
//! change the set of owned resources.
//!
//! # Safe restoration
//!
//! Restoration is compare-before-restore per resource. The current state is
//! only overwritten when it still matches the state the lease applied (or the
//! original state, in which case nothing needs to happen). Otherwise
//! [`Error::ExternalModification`] is returned, nothing is mutated, and the
//! lease remains usable so the caller can retry or call
//! [`Lease::abandon`] to leave the external state untouched.
//!
//! # Crash recovery
//!
//! Mutations are backed by a durable journal. The transaction order is:
//!
//! ```text
//! capture -> write Prepared -> fsync -> apply -> read back -> verify
//!   -> write Applied -> fsync
//! ```
//!
//! A process crash may release an OS lock without removing its journal.
//! [`DnsManager::recover_stale`] inspects records left behind by crashed or
//! exited processes and recovers them where it is safe to do so. Recovery
//! never guesses ownership: when current state matches neither the recorded
//! applied state nor the original state, the resource is reported as
//! [`RecoveryOutcome::ExternalConflict`] and left untouched. Unknown or
//! corrupt journal formats fail closed with [`Error::JournalCorrupt`].
//!
//! # Validation guarantee
//!
//! [`DnsManager::validate`] success means the backend can faithfully
//! represent every explicitly requested semantic. A backend never silently
//! ignores a requested field: unsupported semantics fail with
//! [`Error::Unsupported`] before any lock, journal write, or OS mutation.
//! The pipeline is structural validation, then generic capability checks,
//! then backend-specific semantic validation.
//!
//! # Optional fields
//!
//! `None` means preserve / leave unspecified, never implicitly `false` or
//! empty. In particular, `default_route = None` preserves the current
//! default-route value on every backend; only `Some(true)` / `Some(false)`
//! may change it.
//!
//! # Cooperative vs Enforce
//!
//! [`ConflictPolicy::Cooperative`] (the default) never overwrites externally
//! changed state automatically; conflicts are surfaced to the lease owner.
//!
//! [`ConflictPolicy::Enforce`] is for active VPN, mesh, and tunnel agents
//! and actually guarantees active reconciliation without requiring a public
//! [`DnsManager::watch`] subscription. The first active lease starts the
//! internal native watch and reconciler; the last lease ending stops them.
//! External changes to resources owned by a live lease are reconciled: the
//! reconciler waits for stable authoritative state, rebases the lease onto
//! the new external base, and reapplies the desired overlay
//! transactionally. Restoring a rebased lease returns to the new external
//! base, not the pre-lease state. Backends without watch support fail
//! Enforce lease creation with [`Error::Unsupported`] instead of silently
//! behaving cooperatively. [`DnsManager::watch`] remains a pure
//! observability subscription.
//!
//! # Update transactions
//!
//! [`Lease::update`] moves every owned resource as one logical transaction:
//! either all resources reach the new configuration or all are rolled back
//! to their immediately previous applied state with journals restored. A
//! valid configuration that resolves to a different resource set than the
//! lease owns fails with [`Error::UpdateRequiresRebind`]; restore or abandon
//! the lease and apply fresh.
//!
//! # Split DNS
//!
//! `nameservers` are the resolver endpoints owned by the configuration;
//! `routing_domains` are the names that should route to those endpoints.
//! When routing domains are non-empty and `default_route != Some(true)`,
//! unrelated DNS remains outside the overlay wherever the backend supports
//! true split DNS. Backends follow ownership minimization: a split-only
//! configuration owns only the scoped resources needed to express it (on
//! macOS, only `/etc/resolver/<domain>` files, leaving the service DNS
//! state untouched).
//!
//! Routing domains are part of the platform-neutral configuration model
//! (see [`DnsConfigBuilder::routing_domain`](crate::DnsConfigBuilder::routing_domain)).
//! The mechanism depends on the active backend: systemd-resolved routing
//! domains on Linux, NetworkManager DNS routing where supported (the root
//! wildcard is the canonical `~.`), NRPT rules on Windows, and scoped
//! `/etc/resolver/<domain>` files on macOS.
//! Configurations a backend cannot represent are rejected with
//! [`Error::Unsupported`] before any mutation. Use
//! [`DnsManager::capabilities`] to probe support at runtime.
//!
//! # Platform and backend differences
//!
//! Linux selects among systemd-resolved (per-link DNS and routing domains),
//! NetworkManager (per-interface DNS), resolvconf/openresolv (owner-tagged
//! global records), and direct `/etc/resolv.conf` manipulation, based on
//! which component actually owns DNS state on the host.
//!
//! Windows uses the modern IP Helper APIs for per-interface IPv4/IPv6
//! settings and the Name Resolution Policy Table (NRPT) for split DNS,
//! with native IP Helper and registry notifications for watching. Windows
//! has no global DNS scope. Requires Windows 10 build 19041 or later.
//!
//! macOS uses SystemConfiguration for per-service DNS and scoped
//! `/etc/resolver/<domain>` files for split DNS, with SCDynamicStore and
//! FSEvents notifications for watching.
//!
//! [`Capabilities`] is the authoritative runtime description of what the
//! active backend guarantees. Never assume two backends behave identically.
//!
//! # Privileges
//!
//! Changing system DNS configuration generally requires elevated privileges.
//! `osdns` never attempts privilege escalation. Insufficient permissions are
//! reported as [`Error::RequiresPrivilege`]; the caller is responsible for
//! running with appropriate OS privileges.
//!
//! # Runtime model
//!
//! `osdns` has no async runtime dependency and does not require Tokio or
//! async-std. Configuration changes are synchronous control-plane operations
//! using native blocking APIs. Native watcher threads are started for
//! [`ConflictPolicy::Enforce`] leases (first active lease to last lease end)
//! and for each [`DnsManager::watch`] subscription.
//!
//! # Safety and security limitations
//!
//! - `osdns` never performs privilege escalation.
//! - Filesystem and registry resources are ownership-controlled: files, rules,
//!   and records not demonstrably ours are never overwritten or deleted.
//! - Corrupt or unknown journal state fails closed; no mutation is attempted.
//! - Unsafe code is isolated to platform FFI modules and justified with
//!   `SAFETY:` comments.
//! - DNS configuration alone does not enforce packet routing and is not DNS
//!   leak prevention. Applications requiring traffic isolation must separately
//!   control routing and firewall policy.

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
