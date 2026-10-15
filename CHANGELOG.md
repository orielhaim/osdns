# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Changed

* Rebuilt transactions around coherent native-resource observations and explicit
  rejected, performed, and indeterminate mutation outcomes. Rollback requires
  backend-issued evidence; equivalent DNS values alone do not prove a mutation.
* Journal files and resource locks now use retained `private-fs` directory
  capabilities, with atomic publication, full durability, and retryable ambiguous
  publication and removal errors. Read-only managers do not initialize storage.
* Journal schema 4 separates typed runtime snapshots from the durable format and
  validates resource, backend, owner, filename, and unique resource claims.
  Older schemas are intentionally unsupported and are never migrated or ignored.
  Restore or abandon journals with the version that wrote them before upgrading.
* Live leases retain volatile mutation evidence when Applied publication fails.
  Failed compensation after an ambiguous rebase publication blocks further
  mutation until the journal is repaired; terminal cleanup can also resolve it.
* Partial restore and abandon retain unresolved resources and release completed
  resources. Updates cannot resume once teardown starts. Failed abandon and Drop
  retry journal removal without restoring DNS.
* Watch delivery coalesces events in bounded queues and suppresses own changes by
  authoritative readback. Enforce restarts interrupted observation, rescans active
  leases, and retains scheduled retries across transient errors.
* NetworkManager uses versioned Reapply bound to the recorded D-Bus owner and
  activation. Apply and restore share one guarded mutation pipeline.
  systemd-resolved retains live link handles and verifies the bus namespace.
* Linux default-interface selection uses synchronous Netlink dumps and rejects
  absent or ambiguous main-table defaults. Select an interface explicitly when
  the routing table has no unique default.
* Direct resolver-file backends preserve supported native metadata and reject
  unsupported hard links, ACLs, extended attributes, or file flags. They cannot
  atomically compare against concurrent privileged edits.
* macOS uses native SystemConfiguration property lists and preserves unmanaged
  fields. Scoped resolver files use retained directory handles and exclusive
  creation; replacement and deletion retain a final privileged-writer race.
* Windows NRPT creation and cleanup retain registry handles. Existing-rule updates
  change only the server list while preserving validated policy and owner fields.
  Registry publication does not promise power-loss durability or atomic activation.

### Added

* FreeBSD and NetBSD global DNS backends, native CI, interface enumeration,
  resolver limits, and kqueue notifications.
* `Lease::pending_durability()` exposes journal repair still required by live
  leases. Observation health and pending reconciliation are visible to callers.

## [0.2.3] - 2026-09-20

### Added

* `Error::UnsupportedPlatform` when constructing a system manager on a target with no OS DNS backend. The crate compiles there; it does not pretend to be Linux and does not ship a no-op backend.

### Fixed

* Journal snapshot encode/decode and snapshot types compile on targets with no OS backend, without treating them as Linux.

## [0.2.2] - 2026-09-17

### Fixed

* Treated `DnsFlushResolverCache` as BOOL (nonzero success). Mapping the return as a Win32 status made a successful flush look like `ERROR_INVALID_FUNCTION`.
* Windows crash recovery now reports vanished adapters as `ResourceStatus::Gone` / `Error::ResourceGone` instead of a platform `GetInterfaceDnsSettings` not-found failure.
* Enforce no longer drops a watcher event that arrives during a StillOurs/Rebased pass. `touch` does not reschedule an already-pending resource, so removing the entry at the end of the pass swallowed the change and left the worker idle (the usual failure of `public_watch_is_optional_and_does_not_own_enforce` on loaded Windows).
* Avoid `recv_timeout(Duration::ZERO)` in the reconciler and watch coalescer. A zero timeout can block on Windows instead of returning.

## [0.2.0] - 2026-09-07

### Changed

* Reworked resource identity and recovery around resource incarnations, preventing stale leases from being rebound to recreated interfaces.
* `recover_stale()` now reports individual recovery failures as `RecoveryOutcome::Failed` instead of failing the entire recovery pass. Callers must inspect returned outcomes.
* Replaced the journal format with schema 3. **State written by osdns 0.1.x is intentionally not migrated.** Stop the old process and clear or reset the osdns state directory before upgrading; legacy records will otherwise cause operations such as `apply()` and `recover_stale()` to fail with an unsupported-journal-version error.
* Rebuilt the Windows backend on Rust for Windows 0.100 using focused Win32 bindings and `windows-registry`, `windows-link`, and `windows-result` 0.100.
* Raised the MSRV from Rust 1.89 to Rust 1.95.

### Fixed

* Prevented DNS mutations and restores from overwriting state changed concurrently by another process.
* Hardened recovery against vanished, replaced, reused, or ambiguously identified network interfaces.
* Hardened native watcher startup, shutdown, overflow handling, and callback lifetime behavior across Windows, Linux, and macOS.
* Improved Linux backend and default-interface detection using effective NetworkManager state and kernel routing information.
* Hardened Windows NRPT ownership so foreign or malformed rules are never overwritten or treated as osdns-owned.

### Removed

* Removed the `windows` 0.62 umbrella dependency and obsolete Windows compatibility code.

## 0.1.3

Correctness and API-contract hardening (breaking changes allowed at `0.1.x`):

* `default_route = None` now preserves the current value on every backend
  instead of silently becoming `false` (notably systemd-resolved merges the
  plan with the captured state).
* Added `Capabilities::default_route` plus a backend `validate_plan` hook;
  `validate()` success now guarantees every explicitly requested semantic is
  faithfully representable, and unsupported semantics fail before mutation.
* Fixed the NetworkManager root routing-domain representation to the
  canonical `~.` (was the accidental empty-string form `~`).
* `Lease::update()` is now one logical transaction across all owned
  resources with rollback to the previous applied state and consistent
  journals, reusing the apply transaction machinery.
* Added the typed `Error::UpdateRequiresRebind` (replacing the generic
  `InvalidConfig` for valid configs that resolve to a different resource
  set).
* `ConflictPolicy::Enforce` is now self-contained: the first active lease
  starts internal observation and the last lease ending stops it. Public
  `watch()` is purely observational; Enforce without watch support fails
  honestly with `Unsupported`.
* macOS split-only configurations own only scoped `/etc/resolver/<domain>`
  resources, leaving service DNS state untouched; fixed the macOS build
  (`service_needed` lives on the inherent impl) and updated the macOS
  mutation test for minimal ownership.
* Documented the `nameservers` + `routing_domains` split-DNS model and the
  strengthened validation, `None`-preservation, Enforce, and update
  guarantees.
* CI: updated `actions/checkout` to v7.

## 0.1.0

Initial release.
