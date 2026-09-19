# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
