# Changelog

## Unreleased

- Windows backend rebuilt on Rust for Windows 0.100: committed focused
  `windows-bindgen` sys bindings, `windows-registry`/`windows-link`/
  `windows-result` 0.100, and removal of the `windows` 0.62 umbrella crate.
- Raised the MSRV from Rust 1.89 to Rust 1.95.
- Replaced the 0.1.3 journal format with schema 3 resource-incarnation
  records. This is intentionally incompatible with durable state written by
  0.1.3. Stop the old process and clear or reset its osdns state directory
  before upgrading.

## 0.1.3

Correctness and API-contract hardening (breaking changes allowed at `0.1.x`):

- `default_route = None` now preserves the current value on every backend
  instead of silently becoming `false` (notably systemd-resolved merges the
  plan with the captured state).
- Added `Capabilities::default_route` plus a backend `validate_plan` hook;
  `validate()` success now guarantees every explicitly requested semantic is
  faithfully representable, and unsupported semantics fail before mutation.
- Fixed the NetworkManager root routing-domain representation to the
  canonical `~.` (was the accidental empty-string form `~`).
- `Lease::update()` is now one logical transaction across all owned
  resources with rollback to the previous applied state and consistent
  journals, reusing the apply transaction machinery.
- Added the typed `Error::UpdateRequiresRebind` (replacing the generic
  `InvalidConfig` for valid configs that resolve to a different resource
  set).
- `ConflictPolicy::Enforce` is now self-contained: the first active lease
  starts internal observation and the last lease ending stops it. Public
  `watch()` is purely observational; Enforce without watch support fails
  honestly with `Unsupported`.
- macOS split-only configurations own only scoped `/etc/resolver/<domain>`
  resources, leaving service DNS state untouched; fixed the macOS build
  (`service_needed` lives on the inherent impl) and updated the macOS
  mutation test for minimal ownership.
- Documented the `nameservers` + `routing_domains` split-DNS model and the
  strengthened validation, `None`-preservation, Enforce, and update
  guarantees.
- CI: updated `actions/checkout` to v7.

## 0.1.0

Initial release.
