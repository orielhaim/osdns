# Changelog

## 0.1.2

- Fix macOS build: move the `service_needed` minimal-ownership helper from
  the `Backend` trait impl to the inherent `MacosBackend` impl.

## 0.1.1

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
  resources, leaving service DNS state untouched.
- Documented the `nameservers` + `routing_domains` split-DNS model and the
  strengthened validation, `None`-preservation, Enforce, and update
  guarantees.

## 0.1.0

Initial release.
