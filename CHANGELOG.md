# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Phase 1 (#140) — RustCrypto traits-based core refactor + PHC string format.

## [0.0.9] — 2026-05-19

This release kicks off the enterprise-readiness programme — see the
[v0.0.9 milestone](https://github.com/sebastienrousseau/hsh/milestone/1)
for the full roadmap across Phases 0–7.

### Added

- Cargo **workspace** layout: source moved into `crates/hsh/`; root is now
  a workspace manifest with shared profile and dependency configuration.
- `rust-toolchain.toml` pinning stable rust with `rustfmt`, `clippy`,
  `rust-src`.
- Structured `hsh::Error` enum (thiserror) plus `hsh::Result<T>` alias.
- `SECURITY.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, ADR-0006.
- Consolidated GitHub Actions: a single `ci.yml` delegates to the reusable
  workflows in `sebastienrousseau/pipelines`.

### Changed

- **MSRV** bumped to **1.75** (was 1.60).
- Release profile uses `opt-level = 3` (was `"s"`) and now enables
  `overflow-checks = true` — arithmetic on cost parameters must never
  silently wrap.
- Crate description, README, and crate-level docs no longer claim
  "quantum-resistant" — see ADR-0001 (to be written in Phase 1) and the
  "What HSH is not" section in the README.
- Verification code path no longer prints password, salt, or hash bytes
  to stdout.
- Dependabot: weekly Monday cadence, grouped minor+patch updates, scoped
  commit messages, PR labels.

### Security

- **S1 — constant-time verify.** `argon2i` and `scrypt` verify paths now
  use `subtle::ConstantTimeEq` instead of `==` byte comparison. Closes
  [#149](https://github.com/sebastienrousseau/hsh/issues/149).
- **S3 — zeroize secrets on drop.** `Hash` fields (`hash`, `salt`) are
  private and zeroed on drop via `zeroize::ZeroizeOnDrop`. `set_hash` /
  `set_salt` zeroize the previous buffer before reassignment. Closes
  [#150](https://github.com/sebastienrousseau/hsh/issues/150).
- **S7 — structured errors.** All `Result<T, String>` returns replaced
  with `Result<T, hsh::Error>` implementing `std::error::Error`. Closes
  [#151](https://github.com/sebastienrousseau/hsh/issues/151).
- **S10 — marketing claim.** Removed the misleading "quantum-resistant"
  positioning from README, crate docs, and `Cargo.toml`. Closes
  [#152](https://github.com/sebastienrousseau/hsh/issues/152).

### Breaking changes

- `Hash::{hash, salt, algorithm}` fields are now private; use the
  `hash()`, `salt()`, `algorithm()` accessor methods.
- Error type changed from `String` / `&'static str` to `hsh::Error`.
  Pattern-match on variants or use `Display` for human-readable text.

### Deprecated

- Calls relying on the old verify path's `println!` debug output — those
  prints are gone. There was no API for capturing them, but anyone scraping
  stdout in tests will need to update.

### Removed

- The `feature = "bench"` `cfg_attr` gate from `lib.rs` (was unused and
  triggered an `unexpected_cfgs` warning).

## [0.0.8] — 2025-04-05 and earlier

See git history. Versions prior to 0.0.9 predate this changelog and are
unsupported.

[Unreleased]: https://github.com/sebastienrousseau/hsh/compare/v0.0.9...HEAD
[0.0.9]: https://github.com/sebastienrousseau/hsh/releases/tag/v0.0.9
