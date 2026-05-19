# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Phase 2 (#141) — Operational hardening: fuzz/, Miri, SLSA L3 release.

### Added (Phase 1)

- **`hsh::api::hash`** and **`hsh::api::verify_and_upgrade`** — the
  high-level enterprise surface that serialises hashes in the PHC string
  format and signals when a successful verify should trigger a re-hash
  under the current policy.
- **`hsh::Policy`** with `owasp_minimum_2025()` and
  `rfc9106_first_recommended()` presets.
- **`hsh::Outcome::{Valid { needs_rehash }, Invalid}`** for verification
  results.
- **`HashAlgorithm::Argon2id`** and `HashAlgorithm::Argon2d` variants;
  the enum is now `#[non_exhaustive]`.
- **`Hash::new_argon2id`** — recommended Argon2 constructor.
- **`crate::algorithms::bcrypt::BcryptParams`** with explicit
  `PrehashAlgorithm::{None, Sha256}` opt-in.
- **`crate::algorithms::scrypt::ScryptParams`** with `log_n`/`r`/`p`/
  `dk_len` fields; default = OWASP-2025 minimum (`N = 2^17`).
- **`compat-v0_0_x`** feature flag (currently a no-op marker; will gate
  the v0.0.x shim in a future release).
- Phase 1 test suite (`tests/test_api.rs`, `tests/test_argon2id.rs`).

### Changed (Phase 1)

- **S2/#156 — Argon2id is the recommended default.** New code should use
  `Hash::new_argon2id` or `api::hash` with
  `Policy::owasp_minimum_2025()`. `Hash::new_argon2i` is
  `#[deprecated(since = "0.0.9")]` and verify-only.
- **S4/#157 — Scrypt parameters are configurable.** Default is OWASP-2025
  (`N = 2^17, r = 8, p = 1, dk_len = 64`).
- **S5/#158 — Bcrypt rejects inputs > 72 bytes by default.** Opt into a
  pre-hash via `BcryptParams::with_prehash(PrehashAlgorithm::Sha256)` to
  handle longer inputs explicitly.
- **S8/#161 — Argon2 backend is now the maintained RustCrypto `argon2`
  crate.** `argon2rs` (last released 2017) and its dependencies (`dtt`,
  transitively-imported `vrd`) are removed.
- **S9/#162 — Salts come from `getrandom`** (OS CSPRNG) only. `vrd`
  removed from `[dependencies]`.

### Removed (Phase 1)

- **#163 — `crate::macros`.** The 498-line module of utility macros
  (`hsh_max`, `hsh_min`, `hsh_vec`, `hsh_split`, `hsh_join`, `hsh_assert`,
  `hsh_contains`, `hsh_parse`, `hsh_print`, `random_string`, `new_hash!`,
  `generate_hash!`, `hash_length!`, `match_algo!`, `to_str_error!`)
  has been deleted. None of these belonged in a cryptographic library.

### Security (Phase 1)

- **S6/#159 (partial)** — PHC string format adoption via
  `password_hash::PasswordHash` for verification of Argon2id / Argon2i /
  Argon2d / scrypt, and MCF detection for bcrypt. The legacy
  `Hash::from_string` 6-part dollar-delimited form is still present for
  backwards compatibility but no longer used by the high-level API.
- **#160** — `api::verify_and_upgrade` returns
  `(Outcome, Option<new_phc>)` so the caller can persist a re-hash
  whenever the stored algorithm or Argon2 parameters fall below the
  current `Policy`.

### Roadmap notes left in code

- Scrypt PHC hashing via `api::hash` currently uses the scrypt crate's
  built-in default params; custom-param PHC is tracked as a Phase 1
  follow-up (the raw-bytes path via `Scrypt::hash_with` already supports
  configurable params).
- Bcrypt cost-factor introspection for auto-rehash is a Phase 1
  follow-up — today's verify accepts the stored cost without comparing
  against `policy.bcrypt.cost`.

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
