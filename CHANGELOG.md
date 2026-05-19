# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- **v1.0.0** — ships after an ~8-week stabilisation window during
  which v0.0.9 absorbs post-merge bug reports and the CI nightlies
  produce the first set of SLSA attestations + OpenSSF Scorecard
  scores. See [`doc/adr/0007-v1-stability-contract.md`](doc/adr/0007-v1-stability-contract.md).

### Added (Phase 7)

- **`doc/API-STABILITY.md`** — per-crate per-symbol stability tier
  (Stable / Unstable / Internal), MSRV policy,
  `#[non_exhaustive]` semantics, deprecation policy,
  yanked-release policy, semver bump cheat sheet.
- **`doc/RELEASE.md`** — maintainer release runbook covering
  pre-release checks, the tag-push flow, post-release smoke tests,
  and the rollback / yank procedure.
- **`doc/SUPPORT.md`** — community channels, response-window
  commitments, what to include in a bug report.
- **ADR-0007 — v1.0 stability contract** documenting the
  surfaces frozen at v1.0, the lockstep versioning model across
  the four crates, MSRV policy, and the yank-release SLAs.
- **OpenSSF Scorecard badge** in the README.

### Changed (Phase 7)

- **README** restructured: workspace-at-a-glance table for the four
  crates, capabilities list, what-landed-in-v0.0.9 phase table, and
  a documentation index pointing at every long-form guide.
- **SECURITY.md** rewritten: defended-vs-tracked-follow-up split
  reflects the post-Phase-6 reality (PHC adopted, bcrypt 72-byte
  rejection live, scrypt defaults bumped, FIPS contract enforced,
  etc.). Supply-chain section updated with the Phase 2 pipeline
  details (SLSA L3, sigstore, SBOM, Scorecard, fuzz, Miri).

### Added (Phase 7 hygiene follow-up)

- **`Policy::builder()`** / **`PolicyBuilder`** — fluent
  construction with `PolicyBuilder::new` (blank slate, requires
  primary) and `PolicyBuilder::from_preset(&Policy)` (override
  selected fields).
- **`Policy` accessor methods** — `primary()`, `backend()`,
  `argon2_params()`, `bcrypt_params()`, `scrypt_params()`,
  `pbkdf2_params()`, `has_pepper()`, `to_builder()`.
- **`PolicyBuilder::no_pepper()`** — explicit removal of an
  attached pepper provider.
- **`Error::InvalidPolicy(&'static str)`** — surfaced by
  `PolicyBuilder::build()` when a required field is missing.
- **Workspace-level `[workspace.lints.rust]`** + **`[workspace.lints.clippy]`**
  — single source of truth for lint config; per-crate
  `[lints] workspace = true` inherits. Pedantic / nursery / cargo
  groups added at warn; `clippy::unwrap_used` + `expect_used`
  added at warn (allowed in tests / benches / examples / fuzz via
  per-file `#![allow(...)]`).
- **`cargo-hack` feature-permutation CI job** — checks every
  feature combination across the workspace on each PR.
- **`cargo public-api` diff CI job** — surfaces public-API
  additions / removals on each PR (advisory; pairs with the
  semver bump policy in `doc/API-STABILITY.md`).

### Changed (Phase 7 hygiene follow-up)

- **`Policy` fields are now `pub(crate)`.** Construction via the
  presets / `PolicyBuilder` is the only supported public path.
  Reading the fields uses the new accessor methods. Per
  `doc/API-STABILITY.md`, `Policy`'s struct shape was already
  flagged Unstable; this change tightens that promise.
- **`Hash::new_argon2i`** is now gated behind the
  `compat-v0_0_x` Cargo feature. Slated for removal in v0.2.0.

### Roadmap notes

- Pedantic warnings remain advisory — CI surfaces them but doesn't
  fail on them (per the Makefile's `-D warnings` is scoped to the
  base rust lints).
- A small number of pedantic warnings against the lib code itself
  (collect-then-join, `cast_possible_truncation` in the CLI's
  `calibrate`) are tracked for a hygiene PR in v0.0.10.

## [0.0.9] — 2026-05-19

### Added (Phase 6)

- **`crates/hsh-digest`** — new workspace member for general-purpose
  hashing. Opens with a loud "⚠️ NOT for password storage" warning;
  points readers at `hsh::api::hash` for that.
- **`hsh_digest::Algorithm`** enum: `Sha256`, `Sha384`, `Sha512`
  (FIPS 180-4), `Sha3_256`, `Sha3_384`, `Sha3_512` (FIPS 202),
  `Blake3`. Each variant gated by its own Cargo feature.
- **`hsh_digest::Hasher`** streaming API (`new` / `update` / `finalize`)
  + one-shot `hsh_digest::hash(algorithm, data)` convenience.
- **`hsh_digest::constant_time_eq`** — `subtle`-backed comparison
  helper.
- **`Algorithm::output_len()`** and **`Algorithm::id()`** — metadata
  helpers for protocol code.
- **13 KAT integration tests** in `crates/hsh-digest/tests/kat.rs`
  against NIST CAVP (SHA-2), FIPS 202 (SHA-3), and the BLAKE3
  project test vectors.
- **ADR-0005 — general-hashing scope decision**
  (`doc/adr/0005-general-hashing-scope.md`).

### Forward-compat (Phase 6)

- `k12` Cargo feature declared as a marker for KangarooTwelve /
  TurboSHAKE128/256 (RFC 9861, Oct 2025) — impl in Phase 6 follow-up.
- `ascon` Cargo feature declared as a marker for Ascon-Hash256 /
  Ascon-XOF128 (NIST SP 800-232 final, Aug 2025) — impl in Phase 6
  follow-up.

### Non-goals (Phase 6 / ADR-0005)

- No HMAC, HKDF, SipHash, or SHA-1 in `hsh-digest`. Use the
  RustCrypto siblings (`hmac`, `hkdf`, etc.). SHA-1 specifically is
  deprecated for all security uses.
- No signatures / KEMs / PQ primitives. `hsh-digest` is hashes-only.

### Added (Phase 5)

- **`crates/hsh-cli`** — new workspace member providing the `hsh`
  binary with 6 subcommands:
  - `hsh hash` — produce a storable hash from a password.
  - `hsh verify` — verify a candidate against a stored hash; exit
    code 0 on match, 1 on mismatch.
  - `hsh rehash` — verify + mint a fresh hash under current policy.
  - `hsh inspect` — pretty-print algorithm + parameters of a stored
    hash (PHC, MCF, or `hsh-pepper:` wrapper).
  - `hsh calibrate` — measure KDF parameters to hit a target
    wall-time on the current hardware.
  - `hsh completions <shell>` — emit bash/zsh/fish/powershell/elvish
    completion scripts at runtime.
- **Preset policies** on the CLI: `--policy owasp` (default),
  `--policy rfc9106`, `--policy fips`.
- **`--json`** flag for machine-readable output on every subcommand.
- **6 CLI integration tests** in `crates/hsh-cli/tests/cli.rs`.
- **Packaging templates** under `pkg/`: Docker (multi-stage musl +
  distroless), Homebrew formula, Debian control, Arch PKGBUILD,
  Scoop manifest. Materialised by `release.yml` on tag push.
- **5 migration guides** under `doc/`: from `argonautica`,
  `rust-argon2`, `bcrypt`, `djangohashers`, and raw `password-hash`.

### Changed (Phase 5)

- Removed the old `crates/hsh/src/main.rs` stub binary — the
  `hsh-cli` workspace member is now the canonical `hsh` binary.
- Removed `crates/hsh/tests/test_main.rs` (covered the stub).
- Workspace dev-deps add `clap 4.5`, `clap_complete 4.5`, `anyhow
  1.0`, `rpassword 7.3` for the CLI.

### Security (Phase 5)

- The CLI **never accepts a password on argv**. Passwords are read
  from stdin (TTY prompt with no echo if interactive, first line
  otherwise) or `$HSH_PASSWORD` env. The `--password` flag exists
  but is documented as insecure.

### Forward-compat (Phase 5)

- `clap_mangen`-driven man-page generation deferred: the current
  release of `clap_mangen 0.2.33` is version-skewed against
  `clap_builder 4.5.2`. The CLI works without man pages; this
  becomes a Phase 5 follow-up under `release.yml`.
- MSI / Flatpak / Snap / Nix packaging deferred — listed in
  `pkg/README.md`.
- Phase 4 follow-up — dedicated `hsh-backend-awslc` workspace member
  that routes PBKDF2 through `aws-lc-rs`'s FIPS 140-3 validated module
  and flips `Backend::fips_available_in_build()` to `true`.

### Added (Phase 4)

- **`PrimaryAlgorithm::Pbkdf2`** + **`HashAlgorithm::Pbkdf2`** —
  PBKDF2-HMAC-SHA-256/512 support across the workspace.
- **`crate::algorithms::pbkdf2`** module with `Prf::{Sha256, Sha512}`,
  `Pbkdf2Params` (OWASP-2025 minimum: 600 000 / 210 000 iterations),
  `Pbkdf2::hash_with()` for explicit-param derivation.
- **PHC string format** `$pbkdf2-sha256$i=<iters>,l=<len>$<salt>$<hash>`
  emitted by `api::hash` for PBKDF2 hashes. Parsed end-to-end by
  `api::verify_and_upgrade`.
- **`Backend` enum** (`Native | Fips140Required`) with `is_fips()` and
  `fips_available_in_build()` helpers.
- **`Policy.backend` field** + **`Policy::fips_140_pbkdf2()` preset**
  (PBKDF2-HMAC-SHA-256, 600 000 iters, `Backend::Fips140Required`).
- **Algorithm-drift / iteration-drift / PRF-drift detection** for
  PBKDF2 in `api::verify_and_upgrade::needs_rehash`.
- **Runtime refusal** in `api::hash` when:
  - `Backend::Fips140Required` is set but primary isn't PBKDF2
    (Argon2/bcrypt/scrypt have no FIPS-validated module anywhere).
  - `Backend::Fips140Required` is set but the build can't satisfy it
    (`Backend::fips_available_in_build()` returns `false`).
- **8 PBKDF2 integration tests** in `crates/hsh/tests/test_pbkdf2.rs`
  covering round-trip, wrong-password rejection, iteration drift, PRF
  drift, FIPS-policy refusal of Argon2id, FIPS-policy refusal when
  feature missing, `Backend::is_fips()`, `Policy::fips_140_pbkdf2()`
  preset.
- **ADR-0004 — FIPS 140-3 strategy** (`doc/adr/0004-fips-strategy.md`).
- **`doc/FIPS.md`** — deployment guide with the "fail-closed"
  contract, what's delivered today, three deployment options, and the
  Argon2→PBKDF2 migration playbook.

### Changed (Phase 4)

- `Policy` gains required `backend: Backend` and `pbkdf2: Pbkdf2Params`
  fields. Test / bench struct literals updated.
- `Policy::owasp_minimum_2025()` and `rfc9106_first_recommended()` now
  populate both new fields with sensible defaults
  (`Backend::Native`, OWASP-2025 PBKDF2 params for legacy verification).
- `HashAlgorithm` gets a `Pbkdf2` variant; `parse_algorithm_tag` recognises
  `"pbkdf2"`, `"pbkdf2-sha256"`, `"pbkdf2-sha512"`.
- `Hash::generate_hash` and `Hash::verify` route PBKDF2 through the
  new module.

### Security (Phase 4)

- The Backend contract is **fail-closed**: no `hsh::api::hash` call
  ever silently produces non-FIPS output when the caller asked for
  FIPS. Either the caller gets a hash from a validated module, or
  they get a typed error.
- Custom PBKDF2 PHC encoder lives in `hsh` (not delegated to
  RustCrypto's encoder) so the future `hsh-backend-awslc` swap can
  intercept the derive call without changing the storage format.

### Forward-compat

- `fips` Cargo feature exists today but is a **no-op marker**. Enabling
  it does nothing observable; `Backend::fips_available_in_build()`
  remains `false`. The dedicated `hsh-backend-awslc` follow-up flips
  this when its dependency-graph presence is detected. Documented
  prominently to avoid misleading-marketing.

### Added (Phase 3)

- **`hsh-kms`** — new workspace crate with the [`Pepper`] trait,
  [`KeyVersion`] type, and an in-memory [`LocalPepper`] implementation
  for tests and apps without a KMS. Pepper application is
  `HMAC-SHA-256(key_at(version), password)` → 32-byte tag.
- **Provider stubs** under feature flags `aws-kms`, `gcp-kms`,
  `azure-key-vault`, `hashicorp-vault`. Each exposes a stable
  `FetchOpts` and `fetch_pepper` shape; the network-call
  implementations land incrementally as integration tests against
  real cloud infrastructure get wired up.
- **`hsh` `pepper` feature** — opt-in pepper support behind a Cargo
  feature so non-KMS callers don't pull in `hsh-kms`.
- **`Policy::with_pepper(Arc<dyn Pepper>)`** — attach a pepper
  provider to a policy.
- **Peppered storage format** — `hsh-pepper:<keyver>:<inner>` wrapper
  on the existing PHC / MCF string. The `<keyver>` makes rotation
  non-destructive and queryable from SQL.
- **Rotation semantics in `api::verify_and_upgrade`** — when the
  stored `keyver` differs from `policy.pepper.current()`, a
  successful verify returns `Outcome::Valid { needs_rehash: true }`
  with a freshly-peppered hash so the caller can persist it.
- **Legacy upgrade path** — a non-peppered hash verified against a
  pepper-enabled policy succeeds and triggers rehash under the
  current pepper.
- **6 pepper integration tests** in `crates/hsh/tests/test_pepper.rs`
  covering round-trip, wrong-password rejection, refuse-without-pepper,
  rotation rehash, legacy upgrade, and unknown-version handling.
- **ADR-0003 — pepper key-versioning scheme**
  (`doc/adr/0003-pepper-key-versioning.md`).
- **`doc/KMS-INTEGRATION.md`** — end-to-end guides for AWS / GCP /
  Azure / Vault plus a local-dev recipe and rotation playbook.

### Changed (Phase 3)

- `Policy` gains an optional `pepper: Option<Arc<dyn Pepper>>` field
  behind the `pepper` feature. Struct literal construction in tests
  needs `#[cfg(feature = "pepper")] pepper: None,`.

### Security (Phase 3)

- Peppered hashes verified against a policy *without* a pepper return
  `Outcome::Invalid` rather than failing open. An attacker who can
  forge or strip the `hsh-pepper:` prefix cannot bypass the pepper
  check.
- `LocalPepper` enforces a 16-byte minimum-key safety floor and
  zeroizes all key material on drop.

### Added (Phase 2)

- **`fuzz/`** — cargo-fuzz crate with 5 libfuzzer targets:
  `fuzz_api_round_trip`, `fuzz_phc_parse`, `fuzz_argon2id_verify`,
  `fuzz_bcrypt_verify`, `fuzz_legacy_from_string`. Excluded from the
  workspace default build set; driven via `cargo +nightly fuzz`.
- **`crates/hsh/tests/test_properties.rs`** — proptest harness with 7
  property invariants (round-trip, wrong-password rejection, salt
  uniqueness, bcrypt 72-byte rejection, short-password rejection).
- **Criterion bench suite** — three groups (`hash_owasp_2025`,
  `verify_owasp_2025`, `fast_params`) replacing the previous trivial
  benches.
- **Supply-chain hardening** — rewritten `deny.toml` (yanked = deny,
  multiple-versions = warn, wildcards = deny, bans `argonautica`,
  `argon2rs`, `openssl`, deny unknown-registry/git);
  `supply-chain/audits.toml` (cargo-vet criteria + trusted import
  feeds); `supply-chain/imports.lock` placeholder; `about.toml`
  (cargo-about target matrix for SBOMs).
- **`Makefile`** — POSIX, 25 targets (ci, release, fmt, clippy, test,
  doc, deny, audit, sbom, miri, fuzz, bench, coverage, calibrate).
- **`scripts/`** — `miri.sh` (focused / full), `pre-commit.sh`,
  `parameter-calibration.sh`, `coverage-gap-report.sh`.
- **CI workflows**:
  - `release.yml` — tag↔Cargo.toml verification, quality gate, SBOM,
    SLSA L3 build-provenance via `actions/attest-build-provenance`,
    keyless sigstore signing via `cosign sign-blob`, cargo publish.
  - `miri.yml` — focused Miri on every PR (60-minute budget),
    full sweep weekly (90-minute budget).
  - `scorecard.yml` — OpenSSF Scorecard weekly, SARIF uploaded to
    code-scanning.
  - `fuzz.yml` — nightly cron, 5-target matrix, 10-min-per-target
    budget, crash artefacts retained 30 days.
  - `supply-chain.yml` — `cargo-deny check` + `cargo-audit` on every
    dependency change and weekly.
- **`doc/pre-commit.md`** — install / scope / bypass / CI-parity
  guidance for the local pre-commit hook.

### Changed (Phase 2)

- Workspace `Cargo.toml` adds `exclude = ["fuzz"]` so the libfuzzer
  crate isn't pulled into stable-toolchain builds.

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
