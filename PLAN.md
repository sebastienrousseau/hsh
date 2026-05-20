<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# hsh enterprise-readiness plan

This document is the long-form roadmap for shipping `hsh` as a
distro-grade Rust library and CLI tool: a workspace structure
consistent with the rest of @sebastienrousseau's Rust projects,
multi-algorithm password hashing with structured errors, KMS-backed
peppering, a FIPS 140-3 fail-closed contract, and a multi-platform
release pipeline that produces signed artefacts ready for crates.io,
GitHub Releases, Homebrew, Debian, Arch / AUR, Scoop, and GHCR.

The plan is written so any maintainer can pick up where the last
commit left off. Each phase is sized for a single self-contained
PR; the order respects dependencies (security hot-fixes first,
restructure early, distro outreach last).

## Working invariants

These rules apply to every change inside this plan. They are
binding even when not restated in a section.

- **CI must always be green.** Every push verifies the workflow
  status; any red job is fixed in the same session before
  declaring done. Never bypass with `--no-verify`, `[skip ci]`,
  or `if: false`.
- **Conventional Commits** with signed (`-S`) commits.
- **`#![forbid(unsafe_code)]`** is non-negotiable at the workspace
  root and every crate root. See [ADR-0006](./doc/adr/0006-zero-unsafe-policy.md).
- **OS CSPRNG only.** No `vrd`, no `rand::thread_rng`, no
  `fastrand::Rng::new` — enforced by `clippy.toml`'s
  `disallowed-methods`.
- **Constant-time everywhere** a hash is compared — enforced by code
  review and the inability to call `core::slice::eq` on byte slices
  in crypto contexts.
- **Zeroize on drop** for password / hash / salt / pepper-key
  buffers via `zeroize::ZeroizeOnDrop`.
- **Coverage ≥ 93 % lines** workspace-wide; ratchet upward as the
  suite grows. Gated by `cargo llvm-cov --fail-under-lines 93`.

## Phase mapping

The phases were originally tracked as v0.0.9 milestone issues
#139–#164 + #137. See <https://github.com/sebastienrousseau/hsh/milestone/1>
for the current state.

### Phase 0 — Foundation & security hot-fixes ✅

Closes: #139 #147 #148 #149 #150 #151 #152 #153 #154 #155 #161 #162

- **0.1** Convert to a Cargo workspace (`crates/hsh`, `crates/hsh-cli`,
  `crates/hsh-kms`, `crates/hsh-digest`).
- **0.2** Bump edition / MSRV per crate (lib 1.75, CLI 1.88 due to
  `rpassword` 7.5 let-chains).
- **0.4** Add `SECURITY.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`.
- **0.5** ADR-0006 — zero-unsafe policy.
- **0.6** Verify `cargo fmt / clippy / test / doc` all green.
- **S1** Constant-time verify in Argon2i and scrypt.
- **S3** Zeroize secret material on drop.
- **S7** Replace `Result<T, String>` with `thiserror::Error`.
- **S8** Drop unmaintained `argon2rs` dependency.
- **S9** Salt from `rand_core::OsRng` only — drop `vrd`.
- **S10** Remove misleading "quantum-resistant" marketing.

### Phase 1 — Core refactor on RustCrypto traits ✅

Closes: #140 #156 #157 #158 #159 #160 #163 #164

- **S2** Migrate from Argon2i to Argon2id as the primary.
- **S4** Configurable scrypt params (OWASP-2025 default).
- **S5** Bcrypt 72-byte safety rail (reject by default, opt-in
  HMAC-SHA-256 pre-hash via `BcryptParams::with_prehash`).
- **S6** Adopt PHC string format via `password_hash` crate.
- **Phase 1 core** `verify_and_upgrade()` multi-algo with
  auto-rehash on algorithm / parameter / PRF / pepper-version
  drift.
- **Phase 1.b** Delete utility macros in `src/macros.rs` (replaced
  with the typed `api` surface).
- **Phase 1.c** `compat-v0_0_x` deprecation shim feature — re-
  exposes the pre-0.0.9 stringly-typed API for one release cycle.

### Phase 2 — Operational hardening ✅

Closes: #141

- 5 `cargo-fuzz` libfuzzer targets (`fuzz_api_round_trip`,
  `fuzz_phc_parse`, `fuzz_argon2id_verify`, `fuzz_bcrypt_verify`,
  `fuzz_legacy_from_string`) running on a nightly cron.
- Miri focused suite per-PR (60 min) + full sweep weekly (90 min).
- 7 `proptest` invariants for api round-trip + drift detection.
- 11 `proptest` invariants in `hsh-digest` (chunking equivalence,
  output-length, determinism, cross-algorithm distinctness).
- `cargo-deny` + `cargo-audit` on every PR + weekly cron.
- `cargo-hack` feature-powerset check.
- `cargo-public-api` advisory diff on every PR.
- Coverage at **93.49 % lines / 94.81 % regions** with
  `--fail-under-lines 93` enforced.

### Phase 3 — Pepper & KMS integration ✅

Closes: #142

- `Pepper` trait with `apply(version, password) -> [u8; 32]`
  (HMAC-SHA-256).
- `LocalPepper` in-memory provider with `KeyVersion` rotation.
- 4 KMS provider stubs: AWS KMS, GCP Cloud KMS, Azure Key Vault,
  HashiCorp Vault Transit. Stable shape, real network calls land
  per-provider as v0.0.10+ follow-ups.
- `hsh-pepper:<keyver>:<inner-phc>` wrapper format so rotation is
  non-destructive.
- Fail-closed refusal when a peppered hash hits a pepperless policy.

### Phase 4 — FIPS backend (contract; runtime deferred) ⚠️

Partially closes: #143 (contract). Runtime moves to v0.0.10
milestone #2.

- `Backend::Fips140Required` enforced today — `api::hash` refuses
  to mint Argon2 hashes under this backend, only PBKDF2.
- `Backend::fips_available_in_build()` returns `false` today;
  flipped to `true` by the dedicated `hsh-backend-awslc` follow-up
  when `aws-lc-rs` is wired up.
- See [`doc/FIPS.md`](./doc/FIPS.md) and
  [ADR-0004](./doc/adr/0004-fips-strategy.md).

### Phase 5 — CLI & ecosystem ✅

Closes: #144

- `hsh-cli` binary with six subcommands: `hash`, `verify`,
  `rehash`, `inspect`, `calibrate`, `completions`.
- Shell completions for bash / zsh / fish / PowerShell / elvish.
- Multi-platform packaging templates under `pkg/`: Docker, GHCR,
  Homebrew, Debian, Arch / AUR, Scoop.
- Snapshot tests via `insta` for every operator-facing format.

### Phase 6 — General hashing primitives ✅

Closes: #145 #137

- `hsh-digest` crate ships SHA-256/384/512, SHA3-256/384/512,
  BLAKE3-256 — both one-shot (`hash`) and streaming (`Hasher`).
- 13 KAT vectors from NIST CAVP / RFC 9106 §5 / OpenBSD bcrypt /
  RFC 6070.
- KangarooTwelve / TurboSHAKE (RFC 9861) and Ascon-Hash256 /
  Ascon-XOF128 (NIST SP 800-232) stubbed pending Rust-impl
  follow-up.

### Phase 7 — v1.0.0 stabilisation foundations ⚠️

Partially closes: #146. v1.0 stabilisation work itself moves to
v0.0.10 milestone #2.

Done in v0.0.9:
- `doc/API-STABILITY.md` — per-symbol Tier 1 / 2 / 3 stability tier
  list + semver bump policy.
- `doc/RELEASE.md` — maintainer release runbook.
- `doc/SUPPORT.md` — where to ask, response windows.

Deferred to v0.0.10+:
- Final v1.0 public API surface freeze.
- Final removal of the `compat-v0_0_x` shim (scheduled for v0.2.0).

## v0.0.10 candidates

Tracked under the [v0.0.10 milestone](https://github.com/sebastienrousseau/hsh/milestone/2).

- #143 — Wire up the `aws-lc-rs` FIPS 140-3 validated backend
  behind the existing `Backend::Fips140Required` contract.
- #146 — Final v1.0 public API surface freeze.
- Per-provider KMS network impls (AWS / GCP / Azure / Vault).
- KangarooTwelve / TurboSHAKE Rust implementation.
- Ascon-Hash256 / Ascon-XOF128 Rust implementation.

## Distro outreach (post-v0.0.9)

Once v0.0.9 lands on `main` and the tag is cut:

- **crates.io** — `cargo publish` in dependency order: `hsh-digest`,
  `hsh-kms`, `hsh`, `hsh-cli`.
- **Homebrew** — open PR to `homebrew/core` after tag → cosign-
  verifiable tarball is on GitHub Releases.
- **Arch / AUR** — `hsh-bin` + `hsh` source packages.
- **Debian / Ubuntu** — `hsh_<version>_<arch>.deb` via the
  packaging templates under `pkg/debian/`.
- **Scoop (Windows)** — `pkg/scoop/hsh.json` manifest.
- **GHCR (Docker)** — `ghcr.io/sebastienrousseau/hsh:<version>`
  distroless image.

All channels listed in [`pkg/README.md`](./pkg/README.md).
