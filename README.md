<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

<p align="center">
  <img src="https://cloudcdn.pro/hsh/v1/logos/hsh.svg" alt="Hash (HSH) logo" width="128" />
</p>

<h1 align="center">Hash (HSH)</h1>

<p align="center">
  A multi-algorithm password hashing library for Rust with PHC string
  storage, auto-rehash on policy drift, KMS-backed peppering, and a
  fail-closed FIPS 140-3 contract — written from scratch with
  <code>#![forbid(unsafe_code)]</code> across the workspace.
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/hsh/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/hsh/ci.yml?style=for-the-badge&logo=github" alt="Build" /></a>
  <a href="https://crates.io/crates/hsh"><img src="https://img.shields.io/crates/v/hsh.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Crates.io" /></a>
  <a href="https://docs.rs/hsh"><img src="https://img.shields.io/badge/docs.rs-hsh-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs.rs" /></a>
  <a href="https://codecov.io/gh/sebastienrousseau/hsh"><img src="https://img.shields.io/codecov/c/github/sebastienrousseau/hsh?style=for-the-badge&logo=codecov" alt="Coverage" /></a>
  <a href="https://lib.rs/crates/hsh"><img src="https://img.shields.io/badge/lib.rs-hsh-orange.svg?style=for-the-badge" alt="lib.rs" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/sebastienrousseau/hsh"><img src="https://img.shields.io/ossf-scorecard/github.com/sebastienrousseau/hsh?style=for-the-badge&label=OpenSSF" alt="OpenSSF Scorecard" /></a>
  <a href="https://slsa.dev/spec/v1.0/levels"><img src="https://img.shields.io/badge/SLSA-Level%203-brightgreen?style=for-the-badge" alt="SLSA Level 3" /></a>
</p>

---

## Contents

**Getting started**

- [Install](#install) — Cargo, Homebrew, Arch, Scoop, Docker, source
- [Quick Start](#quick-start) — hash, verify, and auto-rehash in ten lines
- [The hsh ecosystem](#the-hsh-ecosystem) — `hsh`, `hsh-cli`, `hsh-kms`, `hsh-digest` at a glance

**Library reference**

- [One-minute migration from `argonautica`, `rust-argon2`, `bcrypt`, `password-auth`, `djangohashers`](#one-minute-migration) — name-for-name mapping
- [Why this approach?](#why-this-approach) — design rationale
- [Capabilities in v0.0.9](#capabilities-in-v009) — release inventory
- [Algorithms](#algorithms) — Argon2id, bcrypt, scrypt, PBKDF2
- [Policy / PolicyBuilder](#policy--policybuilder) — preset, builder-from-preset, builder-from-scratch
- [Cargo features](#cargo-features) — opt-in matrix
- [Benchmarks](#benchmarks) — headline numbers; full table at [`doc/BENCHMARKS.md`](doc/BENCHMARKS.md)
- [Ecosystem comparison](#ecosystem-comparison) — short matrix; full table at [`doc/COMPARISON.md`](doc/COMPARISON.md)
- [Examples](#examples) — runnable example index

**Operational**

- [When not to use hsh](#when-not-to-use-hsh) — limitations
- [Development](#development) — make targets, fuzzing, Miri, CI
- [Security](#security) — guarantees and compliance
- [Documentation](#documentation) — all reference docs
- [License](#license)

---

## Install

### As a Rust library (crates.io)

```toml
[dependencies]
hsh = "0.0.9"
```

### As a CLI tool

The `hsh` binary ships from the
[`hsh-cli`](https://crates.io/crates/hsh-cli) companion crate
(the `hsh` library crate itself contains no binaries — the split
keeps `clap` + `rpassword` + `anyhow` out of the library's
dependency graph for downstream embedders).

| Channel | Install |
|---|---|
| Cargo (crates.io) | `cargo install hsh-cli --locked` |
| Cargo (from source) | `cargo install --locked --path crates/hsh-cli` |
| Homebrew (personal tap) | `brew tap sebastienrousseau/tap && brew install hsh` |
| Arch Linux (AUR) | `yay -S hsh-bin` (binary) or `yay -S hsh` (source) |
| Scoop (Windows) | `scoop bucket add sebastienrousseau https://github.com/sebastienrousseau/scoop-bucket && scoop install hsh` |
| Debian / Ubuntu (.deb) | `curl -fsSL https://github.com/sebastienrousseau/hsh/releases/latest/download/hsh_0.0.9_amd64.deb -o hsh.deb && sudo dpkg -i hsh.deb` |
| Container (GHCR) | `docker run --rm ghcr.io/sebastienrousseau/hsh:0.0.9 --help` |
| Shell installer | `curl -fsSL https://github.com/sebastienrousseau/hsh/releases/latest/download/hsh-installer.sh \| sh` |

GitHub Releases additionally publish pre-built tarballs for Linux
(gnu + musl), macOS (Intel + Apple Silicon + universal), and Windows
(x86_64, aarch64). Each archive ships with the binary, man page,
shell completions, license bundle, and a cosign keyless signature +
SLSA L3 attestation.

See [`pkg/README.md`](pkg/README.md) for the per-channel maintainer
runbook.

### `pepper` feature

```toml
[dependencies]
hsh = { version = "0.0.9", features = ["pepper"] }
```

Brings in `hsh-kms` and exposes `Policy::with_pepper(...)`. The
`pepper` feature is off by default so applications without a KMS
don't pay the `hmac` / `sha2` cost on the dep graph.

### Build from source

```bash
git clone https://github.com/sebastienrousseau/hsh.git
cd hsh
make ci                                                # fmt + clippy + test + doc
```

**MSRV by crate.** Each workspace crate carries its own
`rust-version`; the CI matrix gates each independently so a satellite
never silently breaks downstream users pinned to the core's floor.

| Crate | MSRV | Why |
|---|---|---|
| [`hsh`](crates/hsh/) (core lib) | **1.75.0** | The committed floor for `default-features = false` + the standard `pepper` feature. Library; broad consumability is the goal. |
| [`hsh-kms`](crates/hsh-kms/) | 1.75.0 | Same floor; KMS providers slot in behind feature flags. |
| [`hsh-digest`](crates/hsh-digest/) | 1.75.0 | Same floor; re-exports RustCrypto primitives. |
| [`hsh-cli`](crates/hsh-cli/) (binary) | 1.85.0 | Edition 2024; `clap` 4.5 + derive macros require a recent stable. |

`rust-toolchain.toml` selects `stable` for local development; the
1.75.0 floor on the core surface is enforced by the dedicated
MSRV CI job on every PR.

---

## Quick Start

```rust
use hsh::{api, Outcome, Policy};

fn main() -> Result<(), hsh::Error> {
    let policy = Policy::owasp_minimum_2025();
    let stored = api::hash(&policy, "correct horse battery staple")?;

    let (outcome, rehashed) = api::verify_and_upgrade(
        &policy,
        "correct horse battery staple",
        &stored,
    )?;

    match outcome {
        Outcome::Valid { needs_rehash: true } => {
            // Policy drifted; persist `rehashed.unwrap()` to keep
            // stored material at the current bar.
        }
        Outcome::Valid { .. } => { /* OK */ }
        Outcome::Invalid => { /* deny */ }
    }
    Ok(())
}
```

The CLI shape is the same three verbs:

```bash
echo -n "correct horse battery staple" | hsh hash --algorithm argon2id
echo -n "correct horse battery staple" | hsh verify -H '$argon2id$v=19$m=19456,t=2,p=1$…'
hsh inspect    '$argon2id$v=19$m=19456,t=2,p=1$…'
hsh calibrate  --algorithm argon2id --target-ms 500
hsh completions zsh > ~/.zsh/functions/_hsh
```

---

## The hsh ecosystem

Four crates ship from this workspace. The library is the core; the
three satellites wrap it for specific delivery surfaces.

| Crate | What it is | Use case |
|---|---|---|
| **[`hsh`](crates/hsh/)** | Library — multi-algorithm password hashing, PHC parser, verify + auto-rehash, FIPS contract | Embed password hashing in any Rust binary or library. |
| **[`hsh-cli`](crates/hsh-cli/)** | One binary: `hsh` (`hash` / `verify` / `rehash` / `inspect` / `calibrate` / `completions`) | CI gates, container images, ad-hoc command-line use. |
| **[`hsh-kms`](crates/hsh-kms/)** | `Pepper` trait + `LocalPepper` + four KMS provider stubs (AWS / GCP / Azure / Vault) | HMAC-SHA-256 server-side peppering with versioned key rotation. |
| **[`hsh-digest`](crates/hsh-digest/)** | General-purpose cryptographic digests (SHA-2 / SHA-3 / BLAKE3) — **not for passwords** | Content addressing, MAC building blocks, non-password digest needs. |

Per-crate READMEs:
[`hsh`](crates/hsh/README.md) · [`hsh-cli`](crates/hsh-cli/README.md) · [`hsh-kms`](crates/hsh-kms/README.md) · [`hsh-digest`](crates/hsh-digest/README.md)

### Per-context quick links

| If you need… | Drop-in config |
|---|---|
| **A drop-in for `argonautica` / `rust-argon2` / `bcrypt` / `password-auth` / `djangohashers`** | [migration guides in `doc/`](doc/) — name-for-name mapping tables, behavioural notes, checklists |
| **FIPS 140-3 deployment + Argon2 → PBKDF2 routing** | [`doc/FIPS.md`](doc/FIPS.md) — fail-closed contract, `aws-lc-rs` integration roadmap |
| **AWS / GCP / Azure / HashiCorp Vault peppering** | [`doc/KMS-INTEGRATION.md`](doc/KMS-INTEGRATION.md) — provider configs, key rotation, `LocalPepper` snapshot pattern |
| **Per-host benchmark calibration** | `hsh calibrate --algorithm argon2id --target-ms 500` + [`doc/BENCHMARKS.md`](doc/BENCHMARKS.md) |
| **Pre-commit / CI gating** | `crates/hsh-cli/examples/*` + the `hsh verify` exit-code contract |

The rest of this README covers the **library** surface (`hsh`
itself). For the satellite crates, jump straight to their READMEs
above.

---

## One-minute migration

Most call sites are mechanical to update. The headline mapping for
the five most common legacy crates is below; per-crate guides with
verified function tables and behavioural notes live in
[`doc/MIGRATION-from-*.md`](doc/).

### From `argonautica` 0.2 *(archived 2019)*

```diff
-[dependencies]
-argonautica = "0.2"
+[dependencies]
+hsh = "0.0.9"
```

```diff
-use argonautica::{Hasher, Verifier};
-let mut h = Hasher::default();
-let stored = h.with_password("hunter2").with_secret_key("server-key").hash()?;
-let ok = Verifier::default().with_hash(&stored).with_password("hunter2").with_secret_key("server-key").verify()?;
+use hsh::{api, Policy};
+let policy = Policy::owasp_minimum_2025();
+let stored = api::hash(&policy, "hunter2")?;
+let (outcome, _) = api::verify_and_upgrade(&policy, "hunter2", &stored)?;
+let ok = outcome.is_valid();
```

### From `rust-argon2` 2.x

```diff
-let cfg = argon2::Config::owasp5();
-let salt = b"saltsaltsalt";
-let stored = argon2::hash_encoded(b"hunter2", salt, &cfg)?;
-let ok    = argon2::verify_encoded(&stored, b"hunter2")?;
+let policy = hsh::Policy::owasp_minimum_2025();
+let stored = hsh::api::hash(&policy, "hunter2")?;
+let (outcome, _) = hsh::api::verify_and_upgrade(&policy, "hunter2", &stored)?;
+let ok = outcome.is_valid();
```

### From `bcrypt` 0.16

```diff
-use bcrypt::{hash, verify, DEFAULT_COST};
-let stored = hash("hunter2", DEFAULT_COST)?;
-let ok     = verify("hunter2", &stored)?;
+use hsh::{api, Policy, PrimaryAlgorithm};
+use hsh::policy::PolicyBuilder;
+let policy = PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
+    .primary(PrimaryAlgorithm::Bcrypt)
+    .build()?;
+let stored = api::hash(&policy, "hunter2")?;
+let (outcome, _) = api::verify_and_upgrade(&policy, "hunter2", &stored)?;
+let ok = outcome.is_valid();
```

### Coming from a different password-hashing crate?

Each crate has a standalone migration guide with TL;DR diff, function-mapping table, behavioural notes, and a checklist:

| Crate | Version | Drop-in for `hsh`? | Migration guide |
|---|---|---|---|
| [`argonautica`](https://crates.io/crates/argonautica) | `0.2.0` (archived 2019) | **no** (FFI wrapper, no PHC strings, no rehash) | [`MIGRATION-from-argonautica.md`](doc/MIGRATION-from-argonautica.md) |
| [`rust-argon2`](https://crates.io/crates/rust-argon2) | `2.1.0` | partial — Argon2 only | [`MIGRATION-from-rust-argon2.md`](doc/MIGRATION-from-rust-argon2.md) |
| [`bcrypt`](https://crates.io/crates/bcrypt) | `0.16.0` | verify-only — bcrypt only | [`MIGRATION-from-bcrypt.md`](doc/MIGRATION-from-bcrypt.md) |
| [`password-auth`](https://crates.io/crates/password-auth) | `0.3.0` | partial — RustCrypto facade | [`MIGRATION-from-password-hash.md`](doc/MIGRATION-from-password-hash.md) |
| [`djangohashers`](https://crates.io/crates/djangohashers) | `1.8.0` | **no** (Django format, not PHC) | [`MIGRATION-from-djangohashers.md`](doc/MIGRATION-from-djangohashers.md) |

If your call sites can't change at all, enable the
`compat-v0_0_x` feature to keep the pre-0.0.9 stringly-typed
shape during cut-over.

---

## Why this approach?

`hsh` targets the niche `argonautica` / `rust-argon2` / `bcrypt` /
`password-auth` occupy — take a password, return a verifiable hash
string, and verify a candidate against it — and is written from
scratch against the OWASP Password Storage Cheat Sheet (2025),
RFC 9106 (Argon2), RFC 7914 (scrypt), and RFC 8018 (PBKDF2). It is
not a fork of any existing crate; the API layer, PHC encoding,
backend dispatch, and pepper integration are independent code on
top of the audited RustCrypto primitives (`argon2`, `pbkdf2`,
`scrypt`, `bcrypt`, `sha2`).

Five architectural choices motivate the rewrite:

1. **Auto-rehash on policy drift.** `api::verify_and_upgrade`
   returns a `(Outcome, Option<String>)` pair — when the stored
   hash uses a weaker algorithm, lower cost parameters, an older
   PBKDF2 PRF, or a previous pepper key version than the live
   `Policy` mandates, the verifier mints a fresh PHC string and
   the caller persists it on next login. No background jobs, no
   "force users to reset on rotation" workflows, no dead-in-DB
   weak hashes that survive the next breach.

2. **`#![forbid(unsafe_code)]` at the workspace root.** No FFI to a
   C library, no raw-pointer dereferences, no `unsafe` blocks in
   any crate. CI enforces the attribute on every push. The
   historical class of `libargon2` / `libcrypto` FFI memory-safety
   CVEs is structurally absent ([ADR-0006](doc/adr/0006-zero-unsafe-policy.md)).

3. **Peppered HMAC with versioned key rotation.** Optional
   `Pepper` trait (in `hsh-kms`) applies HMAC-SHA-256 over the
   password before the KDF — an attacker who exfiltrates the
   password database alone cannot brute-force credentials offline.
   `KeyVersion` is embedded in a custom `hsh-pepper:<version>:<inner>`
   wrapper so rotation is non-destructive; the auto-rehash path
   transparently re-encodes under the new version on next verify.

4. **FIPS 140-3 fail-closed contract.** `Backend::Fips140Required`
   causes `api::hash` to **refuse** to mint a hash unless the build
   can satisfy FIPS 140-3 — never silently degrade to a non-FIPS
   primitive. Argon2 (not FIPS-approved) is automatically routed to
   PBKDF2-HMAC-SHA-256 / SHA-512 under this backend. The contract
   is documented in [`doc/FIPS.md`](doc/FIPS.md); the `aws-lc-rs`
   FIPS backend lands in Phase 4.

5. **Constant-time everywhere it matters.** `subtle::ConstantTimeEq`
   gates every hash comparison; `zeroize::ZeroizeOnDrop` wipes
   password / hash / salt / pepper-key buffers on scope exit;
   `getrandom::OsRng` is the only salt source (never `vrd` or a
   user-supplied seed). The bcrypt path enforces the 72-byte input
   safety rail (CVE-2025-22228 class) unless the caller explicitly
   opts into `with_prehash`.

A few features built on top of those choices:

- **PHC string storage** for Argon2id / scrypt / PBKDF2 + MCF
  (`$2b$…`) for bcrypt + the bespoke `hsh-pepper:` wrapper for
  peppered hashes. Verify accepts all three formats interchangeably.
- **Streaming verify** — `api::verify_and_upgrade` parses the PHC
  envelope, dispatches to the recorded algorithm, and only routes
  through the live `Policy` parameters on the rehash path. Old
  hashes verify at their original cost.
- **CLI symmetry** — every library entry point has a CLI verb of
  the same name (`hsh hash` / `verify` / `rehash` / `inspect` /
  `calibrate`), and `hsh calibrate` measures the host's actual
  Argon2id throughput to suggest cost parameters for a given target
  time budget.

The default profile compiles **eight crates** in the runtime graph:
`argon2`, `bcrypt`, `scrypt`, `pbkdf2`, `password-hash`, `subtle`,
`zeroize`, `getrandom`. **No archived or unmaintained crate appears
in the graph** — `argonautica` (archived 2019), `argon2rs`
(archived 2017), and `openssl` (FFI) are all banned via
[`deny.toml`](deny.toml). `cargo audit`, `cargo deny`, and Miri
are CI gates on every push.

---

## Capabilities in v0.0.9

The 0.0.9 release covers a complete password-hashing stack. See
[`CHANGELOG.md`](CHANGELOG.md) for the detailed inventory; the
table below groups the inventory by capability theme.

| Theme | Headline deliverables |
| :--- | :--- |
| **Foundation** | Cargo workspace; per-crate MSRV (1.75 lib / 1.85 CLI); `#![forbid(unsafe_code)]` workspace-wide ([ADR-0006](doc/adr/0006-zero-unsafe-policy.md)) |
| **Algorithms** | Argon2id (RFC 9106), Argon2i / Argon2d (verify-only legacy), bcrypt (with 72-byte safety rail), scrypt (RFC 7914), PBKDF2-HMAC-SHA-256 / SHA-512 (RFC 8018) |
| **General hashing** | `hsh-digest` ships SHA-256 / 384 / 512, SHA3-256 / 384 / 512, BLAKE3-256; KangarooTwelve / TurboSHAKE (RFC 9861) and Ascon-Hash256 / Ascon-XOF128 (NIST SP 800-232) are stubbed for Phase 6 follow-up |
| **Storage formats** | PHC strings for Argon2id / scrypt / PBKDF2; MCF (`$2b$…`) for bcrypt; bespoke `hsh-pepper:<keyver>:<inner>` wrapper for peppered hashes |
| **Verify + auto-rehash** | Algorithm drift, parameter drift, PBKDF2-PRF drift, and pepper-version drift all trigger rehash on next successful verify |
| **Pepper integration** | `hsh-kms` with `Pepper` trait, `LocalPepper`, and four KMS provider stubs (AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault Transit) |
| **FIPS contract** | `Backend::Fips140Required` causes `api::hash` to fail closed when Argon2 is requested without a FIPS-approved fallback ([`doc/FIPS.md`](doc/FIPS.md)) |
| **Operational hardening** | 5 libfuzzer targets (nightly), 7 proptest invariants, Miri focused (per-PR, 60 min) + full sweep (weekly, 90 min), SLSA L3 build provenance, sigstore keyless signing, OpenSSF Scorecard |
| **CLI** | `hsh-cli` with 6 subcommands (`hash` / `verify` / `rehash` / `inspect` / `calibrate` / `completions`), shell completions for bash / zsh / fish / PowerShell, multi-platform packaging templates (Docker / Homebrew / Debian / Arch / Scoop) |
| **Documentation** | 7 ADRs (scope, FIPS, pepper, unsafe-code, v1.0 contract, KMS, general-hashing), 5 migration guides, API stability + release runbook + support doc |
| **Test coverage** | 13 KAT vectors (Argon2id from RFC 9106 §5, bcrypt OpenBSD vectors, PBKDF2 RFC 6070), 7 property invariants (round-trip, drift detection, pepper version) |

Phase-by-phase breakdown: [`CHANGELOG.md`](CHANGELOG.md).
Milestone: <https://github.com/sebastienrousseau/hsh/milestone/1>.

---

## Algorithms

| Algorithm | Status | OWASP-2025 default | Notes |
| --- | --- | --- | --- |
| **Argon2id** | ✅ Recommended | `m = 19 456 KiB`, `t = 2`, `p = 1` | RFC 9106 §4; verify-only support for Argon2i / Argon2d |
| **Bcrypt** | ✅ Hardened | `cost = 10` | 72-byte safety rail (CVE-2025-22228); opt-in `with_prehash` |
| **Scrypt** | ✅ Configurable | `N = 2^17`, `r = 8`, `p = 1` | Bumped from `N = 2^14` in v0.0.8; reproduce via `ScryptParams` |
| **PBKDF2** | ✅ FIPS-eligible | `iters = 600 000` (SHA-256) / `210 000` (SHA-512), `dk_len = 32` | Routed under `Backend::Fips140Required` |
| Argon2i | Verify-only (legacy) | (same params) | `#[deprecated]`; gated behind `cfg(feature = "compat-v0_0_x")` |
| Argon2d | Available | (same params) | Exposed for completeness; not OWASP-recommended for passwords |

The verifier accepts **any** of the four production algorithms
above interchangeably; the live `Policy` only governs new hashes
and rehash targets.

---

## Policy / PolicyBuilder

Three ways to construct a `Policy`:

```rust
use hsh::{Backend, Policy, PrimaryAlgorithm};
use hsh::policy::PolicyBuilder;

// 1. Preset (most common):
let p1 = Policy::owasp_minimum_2025();

// 2. Builder seeded from a preset:
let p2 = PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
    .primary(PrimaryAlgorithm::Bcrypt)
    .build()
    .unwrap();

// 3. Builder from scratch (must set primary):
let p3 = PolicyBuilder::new()
    .primary(PrimaryAlgorithm::Pbkdf2)
    .backend(Backend::Native)
    .build()
    .unwrap();
```

Read fields via accessors: `policy.primary()`, `policy.backend()`,
`policy.argon2_params()`, `policy.bcrypt_params()`,
`policy.scrypt_params()`, `policy.pbkdf2_params()`,
`policy.has_pepper()`.

The full per-symbol stability tier list (Tier 1 — stable / Tier 2 —
evolving / Tier 3 — experimental) lives at
[`doc/API-STABILITY.md`](doc/API-STABILITY.md).

---

## Cargo features

All optional integrations are off by default. Enable only what the
application needs.

| Feature | Crate | Pulls in | Adds | Documented in |
| :--- | :--- | :--- | :--- | :--- |
| `pepper` | `hsh` | `hsh-kms` | `Policy::with_pepper(...)`, HMAC-SHA-256 peppering, `KeyVersion` rotation | [`doc/KMS-INTEGRATION.md`](doc/KMS-INTEGRATION.md) |
| `fips` | `hsh` | — | Forward-compat marker for `aws-lc-rs` routing (Phase 4) | [`doc/FIPS.md`](doc/FIPS.md) |
| `compat-v0_0_x` | `hsh` | — | Re-exposes the pre-0.0.9 stringly-typed API for migration | [Migration](#one-minute-migration) |
| `aws-kms` | `hsh-kms` | *(future)* `aws-sdk-kms` | AWS KMS pepper backend (stub today) | [`doc/KMS-INTEGRATION.md`](doc/KMS-INTEGRATION.md) |
| `gcp-kms` | `hsh-kms` | *(future)* `gcloud-kms` | GCP Cloud KMS pepper backend (stub today) | [`doc/KMS-INTEGRATION.md`](doc/KMS-INTEGRATION.md) |
| `azure-key-vault` | `hsh-kms` | *(future)* `azure_security_keyvault` | Azure Key Vault pepper backend (stub today) | [`doc/KMS-INTEGRATION.md`](doc/KMS-INTEGRATION.md) |
| `hashicorp-vault` | `hsh-kms` | *(future)* `vaultrs` | HashiCorp Vault Transit backend (stub today) | [`doc/KMS-INTEGRATION.md`](doc/KMS-INTEGRATION.md) |
| `sha2` *(default)* | `hsh-digest` | `sha2` | SHA-256 / 384 / 512 | `crates/hsh-digest/README.md` |
| `sha3` *(default)* | `hsh-digest` | `sha3` | SHA3-256 / 384 / 512 | `crates/hsh-digest/README.md` |
| `blake3` *(default)* | `hsh-digest` | `blake3` | BLAKE3-256 | `crates/hsh-digest/README.md` |
| `k12` | `hsh-digest` | *(future)* `k12` | KangarooTwelve / TurboSHAKE128/256 (RFC 9861, Oct 2025) — stub | [Capabilities](#capabilities-in-v009) |
| `ascon` | `hsh-digest` | *(future)* `ascon-hash` | Ascon-Hash256 / Ascon-XOF128 (NIST SP 800-232 final, Aug 2025) — stub | [Capabilities](#capabilities-in-v009) |

```toml
# Example: peppered password hashing with AWS KMS backend
[dependencies]
hsh = { version = "0.0.9", features = ["pepper"] }
hsh-kms = { version = "0.0.9", features = ["aws-kms"] }
```

---

## Benchmarks

Criterion benchmarks live in
[`crates/hsh/benches/criterion.rs`](crates/hsh/benches/criterion.rs)
and are organised into three groups:

| Group | What it measures |
| --- | --- |
| `hash_owasp_2025` | `api::hash` cost at OWASP-2025 minimum parameters per algorithm |
| `verify_owasp_2025` | `api::verify_and_upgrade` cost at the same parameters |
| `fast_params` | Same shape with non-production parameters used by tests / fuzz / proptest |

Headline numbers — _placeholder; fill in after running
`cargo bench --bench benchmark` on your reference host_:

| Operation | Algorithm | OWASP-2025 params | Median | Notes |
| --- | --- | ---: | ---: | --- |
| `api::hash` | Argon2id | `m=19 456 KiB`, `t=2`, `p=1` | **TBD ms** | _Reference host: Apple M4 / aarch64_ |
| `api::hash` | bcrypt | `cost=10` | **TBD ms** | _Reference host: Apple M4 / aarch64_ |
| `api::hash` | scrypt | `N=2^17`, `r=8`, `p=1` | **TBD ms** | _Reference host: Apple M4 / aarch64_ |
| `api::hash` | PBKDF2-SHA256 | `iters=600 000` | **TBD ms** | _Reference host: Apple M4 / aarch64_ |
| `api::verify_and_upgrade` | Argon2id | as above | **TBD ms** | _Reference host: Apple M4 / aarch64_ |

Reproduce:

```bash
cargo bench --bench benchmark              # full criterion run
cargo bench --bench benchmark -- --quick   # smoke run (~30 s total)
hsh calibrate --algorithm argon2id --target-ms 500   # per-host parameter suggestion
```

Per-host calibration guide and the full methodology live in
[`doc/BENCHMARKS.md`](doc/BENCHMARKS.md).

---

## Ecosystem comparison

`hsh` is the only Rust password-hashing library that ships
**multi-algorithm verify-with-auto-rehash**, **KMS-backed peppering
with versioned rotation**, **a FIPS 140-3 fail-closed contract**,
**SLSA L3 build provenance**, and a **dedicated CLI** in one
workspace.

The full feature matrix — every row, every column, with the
reading-the-table notes — lives at
**[`doc/COMPARISON.md`](doc/COMPARISON.md)** so the README stays
fast to scan.

Quick orientation:

| Crate | Drop-in for `hsh`? | Key gap vs `hsh` |
| --- | --- | --- |
| [`argonautica`](https://crates.io/crates/argonautica) | **no** (archived 2019) | FFI wrapper; no PHC strings; no rehash-on-verify; unmaintained |
| [`rust-argon2`](https://crates.io/crates/rust-argon2) | partial — Argon2 only | No multi-algorithm fallback; no pepper; no FIPS contract; no CLI |
| [`bcrypt`](https://crates.io/crates/bcrypt) | verify-only — bcrypt only | No 72-byte safety rail; no auto-rehash; no Argon2 / scrypt / PBKDF2 path |
| [`password-auth`](https://crates.io/crates/password-auth) | partial — RustCrypto facade | No pepper; no FIPS contract; no CLI; no calibration |
| [`djangohashers`](https://crates.io/crates/djangohashers) | **no** (Django format only) | Custom string format; no auto-rehash to modern KDFs; no PHC |

Per-crate migration guides at
[`doc/MIGRATION-from-*.md`](doc/).

---

## Examples

Run individual examples per crate:

```bash
cargo run -p hsh-cli   --example quickstart
cargo run -p hsh       --example quickstart
cargo run -p hsh       --example fips_policy
cargo run -p hsh       --example migration_from_bcrypt
cargo run -p hsh-kms   --example local_pepper
cargo run -p hsh-kms   --example rotation
cargo run -p hsh-kms   --example refuse_without_pepper
cargo run -p hsh-digest --example streaming
cargo run -p hsh-digest --example content_addressing
```

| Category | Example | Purpose |
| :--- | :--- | :--- |
| **Core** | `hsh/examples/quickstart` | Hash + verify + auto-rehash round-trip |
| | `hsh-cli/examples/quickstart` | Library-shape demonstration of what `hsh-cli` does under the hood |
| | `hsh/examples/builder_pattern` | `PolicyBuilder::new()` / `from_preset()` / setters |
| **FIPS** | `hsh/examples/fips_policy` | `Backend::Fips140Required` fail-closed contract |
| **Migration** | `hsh/examples/migration_from_bcrypt` | Bcrypt → Argon2id transparent upgrade on next verify |
| **Pepper / KMS** | `hsh-kms/examples/local_pepper` | `LocalPepper::builder()` keyset construction |
| | `hsh-kms/examples/rotation` | Two-version keyset; verify under old version triggers rehash under new |
| | `hsh-kms/examples/refuse_without_pepper` | Fail-closed when verifier doesn't carry the pepper |
| **General hashing** | `hsh-digest/examples/streaming` | `Hasher::new` + `update` + `finalize` over a `Read` source |
| | `hsh-digest/examples/content_addressing` | Git-style blob hash with BLAKE3 |

---

## When not to use hsh

A few cases where another tool fits better, listed because the
short answer is "we don't do that yet" rather than because of a
disagreement on priorities.

- **You need quantum-resistant signatures / KEMs.** Use
  [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) (ML-KEM,
  ML-DSA, SLH-DSA). `hsh` covers password hashing only; the
  post-quantum signature landscape is moving fast and a dedicated
  library tracks it better.
- **You need a general-purpose digest only.** Use
  [`hsh-digest`](crates/hsh-digest/) directly — the password APIs
  in `hsh` are deliberately slow. Or reach for the underlying
  RustCrypto crates (`sha2`, `sha3`, `blake3`) if you don't want
  the `Algorithm` dispatch layer.
- **You need streaming HMAC / HKDF.** Use the RustCrypto `hmac` /
  `hkdf` crates directly. `hsh-kms` exposes HMAC-SHA-256 only in
  the context of peppering.
- **You're targeting embedded / `no_std`.** `hsh` requires `std`
  (for `getrandom::OsRng` and the PHC parser); `hsh-digest` is
  `no_std`-friendly with `alloc`. For constrained environments
  with no allocator at all, use the RustCrypto crates' streaming
  APIs directly.
- **You need a self-validating FIPS 140-3 module.** `hsh` itself
  isn't FIPS-validated. The `Backend::Fips140Required` contract
  delegates the primitive to `aws-lc-rs` (Phase 4 follow-up);
  for v0.0.9 the backend selection refuses Argon2 and routes to
  the audited PBKDF2 path.

If you hit a case that should be on this list, please open an
issue — that's how it gets fixed or moved into the supported set.

---

## Development

```bash
make ci              # what CI runs on every PR (fmt + clippy + test + doc)
make test            # full workspace test suite
make miri-focused    # per-PR Miri (60 min budget)
make miri-full       # full Miri sweep (90 min budget)
make fuzz-smoke      # 30 s per fuzz target (nightly cargo-fuzz)
make bench           # full criterion bench suite
make bench-quick     # criterion --quick smoke
make deny            # cargo-deny check all sections
make audit-strict    # cargo-audit --deny warnings
make sbom            # cargo-about NOTICE.md
make coverage        # cargo llvm-cov → lcov.info + HTML report
make calibrate       # measure Argon2id params for ~500 ms target
```

### Fuzzing

Five `cargo-fuzz` targets ship under
[`fuzz/fuzz_targets/`](fuzz/fuzz_targets/):

```bash
cargo +nightly fuzz run fuzz_api_round_trip      # api::hash → api::verify_and_upgrade
cargo +nightly fuzz run fuzz_phc_parse           # PHC envelope parser robustness
cargo +nightly fuzz run fuzz_argon2id_verify     # Argon2id verify with crafted PHC strings
cargo +nightly fuzz run fuzz_bcrypt_verify       # bcrypt verify with crafted MCF strings
cargo +nightly fuzz run fuzz_legacy_from_string  # compat-v0_0_x deserialisation surface
```

Seed corpus included in `fuzz/corpus/<target>/`. Nightly cron
runs each target for 10 minutes via
[`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml); any
crash uploads to artefacts for triage.

### Miri (UB / aliasing / leak verification)

`hsh` is `#![forbid(unsafe_code)]` so Miri does not police `hsh`'s
own code — every byte is checked at compile time. The reason a
Miri job exists is to verify the *interaction* with the runtime
dependencies (`argon2`, `bcrypt`, `scrypt`, `pbkdf2`, `subtle`,
`zeroize`, `getrandom`, `hmac`, `sha2` — RustCrypto uses `unsafe`
internally for SIMD and constant-time primitives) is sound.

```bash
make miri-focused      # focused suite — api + backend_policy (per-PR, 60 min)
make miri-full         # full sweep (weekly, 90 min)

# Or invoke the script directly:
./scripts/miri.sh focused
./scripts/miri.sh full
```

The CI matrix runs the focused suite on every PR (`miri.yml`) and
the full sweep on Sunday 03:00 UTC.

### CI workflows

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| [`ci.yml`](.github/workflows/ci.yml) | PR + push to `main` | fmt + clippy + test + doc; cargo-hack feature powerset; cargo-public-api drift; dependency-review |
| [`codeql.yml`](.github/workflows/codeql.yml) | PR + push + weekly | CodeQL on `rust` and `actions` languages; config-pinned to exclude test/example fixtures |
| [`miri.yml`](.github/workflows/miri.yml) | PR + Sunday 03:00 UTC | Focused per-PR + full weekly sweep |
| [`scorecard.yml`](.github/workflows/scorecard.yml) | Weekly + push to main | OpenSSF Scorecard; SARIF uploaded to code-scanning |
| [`fuzz.yml`](.github/workflows/fuzz.yml) | Daily 04:00 UTC cron | 5-target matrix; 10 min budget per target |
| [`supply-chain.yml`](.github/workflows/supply-chain.yml) | Dep change + weekly | `cargo-deny` + `cargo-audit` |
| [`release.yml`](.github/workflows/release.yml) | Tag `v*.*.*` | Quality gate; SBOM via `cargo-about`; SLSA L3; sigstore; `cargo publish` |

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for signed commits and PR
guidelines.

---

## Security

Password hashing is the line of defence between a database breach
and credential reuse across the user's other accounts. The historical
record is brutal — `libargon2` FFI memory bugs, bcrypt's 72-byte
truncation (CVE-2025-22228), pepper-without-rotation deployments
that turned a single key compromise into a permanent loss. `hsh`'s
posture is built around closing each of those vectors at the
*architectural* level, not via opt-in flags.

### RCE prevention (no `unsafe`, no FFI)

**`hsh` does not link to any C library.** No `libargon2`, no
`libcrypto`, no `libssl`. Every primitive in the dependency graph
is pure Rust from the RustCrypto stack, and the workspace declares
`#![forbid(unsafe_code)]` at the crate roots. The historical class
of "FFI to a hash library has a heap-overflow under crafted input"
CVEs is structurally absent — there is no FFI surface to overflow.

Crates banned via [`deny.toml`](deny.toml):

| Crate | Reason |
| --- | --- |
| `argonautica` | Abandoned (last release 2019); use `argon2` RustCrypto |
| `argon2rs` | Abandoned (last release 2017); use `argon2` RustCrypto |
| `openssl` | Prefer `rustls` + RustCrypto / `aws-lc-rs` |

### Configurable resource budgets

OWASP 2025 minimums are the floor, not the ceiling. Every cost
parameter is configurable via the builder — the defaults below
are the values `Policy::owasp_minimum_2025()` ships with.

| Surface | Default | Protects against |
| --- | --- | --- |
| Argon2id memory cost | `m = 19 456 KiB` (~19 MiB) | GPU / ASIC offline cracking |
| Argon2id time cost | `t = 2` | Same |
| Argon2id parallelism | `p = 1` | Server-side parallelism budget |
| Bcrypt cost | `10` | GPU / ASIC offline cracking |
| Bcrypt input length | hard 72-byte cap (rejects) | Silent truncation (CVE-2025-22228 class) |
| Scrypt N | `2^17` | GPU / ASIC offline cracking (bumped from `2^14` in v0.0.8) |
| PBKDF2 iterations | `600 000` (SHA-256), `210 000` (SHA-512) | GPU / ASIC offline cracking |
| Salt source | `getrandom::OsRng` only | Salt prediction (no `vrd`, no user-supplied seed) |
| Stack-overflow guard | `overflow-checks = true` in release | Arithmetic wrap on crafted cost parameters |

### Defence in depth

- **Constant-time verify** — `subtle::ConstantTimeEq` everywhere a
  hash is compared. Timing side-channels on the verify path do not
  leak information about the stored hash.
- **Zeroized on drop** — password / hash / salt / pepper-key buffers
  wiped via `zeroize::ZeroizeOnDrop`. Heap residue after a hash
  operation does not contain the password.
- **Bcrypt 72-byte safety rail** — `api::hash` rejects oversized
  inputs unless `with_prehash` is set. CVE-2025-22228 was the class
  bug where bcrypt silently truncated long passwords.
- **FIPS fail-closed** — `Backend::Fips140Required` causes
  `api::hash` to refuse to mint Argon2 hashes when the build can't
  satisfy FIPS 140-3, never silently degrade ([`doc/FIPS.md`](doc/FIPS.md)).
- **Pepper refuse-without-key** — a peppered hash verified against
  a pepperless policy returns `Outcome::Invalid`, never silently
  fails open.
- **`#![forbid(unsafe_code)]`** — workspace-wide, CI-enforced
  ([ADR-0006](doc/adr/0006-zero-unsafe-policy.md)).

### Supply chain

- `cargo audit` clean — zero advisories.
- `cargo deny` clean — license / advisory / ban / source checks.
- `cargo-hack` feature powerset gated on every PR — every feature
  combination compiles.
- **SLSA L3** build provenance via
  `actions/attest-build-provenance` on every tagged release.
- **Sigstore keyless signing** via `cosign sign-blob` on every
  release artefact.
- **SBOM** via `cargo-about` (`NOTICE.md` attached to the release).
- **OpenSSF Scorecard** weekly; SARIF uploaded to code-scanning.
- **5 libfuzzer harnesses** running nightly.
- **Miri** per-PR (focused, 60 min) + weekly full sweep (90 min).
- **Pinned GitHub Actions by SHA** — every third-party action
  reference in our workflows resolves to a 40-character commit
  hash, with the semver tag in a trailing comment for readability.
- **Signed commits** enforced via CI.

Vulnerability reporting policy:
[`SECURITY.md`](SECURITY.md).

### Notes

- The `hsh-cli` binary reads passwords from stdin (with
  `rpassword` for no-echo TTY input) and never logs them.
  Operators are still responsible for not piping passwords through
  shell history or process-table-visible argv.
- The `compat-v0_0_x` feature exposes the pre-0.0.9 stringly-typed
  API for migration only. It is `#[deprecated]` and will be
  removed in 0.1.0 ([`doc/API-STABILITY.md`](doc/API-STABILITY.md)).

---

## Documentation

| Document | Covers |
| --- | --- |
| [`doc/API-STABILITY.md`](doc/API-STABILITY.md) | Per-crate, per-symbol stability tier (1 — stable / 2 — evolving / 3 — experimental) + semver bump policy |
| [`doc/FIPS.md`](doc/FIPS.md) | FIPS 140-3 deployment, Argon2 → PBKDF2 routing, `aws-lc-rs` integration roadmap |
| [`doc/KMS-INTEGRATION.md`](doc/KMS-INTEGRATION.md) | Pepper / KMS deployment for AWS / GCP / Azure / HashiCorp Vault |
| [`doc/BENCHMARKS.md`](doc/BENCHMARKS.md) | Criterion methodology, reproduction commands, per-host calibration |
| [`doc/COMPARISON.md`](doc/COMPARISON.md) | Feature matrix vs `argonautica`, `rust-argon2`, `bcrypt`, `password-auth`, `djangohashers` |
| [`doc/RELEASE.md`](doc/RELEASE.md) | Maintainer release runbook |
| [`doc/SUPPORT.md`](doc/SUPPORT.md) | Where to ask, response windows |
| [`doc/pre-commit.md`](doc/pre-commit.md) | Local pre-commit hook setup |
| [`doc/MIGRATION-from-*.md`](doc/) | 5 migration guides (argonautica, rust-argon2, bcrypt, djangohashers, password-hash) |
| [`doc/adr/`](doc/adr/) | 7 ADRs covering scope, FIPS, pepper-key versioning, zero-`unsafe` policy, v1.0 contract |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting, supported versions, threat model |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Setup, signed commits, PR guidelines |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-release notes following Keep a Changelog 1.1.0 |

The per-crate READMEs at
[`crates/hsh`](crates/hsh/README.md),
[`crates/hsh-cli`](crates/hsh-cli/README.md),
[`crates/hsh-kms`](crates/hsh-kms/README.md), and
[`crates/hsh-digest`](crates/hsh-digest/README.md) document the
surface specific to each artifact (library API, CLI subcommands,
Pepper trait + KMS providers, digest primitives).

---

## License

Dual-licensed under
[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or
[MIT](https://opensource.org/licenses/MIT), at your option.

See [`CHANGELOG.md`](CHANGELOG.md) for release history.

<p align="right"><a href="#contents">Back to Top</a></p>
