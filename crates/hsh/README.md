<p align="center">
  <img src="https://cloudcdn.pro/hsh/v1/logos/hsh.svg" alt="hsh logo" width="128" />
</p>

<h1 align="center">hsh</h1>

<p align="center">
  <strong>Enterprise password hashing for Rust — Argon2id / bcrypt / scrypt / PBKDF2 with PHC, KMS pepper, and a FIPS contract.</strong>
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/hsh/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/hsh/ci.yml?style=for-the-badge&logo=github" alt="Build" /></a>
  <a href="https://crates.io/crates/hsh"><img src="https://img.shields.io/crates/v/hsh.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Crates.io" /></a>
  <a href="https://docs.rs/hsh"><img src="https://img.shields.io/badge/docs.rs-hsh-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs.rs" /></a>
  <a href="https://lib.rs/crates/hsh"><img src="https://img.shields.io/badge/lib.rs-v0.0.9-orange.svg?style=for-the-badge" alt="lib.rs" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/sebastienrousseau/hsh"><img src="https://img.shields.io/ossf-scorecard/github.com/sebastienrousseau/hsh?style=for-the-badge&label=OpenSSF" alt="OpenSSF Scorecard" /></a>
</p>

---

## Contents

**Getting started**: [Install](#install) · [Quick Start](#quick-start) · [Algorithms](#algorithms) · [The hsh ecosystem](#the-hsh-ecosystem)

**Library reference**: [Cargo features](#cargo-features) · [The Policy / PolicyBuilder model](#the-policy--policybuilder-model) · [verify_and_upgrade contract](#verify_and_upgrade-contract) · [Pepper integration](#pepper-integration) · [FIPS contract](#fips-contract)

**Operational**: [Security](#security) · [When not to use hsh](#when-not-to-use-hsh) · [Documentation](#documentation) · [Development](#development) · [License](#license)

---

## Install

```toml
[dependencies]
hsh = "0.0.9"
```

MSRV **1.75** stable. Works on Linux, macOS, Windows.

For the command-line tool, see [`hsh-cli`](../hsh-cli/).

### Optional features

| Feature           | Pulls in                          | Adds                                                 |
| ----------------- | --------------------------------- | ---------------------------------------------------- |
| `default`         | —                                 | Argon2id / bcrypt / scrypt / PBKDF2; PHC + MCF parse |
| `pepper`          | [`hsh-kms`](../hsh-kms/)          | HMAC-SHA-256 pepper + KMS-backed key rotation        |
| `fips`            | (forward-compat marker)           | Marker for the future `aws-lc-rs` FIPS routing       |
| `compat-v0_0_x`   | —                                 | Re-exposes the v0.0.x stringly-typed API for migration |

The companion crates ([`hsh-kms`](../hsh-kms/), [`hsh-digest`](../hsh-digest/), [`hsh-cli`](../hsh-cli/)) have their own feature flags — see each crate's README.

---

## Quick Start

```rust
use hsh::{api, Policy, Outcome};

# fn main() -> Result<(), hsh::Error> {
let policy = Policy::owasp_minimum_2025();
let stored = api::hash(&policy, "correct horse battery staple")?;

// `stored` is a PHC string: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>

let outcome = api::verify_and_upgrade(
    &policy,
    "correct horse battery staple",
    &stored,
)?;

match outcome {
    (Outcome::Valid { needs_rehash: true }, Some(new_phc)) => persist(new_phc),
    (Outcome::Valid { needs_rehash: false }, _) => { /* ok */ }
    (Outcome::Invalid, _) => deny(),
}
# Ok(()) }
# fn persist(_: String) {}
# fn deny() {}
```

---

## Algorithms

| Algorithm      | Status                  | OWASP-2025 default                 | Notes                                                            |
| -------------- | ----------------------- | ---------------------------------- | ---------------------------------------------------------------- |
| **Argon2id**   | ✅ Recommended          | `m = 19 456 KiB`, `t = 2`, `p = 1` | RFC 9106 §4 first-recommended preset also shipped                |
| Argon2i        | Verify-only (legacy)    | (same params)                      | `#[deprecated]` — for migrating existing Argon2i hashes only      |
| Argon2d        | Available               | (same params)                      | Exposed for completeness; not recommended                         |
| **Bcrypt**     | ✅ Hardened             | `cost = 10`                        | 72-byte safety rail (CVE-2025-22228 class); `with_prehash` opt-in |
| **Scrypt**     | ✅ Configurable          | `N = 2^17`, `r = 8`, `p = 1`       | Configurable via `ScryptParams`                                  |
| **PBKDF2**     | ✅ FIPS-eligible        | `iters = 600 000`, `dk_len = 32`   | HMAC-SHA-256 / SHA-512 — `Backend::Fips140Required` path          |

---

## The hsh ecosystem

| Crate                                       | Role                                                                |
| ------------------------------------------- | ------------------------------------------------------------------- |
| **`hsh`** (this crate)                      | Core library — multi-algorithm hash + verify + rehash               |
| [`hsh-cli`](../hsh-cli/)                    | `hsh` binary — `hash` / `verify` / `rehash` / `inspect` / `calibrate` |
| [`hsh-kms`](../hsh-kms/)                    | `Pepper` trait + KMS integrations (AWS / GCP / Azure / Vault stubs) |
| [`hsh-digest`](../hsh-digest/)              | General-purpose digests (SHA-2 / SHA-3 / BLAKE3) — **not for passwords** |

---

## The Policy / PolicyBuilder model

A [`Policy`] captures the algorithm + parameters + backend choices for a deployment. Construct via preset, builder, or combinator:

```rust
use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};
use hsh::Backend;

// Preset (most common):
let p1 = Policy::owasp_minimum_2025();

// Builder seeded from a preset, overriding select fields:
let p2 = PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
    .primary(PrimaryAlgorithm::Bcrypt)
    .build()
    .unwrap();

// Builder from scratch (must set primary):
let p3 = PolicyBuilder::new()
    .primary(PrimaryAlgorithm::Pbkdf2)
    .backend(Backend::Native)
    .build()
    .unwrap();
```

Fields are non-public — read via accessors (`primary()`, `backend()`, `argon2_params()`, etc.). See [doc/API-STABILITY.md](../../doc/API-STABILITY.md) for the full stability tier list.

---

## `verify_and_upgrade` contract

```text
            ┌──────────────────────────────────────┐
            │ api::verify_and_upgrade(policy, pw,  │
            │                         stored)      │
            └──────────────────────────────────────┘
                              │
                ┌─────────────┴─────────────┐
                ▼                           ▼
       Stored hash matches?         Stored hash doesn't match
                │                           │
                ▼                           ▼
   Algorithm + params           ┌─ Outcome::Invalid
   meet current policy?         │  rehashed = None
   ┌──────┴──────┐
   ▼ yes         ▼ no
Outcome::Valid   Outcome::Valid
{needs_rehash    {needs_rehash
 :false},        :true},
rehashed=None    rehashed=Some(new_phc)
```

Supports PHC strings for Argon2id / Argon2i / Argon2d / scrypt / PBKDF2, MCF (`$2b$…`) for bcrypt, and the wrapper format `hsh-pepper:<keyver>:<inner>` when the `pepper` feature is on.

---

## Pepper integration

Requires the `pepper` feature.

```rust,no_run
use std::sync::Arc;
use hsh::{api, Policy};
use hsh_kms::{KeyVersion, LocalPepper};

# fn main() -> Result<(), hsh::Error> {
let pepper = LocalPepper::builder()
    .add(KeyVersion::new(1), b"v1-pepper-keep-secret-32-bytes!!".to_vec())
    .current(KeyVersion::new(1))
    .build()
    .unwrap();

let policy = Policy::owasp_minimum_2025()
    .with_pepper(Arc::new(pepper));

let stored = api::hash(&policy, "user-password")?;
// stored is "hsh-pepper:1:$argon2id$..."
# Ok(()) }
```

For production deployments, fetch the pepper from your KMS at startup — see [`hsh-kms`](../hsh-kms/) and [`doc/KMS-INTEGRATION.md`](../../doc/KMS-INTEGRATION.md).

---

## FIPS contract

`Policy::fips_140_pbkdf2()` returns a policy with `Backend::Fips140Required`. `api::hash` then refuses to mint hashes with Argon2 / bcrypt / scrypt (no FIPS-validated module exists for any of them), and refuses entirely when the build can't satisfy FIPS. See [`doc/FIPS.md`](../../doc/FIPS.md) for the deployment story.

---

## Security

- **Constant-time verification** — `subtle::ConstantTimeEq` everywhere a hash is compared.
- **Zeroized on drop** — password / hash / salt buffers wiped via `zeroize::ZeroizeOnDrop`.
- **`#![forbid(unsafe_code)]`** workspace-wide (ADR-0006).
- **Bcrypt 72-byte safety rail** — CVE-2025-22228 mitigation.
- **OsRng-only salt** — never `vrd` or any non-CSPRNG source.
- **Structured errors** — `hsh::Error` impls `std::error::Error`.

Vulnerability reporting: see [`SECURITY.md`](../../SECURITY.md).

---

## When not to use hsh

- **Quantum-resistant signatures / KEMs** — use [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) (ML-KEM, ML-DSA, SLH-DSA).
- **General-purpose hashing only** — use [`hsh-digest`](../hsh-digest/) directly; the password APIs here are deliberately slow.
- **Streaming HMAC / KDF** — use the RustCrypto `hmac` / `hkdf` crates.
- **Embedded / `no_std`** — `hsh` requires `std` for OsRng and password_hash; for constrained environments use `hsh-digest` (which is `no_std`-friendly).

---

## Documentation

| Doc                                                                       | What's in it                                                               |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| [`API-STABILITY.md`](../../doc/API-STABILITY.md)                          | Per-symbol stability tier + semver bump policy                              |
| [`FIPS.md`](../../doc/FIPS.md)                                            | FIPS 140-3 deployment + Argon2 → PBKDF2 migration playbook                  |
| [`KMS-INTEGRATION.md`](../../doc/KMS-INTEGRATION.md)                      | Pepper / KMS providers for AWS / GCP / Azure / Vault                       |
| [`COMPARISON.md`](../../doc/COMPARISON.md)                                | Feature matrix vs argonautica / rust-argon2 / bcrypt / password-auth        |
| [`BENCHMARKS.md`](../../doc/BENCHMARKS.md)                                | Criterion methodology + reproduction commands                              |
| [`MIGRATION-from-*.md`](../../doc/)                                       | Migration guides from 5 ecosystem crates                                   |
| [`adr/`](../../doc/adr/)                                                  | 7 Architecture Decision Records                                            |
| [`SECURITY.md`](../../SECURITY.md)                                        | Vulnerability reporting + threat model                                     |

---

## Development

```bash
make ci                # what CI runs on every PR
make test              # full workspace test suite
make miri-focused      # per-PR Miri (60 min budget)
make fuzz-smoke        # 30 s per fuzz target (nightly cargo-fuzz)
make sbom              # cargo-about SBOM
```

See [`CONTRIBUTING.md`](../../CONTRIBUTING.md) for setup, signed commits, and PR guidelines.

---

## License

Dual-licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/licenses/MIT), at your option.

<p align="right"><a href="#hsh">Back to top</a></p>
