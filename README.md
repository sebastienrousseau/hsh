<p align="center">
  <img src="https://cloudcdn.pro/hsh/v1/logos/hsh.svg" alt="Hash (HSH) logo" width="128" />
</p>

<h1 align="center">Hash (HSH)</h1>

<p align="center">
  <strong>Enterprise password hashing for Rust.</strong>
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/hsh/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/hsh/ci.yml?style=for-the-badge&logo=github" alt="Build" /></a>
  <a href="https://crates.io/crates/hsh"><img src="https://img.shields.io/crates/v/hsh.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Crates.io" /></a>
  <a href="https://docs.rs/hsh"><img src="https://img.shields.io/badge/docs.rs-hsh-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs.rs" /></a>
  <a href="https://codecov.io/gh/sebastienrousseau/hsh"><img src="https://img.shields.io/codecov/c/github/sebastienrousseau/hsh?style=for-the-badge&logo=codecov" alt="Coverage" /></a>
  <a href="https://lib.rs/crates/hsh"><img src="https://img.shields.io/badge/lib.rs-v0.0.9-orange.svg?style=for-the-badge" alt="lib.rs" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/sebastienrousseau/hsh"><img src="https://img.shields.io/ossf-scorecard/github.com/sebastienrousseau/hsh?style=for-the-badge&label=OpenSSF" alt="OpenSSF Scorecard" /></a>
</p>

---

## Contents

**Getting started**: [Install](#install) · [Quick Start](#quick-start) · [Algorithms](#algorithms) · [The hsh family](#the-hsh-family)

**Library reference**: [Cargo features](#cargo-features) · [MSRV per crate](#msrv-per-crate) · [Policy / PolicyBuilder](#policy--policybuilder)

**Operational**: [Capabilities in v0.0.9](#capabilities-in-v009) · [Benchmarks](#benchmarks) · [Ecosystem comparison](#ecosystem-comparison) · [Security](#security) · [When not to use hsh](#when-not-to-use-hsh) · [Development](#development) · [Documentation](#documentation) · [License](#license)

---

## Install

### As a Rust library

```toml
[dependencies]
hsh = "0.0.9"
```

### As a CLI tool

```bash
cargo install hsh-cli                                       # crates.io
brew install sebastienrousseau/tap/hsh                       # Homebrew (post-release)
curl -fsSL https://github.com/sebastienrousseau/hsh/releases/latest/download/hsh-installer.sh | sh
docker run --rm -i ghcr.io/sebastienrousseau/hsh:0.0.9 --help
```

Multi-channel packaging templates are under [`pkg/`](pkg/) (Docker, Homebrew, Debian, Arch AUR, Scoop).

### Build from source

```bash
git clone https://github.com/sebastienrousseau/hsh
cd hsh
make ci                                                      # fmt + clippy + test + doc
```

### MSRV per crate

| Crate                                  | MSRV     | Why                                                              |
| -------------------------------------- | -------- | ---------------------------------------------------------------- |
| [`hsh`](crates/hsh/)                   | **1.75** | Library; broad consumability is the goal                          |
| [`hsh-kms`](crates/hsh-kms/)           | **1.75** | Same as `hsh` — KMS providers slot in behind feature flags        |
| [`hsh-digest`](crates/hsh-digest/)     | **1.75** | Same as `hsh` — re-exports RustCrypto primitives                  |
| [`hsh-cli`](crates/hsh-cli/)           | **1.85** | Edition 2024; clap 4.5 + derive macros benefit from newer Rust    |

CI gates the MSRV per crate on every PR via `cargo +1.75 check` and `cargo +1.85 check`.

---

## Quick Start

```rust
use hsh::{api, Policy, Outcome};

# fn main() -> Result<(), hsh::Error> {
let policy = Policy::owasp_minimum_2025();
let stored = api::hash(&policy, "correct horse battery staple")?;

let (outcome, rehashed) = api::verify_and_upgrade(
    &policy,
    "correct horse battery staple",
    &stored,
)?;

match (outcome, rehashed) {
    (Outcome::Valid { needs_rehash: true }, Some(new_phc)) => {
        // Policy drifted; persist the fresh hash.
        persist(new_phc);
    }
    (Outcome::Valid { .. }, _) => { /* OK */ }
    (Outcome::Invalid, _) => deny(),
}
# Ok(()) }
# fn persist(_: String) {}
# fn deny() {}
```

For the CLI:

```bash
echo -n "correct horse battery staple" | hsh hash --algorithm argon2id
echo -n "correct horse battery staple" | hsh verify -H '$argon2id$...'
hsh inspect '$argon2id$...'
hsh calibrate --algorithm argon2id --target-ms 500
hsh completions zsh > ~/.zsh/functions/_hsh
```

---

## Algorithms

| Algorithm      | Status                  | OWASP-2025 default                 | Notes                                                            |
| -------------- | ----------------------- | ---------------------------------- | ---------------------------------------------------------------- |
| **Argon2id**   | ✅ Recommended          | `m = 19 456 KiB`, `t = 2`, `p = 1` | RFC 9106 §4 first-recommended preset also shipped                |
| Argon2i        | Verify-only (legacy)    | (same params)                      | `#[deprecated]`, `cfg(feature = "compat-v0_0_x")`                 |
| Argon2d        | Available               | (same params)                      | Exposed for completeness                                          |
| **Bcrypt**     | ✅ Hardened             | `cost = 10`                        | 72-byte safety rail (CVE-2025-22228); opt-in `with_prehash`       |
| **Scrypt**     | ✅ Configurable          | `N = 2^17`, `r = 8`, `p = 1`       | Configurable via `ScryptParams`                                  |
| **PBKDF2**     | ✅ FIPS-eligible        | `iters = 600 000`, `dk_len = 32`   | HMAC-SHA-256 / SHA-512; `Backend::Fips140Required` path           |

---

## The hsh family

| Crate                                              | Role                                                                |
| -------------------------------------------------- | ------------------------------------------------------------------- |
| [`hsh`](crates/hsh/)                               | Core library — multi-algorithm hash + verify + rehash               |
| [`hsh-cli`](crates/hsh-cli/)                       | `hsh` binary — `hash` / `verify` / `rehash` / `inspect` / `calibrate` |
| [`hsh-kms`](crates/hsh-kms/)                       | `Pepper` trait + KMS providers (AWS / GCP / Azure / Vault stubs)    |
| [`hsh-digest`](crates/hsh-digest/)                 | General-purpose digests (SHA-2 / SHA-3 / BLAKE3) — **not for passwords** |

Per-crate READMEs live under `crates/<name>/README.md`.

---

## Cargo features

| Feature           | Crate         | Pulls in                                       | Adds                                                  |
| ----------------- | ------------- | ---------------------------------------------- | ----------------------------------------------------- |
| `pepper`          | `hsh`         | `hsh-kms`                                      | HMAC-SHA-256 pepper + KMS-backed key rotation         |
| `fips`            | `hsh`         | (forward-compat marker)                        | Marker for future `aws-lc-rs` FIPS routing            |
| `compat-v0_0_x`   | `hsh`         | —                                              | Re-exposes the v0.0.x stringly-typed API for migration |
| `aws-kms`         | `hsh-kms`     | (future) `aws-sdk-kms`                         | AWS KMS pepper backend (stub today)                    |
| `gcp-kms`         | `hsh-kms`     | (future) `gcloud-kms`                          | GCP Cloud KMS pepper backend (stub today)              |
| `azure-key-vault` | `hsh-kms`     | (future) `azure_security_keyvault`             | Azure Key Vault pepper backend (stub today)            |
| `hashicorp-vault` | `hsh-kms`     | (future) `vaultrs`                             | HashiCorp Vault Transit backend (stub today)           |
| `sha2`            | `hsh-digest`  | `sha2`                                         | SHA-256 / 384 / 512                                   |
| `sha3`            | `hsh-digest`  | `sha3`                                         | SHA3-256 / 384 / 512                                  |
| `blake3`          | `hsh-digest`  | `blake3`                                       | BLAKE3-256                                            |
| `k12`             | `hsh-digest`  | (future) `k12`                                 | KangarooTwelve / TurboSHAKE (RFC 9861, Oct 2025) — stub |
| `ascon`           | `hsh-digest`  | (future) `ascon-hash`                          | Ascon-Hash256 / Ascon-XOF128 (NIST SP 800-232) — stub  |

---

## Policy / PolicyBuilder

Three ways to construct a `Policy`:

```rust
use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};
use hsh::Backend;

// 1. Preset (most common):
let p1 = Policy::owasp_minimum_2025();

// 2. Builder seeded from preset:
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

Read fields via accessors: `policy.primary()`, `policy.backend()`, `policy.argon2_params()`, `policy.bcrypt_params()`, `policy.scrypt_params()`, `policy.pbkdf2_params()`, `policy.has_pepper()`.

Full stability tier list: [`doc/API-STABILITY.md`](doc/API-STABILITY.md).

---

## Capabilities in v0.0.9

| Theme                       | Headline deliverables                                                                |
| --------------------------- | ------------------------------------------------------------------------------------ |
| **Foundation**              | Cargo workspace; per-crate MSRV; `#![forbid(unsafe_code)]` workspace-wide            |
| **Algorithms**              | Argon2id / bcrypt / scrypt / PBKDF2; SHA-2 / SHA-3 / BLAKE3 (in `hsh-digest`)         |
| **Storage formats**         | PHC strings (Argon2id / scrypt / PBKDF2); MCF (`$2b$…`) for bcrypt; `hsh-pepper:` wrap |
| **Verify + auto-rehash**    | Algorithm drift, parameter drift, PRF drift, pepper-version drift all trigger rehash |
| **Pepper integration**      | `hsh-kms` with `Pepper` trait, `LocalPepper`, 4 KMS provider stubs                    |
| **FIPS contract**           | `Backend::Fips140Required` + fail-closed `api::hash`                                  |
| **Operational hardening**   | 5 libfuzzer targets, 7 proptest invariants, Miri focused/full, SLSA L3, cosign       |
| **CLI**                     | `hsh-cli` with 6 subcommands, shell completions, multi-platform packaging templates  |
| **Documentation**           | 7 ADRs, 5 migration guides, API stability + release runbook + support doc            |
| **Test coverage**           | ~210 tests across 19 binaries + 13 KAT vectors + 7 property invariants               |

Phase-by-phase breakdown: [`CHANGELOG.md`](CHANGELOG.md). Live milestone: <https://github.com/sebastienrousseau/hsh/milestone/1>.

---

## Benchmarks

Criterion benchmarks live in [`crates/hsh/benches/criterion.rs`](crates/hsh/benches/criterion.rs) and are organised into three groups:

| Group                  | What it measures                                                                                |
| ---------------------- | ----------------------------------------------------------------------------------------------- |
| `hash_owasp_2025`      | `api::hash` cost at OWASP-2025 minimum parameters per algorithm                                  |
| `verify_owasp_2025`    | `api::verify_and_upgrade` cost at the same parameters                                            |
| `fast_params`          | Same shape with non-production parameters used by tests / fuzz / proptest                        |

Reproduce:

```bash
cargo bench --bench benchmark              # full criterion run
cargo bench --bench benchmark -- --quick   # smoke run (~30s total)
```

Published numbers + per-host calibration guide live in [`doc/BENCHMARKS.md`](doc/BENCHMARKS.md).

---

## Ecosystem comparison

| Crate                                     | Drop-in for `hsh`? | Key gap vs `hsh`                                              |
| ----------------------------------------- | ------------------ | ------------------------------------------------------------- |
| [`argonautica`](https://crates.io/crates/argonautica)   | No — unmaintained since 2019 | No PHC strings; no rehash-on-verify; FFI to `libargon2` |
| [`rust-argon2`](https://crates.io/crates/rust-argon2)   | Partial — Argon2 only        | No multi-algorithm fallback; no pepper; no FIPS contract |
| [`bcrypt`](https://crates.io/crates/bcrypt)             | Verify-only — bcrypt only    | No 72-byte safety rail; no auto-rehash; no Argon2 path  |
| [`password-auth`](https://crates.io/crates/password-auth) | Partial — RustCrypto facade  | No pepper; no FIPS contract; no CLI                     |
| [`djangohashers`](https://crates.io/crates/djangohashers) | No — Django format only      | Custom string format; no auto-rehash to modern KDFs     |

Full feature matrix: [`doc/COMPARISON.md`](doc/COMPARISON.md).

Migration guides for each of these are under [`doc/MIGRATION-from-*.md`](doc/).

---

## Security

### Defence in depth

- **Constant-time verify** — `subtle::ConstantTimeEq` everywhere a hash is compared.
- **Zeroized on drop** — password / hash / salt / pepper-key buffers wiped via `zeroize::ZeroizeOnDrop`.
- **`#![forbid(unsafe_code)]`** — workspace-wide (ADR-0006).
- **Bcrypt 72-byte safety rail** — rejects oversized inputs unless `with_prehash` is set (CVE-2025-22228 class).
- **OsRng-only salt** — never `vrd` or any non-CSPRNG source.
- **FIPS fail-closed** — `Backend::Fips140Required` refuses to mint hashes when the build can't satisfy it.
- **Pepper refuse-without-key** — a peppered hash verified against a pepperless policy returns `Outcome::Invalid`, never silently fails open.

### Resource posture

| Surface                | Default                                | Why                                                                            |
| ---------------------- | -------------------------------------- | ------------------------------------------------------------------------------ |
| Argon2id memory cost   | `m = 19 456 KiB` (~19 MiB)             | OWASP-2025 minimum                                                              |
| PBKDF2 iterations      | `600 000` (SHA-256), `210 000` (SHA-512) | OWASP-2025 minimums                                                             |
| Bcrypt input limit     | 72 bytes (rejects)                     | Without `with_prehash`, refuses to silently truncate                            |
| Scrypt N               | `2^17`                                 | OWASP-2025 minimum (was `2^14` in v0.0.8; bumped in v0.0.9)                     |
| Salt source            | `getrandom::OsRng`                     | Crypto-quality CSPRNG only                                                      |
| Stack-overflow guard   | `overflow-checks = true` in release    | Arithmetic on cost parameters must never silently wrap                          |

### Supply chain

- **`cargo-deny`** + **`cargo-audit`** on every PR and weekly cron.
- **SLSA L3** build-provenance via `actions/attest-build-provenance` on every tagged release.
- **Sigstore keyless signing** via `cosign sign-blob` on every release artefact.
- **SBOM** via `cargo-about` (NOTICE.md attached to the release).
- **OpenSSF Scorecard** weekly; SARIF uploaded to code-scanning.
- **5 libfuzzer harnesses** running nightly via `.github/workflows/fuzz.yml`.
- **Miri** per-PR (focused, 60 min) + weekly full sweep (90 min).
- **Pinned GitHub Actions** by SHA where the ecosystem supports; Dependabot updates the pins.

Vulnerability reporting policy: [`SECURITY.md`](SECURITY.md).

---

## When not to use hsh

- **Quantum-resistant signatures / KEMs** — use [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) (ML-KEM, ML-DSA, SLH-DSA).
- **General-purpose hashing only** — use [`hsh-digest`](crates/hsh-digest/) directly; the password APIs in `hsh` are deliberately slow.
- **Streaming HMAC / HKDF** — use the RustCrypto `hmac` / `hkdf` crates.
- **Embedded / `no_std`** — `hsh` requires `std`; for constrained environments use `hsh-digest` (`no_std`-friendly).
- **Self-validating FIPS module** — `hsh` itself isn't FIPS-validated. The contract delegates to `aws-lc-rs` (Phase 4 follow-up).

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

### CI workflows

| Workflow                                                 | Trigger                | What it does                                       |
| -------------------------------------------------------- | ---------------------- | -------------------------------------------------- |
| [`ci.yml`](.github/workflows/ci.yml)                     | PR + push to `main`    | fmt + clippy + test + doc; matrix MSRV gates       |
| [`miri.yml`](.github/workflows/miri.yml)                 | PR + Sunday 03:00 UTC  | Focused per-PR + full weekly sweep                  |
| [`scorecard.yml`](.github/workflows/scorecard.yml)       | Weekly + push to main  | OpenSSF Scorecard; SARIF uploaded                  |
| [`fuzz.yml`](.github/workflows/fuzz.yml)                 | Daily 04:00 UTC cron   | 5-target matrix; 10 min budget per target          |
| [`supply-chain.yml`](.github/workflows/supply-chain.yml) | Dep change + weekly    | `cargo-deny` + `cargo-audit`                       |
| [`release.yml`](.github/workflows/release.yml)           | Tag `v*.*.*`           | Quality gate; SBOM; SLSA L3; sigstore; cargo publish |

---

## Documentation

| Doc                                                          | What's in it                                                          |
| ------------------------------------------------------------ | --------------------------------------------------------------------- |
| [`doc/API-STABILITY.md`](doc/API-STABILITY.md)               | Per-crate per-symbol stability tier + semver bump policy               |
| [`doc/RELEASE.md`](doc/RELEASE.md)                           | Maintainer release runbook                                            |
| [`doc/SUPPORT.md`](doc/SUPPORT.md)                           | Where to ask, response windows                                        |
| [`doc/FIPS.md`](doc/FIPS.md)                                 | FIPS 140-3 deployment + Argon2 → PBKDF2 migration playbook             |
| [`doc/KMS-INTEGRATION.md`](doc/KMS-INTEGRATION.md)           | Pepper / KMS deployment for AWS / GCP / Azure / Vault                 |
| [`doc/BENCHMARKS.md`](doc/BENCHMARKS.md)                     | Criterion methodology + reproduction commands                          |
| [`doc/COMPARISON.md`](doc/COMPARISON.md)                     | Feature matrix vs 5 ecosystem crates                                  |
| [`doc/MIGRATION-from-*.md`](doc/)                            | Migration guides (5: argonautica, rust-argon2, bcrypt, djangohashers, password-hash) |
| [`doc/adr/`](doc/adr/)                                       | 7 ADRs covering scope, FIPS, pepper, unsafe-code, v1.0 contract        |
| [`doc/pre-commit.md`](doc/pre-commit.md)                     | Local pre-commit hook setup                                            |
| [`SECURITY.md`](SECURITY.md)                                 | Vulnerability reporting + threat model                                 |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                         | Setup, signed commits, PR guidelines                                  |
| [`CHANGELOG.md`](CHANGELOG.md)                               | Keep-a-Changelog format, version-by-version breakdown                  |
| Per-crate READMEs                                            | [`hsh`](crates/hsh/) · [`hsh-cli`](crates/hsh-cli/) · [`hsh-kms`](crates/hsh-kms/) · [`hsh-digest`](crates/hsh-digest/) |

---

## License

Dual-licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/licenses/MIT), at your option.

<p align="right"><a href="#hash-hsh">Back to top</a></p>
