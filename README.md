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

## Install

```bash
cargo add hsh
```

Or add to `Cargo.toml`:

```toml
[dependencies]
hsh = "0.0.9"
```

Requires Rust **1.75** or later. Works on macOS, Linux, and Windows.

For the command-line tool:

```bash
cargo install hsh-cli   # provides the `hsh` binary
```

---

## Overview

`hsh` is a Rust workspace for **storing and verifying passwords** with
multiple memory-hard KDFs behind a single, ergonomic API. v0.0.9
delivers the full enterprise-readiness programme across seven phases.

### Workspace at a glance

| Crate                                           | Purpose                                                                          |
| ----------------------------------------------- | -------------------------------------------------------------------------------- |
| [`hsh`](crates/hsh/)                            | Core library — Argon2id / bcrypt / scrypt / PBKDF2 with PHC, rehash, pepper, FIPS contract |
| [`hsh-cli`](crates/hsh-cli/)                    | `hsh` binary — `hash` / `verify` / `rehash` / `inspect` / `calibrate` / `completions` |
| [`hsh-kms`](crates/hsh-kms/)                    | Pepper trait + KMS integrations (AWS / GCP / Azure / Vault — stubs today)        |
| [`hsh-digest`](crates/hsh-digest/)              | General-purpose digests (SHA-2 / SHA-3 / BLAKE3) — **not for passwords**          |

### Capabilities

- **Multi-algorithm**: Argon2id (default), Argon2i (verify-only legacy),
  bcrypt, scrypt, PBKDF2-HMAC-SHA-256/512.
- **PHC string format** for storage; MCF (`$2b$…`) parsing for legacy
  bcrypt.
- **`verify_and_upgrade`** signals when a stored hash falls below the
  current `Policy`, returning a freshly-minted hash for the caller to
  persist.
- **Pepper support** via the `pepper` feature: HMAC-SHA-256-keyed
  pre-hash from a KMS-held secret, with versioned rotation.
- **FIPS contract** via the `fips` feature: `Backend::Fips140Required`
  fails closed when the build can't satisfy validated crypto.
  See [`doc/FIPS.md`](doc/FIPS.md).
- **Constant-time verification** — `subtle::ConstantTimeEq` everywhere.
- **Zeroized on drop** — password / hash / salt buffers wiped via
  `zeroize`.
- **Structured errors** — `hsh::Error` impls `std::error::Error`.
- **`#![forbid(unsafe_code)]`** workspace-wide (ADR-0006).

### What HSH is *not*

- **Not post-quantum cryptography.** Memory-hard KDFs aren't PQ
  primitives. For PQ, use [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs).
- **Not a self-validating FIPS module.** The `fips` feature is a
  forward-compat marker today; real validation arrives via the
  Phase 4 follow-up `hsh-backend-awslc` crate.

---

## Algorithms

| Algorithm | Status                | Notes                                                            |
| --------- | --------------------- | ---------------------------------------------------------------- |
| **Argon2id**  | ✅ Recommended    | OWASP-2025 default: `m = 19 456 KiB`, `t = 2`, `p = 1`           |
| Argon2i   | Verify-only (legacy)  | `#[deprecated]` — verify-only for migration                       |
| Argon2d   | Available             | For completeness                                                  |
| Bcrypt    | ✅ Hardened           | 72-byte input rejection (CVE-2025-22228 class) + `--with-prehash` |
| Scrypt    | ✅ Configurable       | OWASP-2025 default: `N = 2^17`, `r = 8`, `p = 1`                  |
| PBKDF2    | ✅ FIPS-eligible      | HMAC-SHA-256/512; OWASP-2025: `iters = 600 000` / `210 000`        |

---

## Usage

### Library

```rust
use hsh::{api, Policy, Outcome};

let policy = Policy::owasp_minimum_2025();
let stored = api::hash(&policy, "correct horse battery staple")?;

match api::verify_and_upgrade(&policy, password, &stored)? {
    (Outcome::Valid { needs_rehash: true }, Some(new_phc)) => {
        persist(new_phc);   // policy drifted; rotate the stored value
    }
    (Outcome::Valid { needs_rehash: false }, _) => { /* OK */ }
    (Outcome::Invalid, _) => { deny() }
}
# Ok::<(), hsh::Error>(())
```

### CLI

```bash
# Hash a password (reads from stdin)
echo -n "correct horse" | hsh hash --algorithm argon2id
# → $argon2id$v=19$m=19456,t=2,p=1$…

# Verify
echo -n "correct horse" | hsh verify -H '$argon2id$…'
# → valid

# Calibrate Argon2id params for a 500ms target on this host
hsh calibrate --algorithm argon2id --target-ms 500

# Emit completions
hsh completions zsh > ~/.zsh/completions/_hsh
```

---

## What landed in v0.0.9

| Phase | Topic                                                         | Status |
| ----- | ------------------------------------------------------------- | ------ |
| **0** | Workspace + 4 critical security hot-fixes (S1/S3/S7/S10)     | ✅ |
| **1** | RustCrypto migration, PHC, `verify_and_upgrade`              | ✅ |
| **2** | Fuzz / Miri / proptest / SLSA L3 release / OpenSSF Scorecard | ✅ |
| **3** | Pepper + KMS integration (AWS / GCP / Azure / Vault stubs)   | ✅ |
| **4** | PBKDF2 + `Backend::Fips140Required` fail-closed contract     | ✅ |
| **5** | `hsh-cli` + 5 packaging templates + 5 migration guides       | ✅ |
| **6** | `hsh-digest` general-purpose hashing crate                   | ✅ |
| **7** | API-stability contract + release runbook + v1.0 prep         | ✅ |

Full breakdown in [`CHANGELOG.md`](CHANGELOG.md).
Live status of the milestone:
<https://github.com/sebastienrousseau/hsh/milestone/1>.

---

## Documentation

| Doc                                                               | What's in it                                                                 |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| [`doc/API-STABILITY.md`](doc/API-STABILITY.md)                    | Per-crate per-symbol stability tier; v1.0 commitment                          |
| [`doc/RELEASE.md`](doc/RELEASE.md)                                | Maintainer release runbook (tag flow, yank policy, smoke tests)              |
| [`doc/SUPPORT.md`](doc/SUPPORT.md)                                | Where to ask, response windows, what to include in bug reports               |
| [`doc/FIPS.md`](doc/FIPS.md)                                      | FIPS 140-3 deployment guide + Argon2 → PBKDF2 migration playbook              |
| [`doc/KMS-INTEGRATION.md`](doc/KMS-INTEGRATION.md)                | Pepper / KMS deployment for AWS / GCP / Azure / Vault                         |
| [`SECURITY.md`](SECURITY.md)                                      | Vulnerability reporting policy, threat model, supply-chain posture            |
| [`doc/MIGRATION-from-*.md`](doc/)                                  | Migration guides: argonautica, rust-argon2, bcrypt, djangohashers, password-hash |
| [`doc/adr/`](doc/adr/)                                            | Architecture Decision Records 0001–0007                                       |

---

## Roadmap to v1.0.0

The v0.0.9 release is the **stabilisation snapshot**. v1.0.0 ships
after an ~8-week soak in which:

1. The published v0.0.9 crates absorb post-merge bug reports.
2. CI nightlies produce the first set of SLSA attestations and
   OpenSSF Scorecard scores.
3. Any blockers land as v0.0.10 / v0.0.11 patches.

The full v1.0 contract is in
[`doc/adr/0007-v1-stability-contract.md`](doc/adr/0007-v1-stability-contract.md).

---

## Development

```bash
make ci              # what CI runs on every PR
make test            # full workspace test suite
make miri-focused    # per-PR Miri (60 min budget)
make fuzz-smoke      # 30 s per fuzz target (nightly cargo-fuzz)
make sbom            # cargo-about SBOM
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, signed commits,
and PR guidelines.
See [`SECURITY.md`](SECURITY.md) for the vulnerability reporting policy.

---

## License

Dual-licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/licenses/MIT), at your option.

<p align="right"><a href="#hash-hsh">Back to Top</a></p>
