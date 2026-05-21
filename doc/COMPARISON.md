# Ecosystem comparison

How `hsh` compares to the major Rust password-hashing crates. The
goal of this document is to help you decide whether `hsh` is the
right pick for your use case — and if not, where to look instead.

## Summary

| Crate                          | Maintained? | Multi-algo | PHC | Auto-rehash | Pepper | FIPS contract | CLI | Workspace |
| ------------------------------ | ----------- | ---------- | --- | ----------- | ------ | ------------- | --- | --------- |
| **`hsh`** (this)               | ✅           | ✅          | ✅   | ✅           | ✅      | ✅              | ✅   | ✅         |
| [`argonautica`][argonautica]   | ❌ (2019)    | ❌ (Argon2) | ❌   | ❌           | ✅ (key) | ❌              | ❌   | ❌         |
| [`rust-argon2`][rust-argon2]   | ✅           | ❌ (Argon2) | ✅   | ❌           | ❌      | ❌              | ❌   | ❌         |
| [`bcrypt`][bcrypt]             | ✅           | ❌ (bcrypt) | ❌   | ❌           | ❌      | ❌              | ❌   | ❌         |
| [`password-auth`][password-auth] | ✅         | ✅          | ✅   | partial     | ❌      | ❌              | ❌   | ❌         |
| [`scrypt`][scrypt]             | ✅           | ❌ (scrypt) | ✅   | ❌           | ❌      | ❌              | ❌   | ❌         |
| [`djangohashers`][djangohashers] | ✅         | ✅          | ❌ (Django format) | ❌ | ❌      | ❌              | ❌   | ❌         |

Legend: ✅ supported · ❌ not supported · partial = present but limited.

[argonautica]: https://crates.io/crates/argonautica
[rust-argon2]: https://crates.io/crates/rust-argon2
[bcrypt]: https://crates.io/crates/bcrypt
[password-auth]: https://crates.io/crates/password-auth
[scrypt]: https://crates.io/crates/scrypt
[djangohashers]: https://crates.io/crates/djangohashers

## Detailed matrix

### Algorithm coverage

| Crate            | Argon2id | Argon2i | Argon2d | bcrypt | scrypt | PBKDF2 |
| ---------------- | -------- | ------- | ------- | ------ | ------ | ------ |
| **`hsh`**        | ✅        | ✅       | ✅       | ✅      | ✅      | ✅      |
| `argonautica`    | ✅        | ✅       | ✅       | ❌      | ❌      | ❌      |
| `rust-argon2`    | ✅        | ✅       | ✅       | ❌      | ❌      | ❌      |
| `bcrypt`         | ❌        | ❌       | ❌       | ✅      | ❌      | ❌      |
| `password-auth`  | ✅        | ❌       | ❌       | ❌      | ✅      | ✅      |
| `scrypt`         | ❌        | ❌       | ❌       | ❌      | ✅      | ❌      |
| `djangohashers`  | ✅        | ❌       | ❌       | ✅      | ✅      | ✅      |

### Safety features

| Feature                                              | `hsh` | `argonautica` | `rust-argon2` | `bcrypt` | `password-auth` |
| ---------------------------------------------------- | ----- | ------------- | ------------- | -------- | --------------- |
| Constant-time verify (`subtle`)                      | ✅     | partial       | partial       | ✅        | ✅               |
| Zeroize on drop                                      | ✅     | ❌             | ❌             | partial  | ❌               |
| `#![forbid(unsafe_code)]`                            | ✅     | ❌ (FFI)       | ✅             | ✅        | ✅               |
| **Bcrypt 72-byte safety rail (CVE-2025-22228)**      | ✅     | n/a           | n/a           | ❌        | n/a             |
| Salt source                                          | OsRng | mixed         | OsRng         | OsRng    | OsRng           |
| OWASP-2025 default parameters                        | ✅     | ❌             | manual        | manual   | partial         |
| Structured `std::error::Error`                       | ✅     | ✅             | ✅             | ✅        | ✅               |
| `#[non_exhaustive]` on public enums                  | ✅     | ❌             | partial       | ❌        | partial         |

### Ergonomics

| Feature                                              | `hsh` | `argonautica` | `rust-argon2` | `bcrypt` | `password-auth` |
| ---------------------------------------------------- | ----- | ------------- | ------------- | -------- | --------------- |
| Single high-level API for all algorithms             | ✅     | ❌             | ❌             | ❌        | ✅               |
| Builder pattern for configuration                    | ✅     | ✅             | ❌             | ❌        | ❌               |
| **Auto-rehash on policy drift**                      | ✅     | ❌             | ❌             | ❌        | partial         |
| **Algorithm migration on verify**                    | ✅     | ❌             | ❌             | ❌        | partial         |
| PHC string output                                    | ✅     | ❌             | ✅             | ❌ (MCF)  | ✅               |
| MCF (`$2b$…`) parsing                                | ✅     | n/a           | n/a           | ✅        | partial         |

### Operational

| Feature                                              | `hsh` | `argonautica` | `rust-argon2` | `bcrypt` | `password-auth` |
| ---------------------------------------------------- | ----- | ------------- | ------------- | -------- | --------------- |
| Server-side **pepper** (in-process, HMAC-SHA-256 + key versioning) | ✅     | partial (key) | ❌             | ❌        | ❌               |
| Versioned pepper rotation                            | ✅     | ❌             | ❌             | ❌        | ❌               |
| KMS-backed pepper providers (AWS / GCP / Azure / Vault) | 🟡 stub interfaces in v0.0.9 — real fetch in 0.1.x | ❌ | ❌ | ❌ | ❌ |
| **FIPS 140-3 contract** (`Backend::Fips140Required`, mint-time fail-closed) | ✅     | ❌             | ❌             | ❌        | ❌               |
| **FIPS 140-3 runtime** (PBKDF2 routed through validated crypto module) | 🟡 contract-only in v0.0.9 — `hsh-backend-awslc` lands in 0.1.x | ❌ | ❌ | ❌ | ❌ |
| CLI binary                                           | ✅     | ❌             | ❌             | ❌        | ❌               |
| Multi-platform packaging templates                   | ✅     | ❌             | ❌             | ❌        | ❌               |
| Migration guides from competing crates               | ✅ (5) | ❌             | ❌             | ❌        | ❌               |

### Supply chain & CI

| Feature                                              | `hsh` | `argonautica` | `rust-argon2` | `bcrypt` | `password-auth` |
| ---------------------------------------------------- | ----- | ------------- | ------------- | -------- | --------------- |
| `cargo-deny` on every PR                             | ✅     | ❌             | partial       | ❌        | partial         |
| `cargo-audit` on every PR                            | ✅     | ❌             | partial       | ❌        | partial         |
| SBOM (`cargo-about`)                                 | ✅     | ❌             | ❌             | ❌        | ❌               |
| **SLSA L3 build provenance**                         | ✅     | ❌             | ❌             | ❌        | ❌               |
| **Sigstore keyless signing**                         | ✅     | ❌             | ❌             | ❌        | ❌               |
| OpenSSF Scorecard published                          | ✅     | ❌             | ❌             | ❌        | ❌               |
| Fuzz harnesses (libfuzzer)                           | ✅ (5) | ❌             | ❌             | ❌        | ❌               |
| Property tests (proptest)                            | ✅ (7) | ❌             | ❌             | ❌        | ❌               |
| Miri (focused + full)                                | ✅     | ❌             | ❌             | ❌        | ❌               |
| KAT vectors (NIST CAVP / FIPS 202)                   | ✅ (13)| ❌             | ❌             | ❌        | ❌               |

## When to pick which

### Pick `hsh` if

- You want **multi-algorithm support** with one API.
- You need **auto-rehash on policy drift** (algorithm or parameter migration).
- You want **in-process versioned pepper** today; KMS-backed providers (AWS / GCP / Azure / Vault) are stub interfaces in v0.0.9 and land for real in 0.1.x.
- You're going to deploy in a regulated environment where the **FIPS 140-3 *contract*** matters (mint-time fail-closed behaviour). The **validated runtime** (PBKDF2 through `aws-lc-rs`) lands as `hsh-backend-awslc` in 0.1.x.
- You want a **CLI** for ops / scripting.
- You value enterprise-grade **supply-chain hygiene** (SLSA L3, sigstore, SBOM, Scorecard).

### Pick `argonautica` if

- Don't. It's been unmaintained since March 2019. No security
  updates. FFI binding to a C library that has its own
  vulnerabilities timeline.

### Pick `rust-argon2` if

- You only need Argon2, you don't need multi-algorithm migration,
  and you want the smallest possible dependency surface.
- Future-proofing against algorithm rotation isn't important.

### Pick `bcrypt` directly if

- You're integrating with an existing bcrypt-only codebase and don't
  need any of `hsh`'s safety / migration features.
- **Be aware** of the 72-byte truncation behaviour (CVE-2025-22228
  class). If your application might receive long inputs, use `hsh`'s
  `BcryptParams::with_prehash` adapter or hand-roll the same.

### Pick `password-auth` if

- You're already on the RustCrypto stack and want a thin facade.
- You don't need pepper / FIPS / CLI / packaging.

### Pick `djangohashers` if

- You're consuming hashes produced by a Python/Django sibling
  service and need format compatibility.
- For new code that owns its own hashes, prefer `hsh` and use
  [`doc/MIGRATION-from-djangohashers.md`](MIGRATION-from-djangohashers.md)
  to wrap.

## Migration guides

For each crate above, `hsh` ships a step-by-step migration:

- [Migrating from `argonautica`](MIGRATION-from-argonautica.md)
- [Migrating from `rust-argon2`](MIGRATION-from-rust-argon2.md)
- [Migrating from `bcrypt`](MIGRATION-from-bcrypt.md)
- [Migrating from `djangohashers`](MIGRATION-from-djangohashers.md)
- [Migrating from `password-hash` (RustCrypto stack)](MIGRATION-from-password-hash.md)

Each guide includes the equivalent `hsh` API calls, a Cargo.toml
diff, and a breaking-change checklist.

## Methodology

This matrix was compiled by reading each crate's latest published
release on crates.io, its README, and its `docs.rs` API surface.
Versions surveyed as of 2026-05-19:

- `argonautica` 0.2.0 (last release 2019-03-05)
- `rust-argon2` 3.0.0 (2025-07-17)
- `bcrypt` 0.19.1 (2026-05-06)
- `password-auth` 1.1.0-rc.1 (2026-01-12)
- `scrypt` 0.12.0 (2026-04-22)
- `djangohashers` 1.8.4 (2025-12-28)

Re-run [`scripts/coverage-check.sh`](../scripts/coverage-check.sh)
periodically to refresh the matrix as upstream crates evolve.

## See also

- [`README.md#ecosystem-comparison`](../README.md#ecosystem-comparison) for the abbreviated table.
- [`doc/MIGRATION-from-*.md`](.) for per-crate migration walk-throughs.
- [`doc/API-STABILITY.md`](API-STABILITY.md) for the v1.0 commitment that backs `hsh`'s feature set.
