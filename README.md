<p align="center">
  <img src="https://kura.pro/hsh/images/logos/hsh.svg" alt="Hash (HSH) logo" width="128" />
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

---

## Overview

HSH is a Rust library for **storing and verifying passwords** with multiple
memory-hard KDFs behind a single, ergonomic API. v0.0.9 is the first release
on the enterprise-readiness roadmap (see [the milestone][ms]).

- **Multi-algorithm** — Argon2i, bcrypt, scrypt today; Argon2id, PHC strings, KMS pepper, and an optional FIPS backend on the roadmap.
- **Constant-time verification** — `subtle::ConstantTimeEq` everywhere a hash is compared.
- **Zeroized on drop** — password / hash / salt buffers are wiped from memory.
- **Structured errors** — every fallible op returns a `hsh::Error` that implements `std::error::Error`.
- **`#![forbid(unsafe_code)]`** — workspace-wide.

[ms]: https://github.com/sebastienrousseau/hsh/milestone/1

### What HSH is *not*

- **Not post-quantum cryptography.** Memory-hard KDFs make brute-force expensive on classical and quantum hardware alike, but they aren't PQ primitives (ML-KEM, ML-DSA, SLH-DSA). If you need PQ, use [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs).
- **Not yet PHC-compliant** in the serialized hash form — see issue [#159][i159].
- **Not yet FIPS-validated** — see issue [#143][i143].

[i159]: https://github.com/sebastienrousseau/hsh/issues/159
[i143]: https://github.com/sebastienrousseau/hsh/issues/143

---

## Algorithms

| Algorithm | Status   | Notes                                                            |
| --------- | -------- | ---------------------------------------------------------------- |
| Argon2i   | Default  | Argon2**id** replaces it in v0.1.0 (issue [#156][i156])           |
| Bcrypt    | OK       | 72-byte safety rail lands in v0.1.0 ([#158][i158])                |
| Scrypt    | OK       | Fixed params today; configurable per OWASP 2025 in v0.1.0         |

[i156]: https://github.com/sebastienrousseau/hsh/issues/156
[i158]: https://github.com/sebastienrousseau/hsh/issues/158

---

## Usage

```rust
use hsh::models::hash::Hash;

let password = "correct horse battery staple";
let salt     = "abcdefghijklmnop";
let h = Hash::new(password, salt, "argon2i").unwrap();

assert!(h.verify(password).unwrap());
assert!(!h.verify("wrong-guess").unwrap());
```

---

## Roadmap

The v0.0.9 milestone tracks the full enterprise-readiness programme across
seven phases — workspace + security hot-fixes (Phase 0), RustCrypto core
refactor + PHC strings (Phase 1), fuzzing + Miri + SLSA release automation
(Phase 2), KMS pepper integrations (Phase 3), `aws-lc-rs` FIPS backend
(Phase 4), CLI + packaging (Phase 5), optional general primitives (Phase 6),
and v1.0 stabilisation (Phase 7).

See the [milestone tracker][ms] for live status.

---

## Development

```bash
cargo build        # Build the workspace
cargo test         # Run all tests
cargo clippy       # Lint with Clippy
cargo fmt          # Format with rustfmt
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, signed commits, and PR guidelines.
See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy.

---

## License

Dual-licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/licenses/MIT), at your option.

<p align="right"><a href="#hash-hsh">Back to Top</a></p>
