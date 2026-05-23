<p align="center">
  <img src="https://cloudcdn.pro/hsh/v1/logos/hsh.svg" alt="hsh-digest logo" width="128" />
</p>

<h1 align="center">hsh-digest</h1>

<p align="center">
  <strong>General-purpose cryptographic hashing primitives (SHA-2 / SHA-3 / BLAKE3) — <em>NOT</em> for password storage.</strong>
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/hsh/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/hsh/ci.yml?style=for-the-badge&logo=github" alt="Build" /></a>
  <a href="https://crates.io/crates/hsh-digest"><img src="https://img.shields.io/crates/v/hsh-digest.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Crates.io" /></a>
  <a href="https://docs.rs/hsh-digest"><img src="https://img.shields.io/badge/docs.rs-hsh--digest-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs.rs" /></a>
</p>

---

> ⚠️ **This crate is NOT for password storage.** Hashing passwords requires a memory-hard / iteration-hard KDF (Argon2id, scrypt, bcrypt, PBKDF2). For that, use [`hsh::api::hash`](../hsh/) — not the primitives here.

---

## Contents

[Install](#install) · [When to use](#when-to-use) · [Quick Start](#quick-start) · [Algorithm matrix](#algorithm-matrix) · [Streaming vs one-shot](#streaming-vs-one-shot) · [Constant-time compare](#constant-time-compare) · [Test vectors](#test-vectors) · [Examples](#examples) · [License](#license)

---

## Install

```toml
[dependencies]
hsh-digest = "0.0.9"
```

MSRV **1.75** stable.

### Feature flags

| Feature   | Status        | Pulls in           | Notes                                                  |
| --------- | ------------- | ------------------ | ------------------------------------------------------ |
| `default` | —             | `sha2 sha3 blake3` | The sensible defaults                                  |
| `sha2`    | ✅            | `sha2` 0.10        | SHA-256, SHA-384, SHA-512 (FIPS 180-4)                 |
| `sha3`    | ✅            | `sha3` 0.10        | SHA3-256, SHA3-384, SHA3-512 (FIPS 202)                |
| `blake3`  | ✅            | `blake3` 1.5       | BLAKE3-256                                             |
| `k12`     | 🚧 reserved   | (future) `k12`     | KangarooTwelve / TurboSHAKE128/256 (RFC 9861, Oct 2025) |
| `ascon`   | 🚧 reserved   | (future) `ascon-hash` | Ascon-Hash256 / Ascon-XOF128 (NIST SP 800-232 Aug 2025) |

Disable a default feature to shrink the dependency surface:

```toml
hsh-digest = { version = "0.0.9", default-features = false, features = ["sha2"] }
```

---

## When to use

✅ **Yes, use `hsh-digest` for:**

- Content addressing (Git-style, IPFS-style content hashes).
- Building blocks for higher-level protocols (Merkle trees, commitment schemes).
- Pre-processing input for an HMAC or signature scheme.
- PHC string parsing for non-`hsh` hashes.

❌ **No, don't use `hsh-digest` for:**

- **Password storage.** Use [`hsh::api::hash`](../hsh/) — it picks a memory-hard KDF and applies constant-time verification.
- **HMAC / KDF / signatures / KEMs.** Use the RustCrypto siblings (`hmac`, `hkdf`, `digest`, `signatures/*`).

ADR-0005 documents the scope boundary: [`doc/adr/0005-general-hashing-scope.md`](../../doc/adr/0005-general-hashing-scope.md).

---

## Quick Start

### One-shot

```rust
use hsh_digest::{Algorithm, hash};

let digest = hash(Algorithm::Sha256, b"hello, world").unwrap();
assert_eq!(digest.len(), 32);
```

### Streaming

```rust
use hsh_digest::{Algorithm, Hasher};

let mut hasher = Hasher::new(Algorithm::Blake3).unwrap();
hasher.update(b"hello, ");
hasher.update(b"world");
let digest = hasher.finalize();
assert_eq!(digest.len(), 32);
```

---

## Algorithm matrix

| Variant                  | Output | Spec                                  | Cargo feature |
| ------------------------ | ------ | ------------------------------------- | ------------- |
| `Algorithm::Sha256`      | 32 B   | FIPS 180-4                            | `sha2`        |
| `Algorithm::Sha384`      | 48 B   | FIPS 180-4                            | `sha2`        |
| `Algorithm::Sha512`      | 64 B   | FIPS 180-4                            | `sha2`        |
| `Algorithm::Sha3_256`    | 32 B   | FIPS 202                              | `sha3`        |
| `Algorithm::Sha3_384`    | 48 B   | FIPS 202                              | `sha3`        |
| `Algorithm::Sha3_512`    | 64 B   | FIPS 202                              | `sha3`        |
| `Algorithm::Blake3`      | 32 B   | BLAKE3 spec (Aumasson et al., 2020)   | `blake3`      |

All variants implement constant-output-length digests. For variable-length output (SHAKE / TurboSHAKE), see the `k12` follow-up feature.

`Algorithm::id()` returns the standard identifier (`"sha256"`, `"sha3-256"`, `"blake3"`, etc.) for use in PHC strings or protocol headers.

---

## Streaming vs one-shot

Both are equivalent — choose based on whether the input is already in memory:

```rust
use hsh_digest::{Algorithm, hash, Hasher};

let oneshot = hash(Algorithm::Sha256, b"hello").unwrap();

let mut streaming = Hasher::new(Algorithm::Sha256).unwrap();
streaming.update(b"hello");
let streamed = streaming.finalize();

assert_eq!(oneshot, streamed);
```

The streaming API exposes `Update` semantics for incremental hashing (file-content addressing, network-stream MACing, etc.).

---

## Constant-time compare

```rust
use hsh_digest::constant_time_eq;

let a = b"sha256-tag-32-bytes...";
let b = b"sha256-tag-32-bytes...";
assert!(constant_time_eq(a, b));
```

Wraps [`subtle::ConstantTimeEq`] so comparing two digest tags doesn't leak the prefix-match length via timing. Use this whenever you compare a computed digest against an expected one (MAC verification, content-hash equality checks).

---

## Test vectors

The crate ships KAT tests (`crates/hsh-digest/tests/kat.rs`) against:

- **SHA-2** — NIST CAVP byte-test vectors (`SHAVS`).
- **SHA-3** — NIST CAVP byte-test vectors (`SHA3VS`).
- **BLAKE3** — project test vectors at `blake3-team/BLAKE3/test_vectors`.

Run with:

```bash
cargo test -p hsh-digest
```

---

## Examples

See [`crates/hsh-digest/examples/`](examples/) for runnable demos:

- `oneshot.rs` — minimal hash + hex print.
- `streaming.rs` — incremental hashing of a large input.
- `content_addressing.rs` — Git-style content-hash workflow.

Run with `cargo run -p hsh-digest --example oneshot`.

---

## Documentation

| Doc                                                                                | What's in it                                                              |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| [`adr/0005-general-hashing-scope.md`](../../doc/adr/0005-general-hashing-scope.md) | Scope decision: re-export only, no KDF / MAC / signature drift             |

---

## License

Dual-licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/licenses/MIT), at your option.

<p align="right"><a href="#hsh-digest">Back to top</a></p>
