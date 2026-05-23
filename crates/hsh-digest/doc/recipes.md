<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `hsh-digest` recipes

Copy-pasteable patterns for non-password cryptographic digests.

> [!WARNING]
> **None of these patterns are appropriate for password storage.**
> Use the `hsh` library's `api::hash` / `api::verify_and_upgrade`
> instead. The digests below are *fast by design* — exactly what you
> want for content-addressing and exactly what you don't want for
> password storage.

## Table of contents

- [One-shot hashing](#one-shot-hashing)
- [Streaming hashing (large files, network)](#streaming-hashing-large-files-network)
- [Content-addressed storage (Git / IPFS style)](#content-addressed-storage-git--ipfs-style)
- [Merkle tree leaves](#merkle-tree-leaves)
- [Picking an algorithm](#picking-an-algorithm)
- [HMAC building block](#hmac-building-block)
- [Commitment schemes](#commitment-schemes)

## One-shot hashing

```rust
use hsh_digest::{hash, Algorithm};

# fn main() -> Result<(), hsh_digest::DigestError> {
let digest = hash(Algorithm::Sha256, b"hello, world")?;
assert_eq!(digest.len(), 32);
# Ok(())
# }
```

Returns `Vec<u8>` of the algorithm's fixed output width (32 / 48 /
64 bytes depending on the variant).

## Streaming hashing (large files, network)

For input that doesn't fit in memory:

```rust
use std::io::Read;
use hsh_digest::{Algorithm, Hasher};

# fn demo<R: Read>(mut input: R) -> Result<Vec<u8>, hsh_digest::DigestError> {
let mut hasher = Hasher::new(Algorithm::Sha256)?;
let mut buf = [0u8; 8192];

loop {
    let n = input.read(&mut buf).map_err(|e| {
        // Map I/O errors to a Digest error or your own error type.
        // `hsh-digest` itself doesn't do I/O.
        let _ = e;
        hsh_digest::DigestError::UnsupportedAlgorithm(Algorithm::Sha256)
    })?;
    if n == 0 { break; }
    hasher.update(&buf[..n]);
}

Ok(hasher.finalize())
# }
# fn main() {}
```

Property: the result is bit-identical to `hash(alg, &all_bytes)`
regardless of how `update` chunks the input. The `tests/properties.rs`
file exercises this with `proptest` against 256 random
chunking patterns per run.

## Content-addressed storage (Git / IPFS style)

Use the digest of a blob as its storage key:

```rust
use hsh_digest::{hash, Algorithm};

# fn main() -> Result<(), hsh_digest::DigestError> {
let blob = b"file contents";
let key = hash(Algorithm::Blake3, blob)?;

// Render as hex for the file-path component.
let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
let path = format!("objects/{}/{}", &key_hex[..2], &key_hex[2..]);
// path = "objects/ab/cdef…" (Git-style two-char prefix shard)
# Ok(())
# }
```

BLAKE3 is the right default for new content-addressing systems:
fastest of the three, parallelisable across CPU cores at the
SIMD layer, no known weaknesses.

SHA-256 if you need ecosystem interop (Git, OCI containers,
Sigstore — all SHA-256 by default).

## Merkle tree leaves

Hashing leaves before building inner nodes:

```rust
use hsh_digest::{hash, Algorithm};

# fn main() -> Result<(), hsh_digest::DigestError> {
fn leaf_hash(data: &[u8]) -> Result<Vec<u8>, hsh_digest::DigestError> {
    // Domain-separate leaf hashes from inner hashes — prefix
    // with 0x00 for leaves, 0x01 for inner. Prevents second-
    // preimage attacks across leaf-vs-inner boundary.
    let mut input = Vec::with_capacity(1 + data.len());
    input.push(0x00);
    input.extend_from_slice(data);
    hash(Algorithm::Sha256, &input)
}

let leaves = ["a".as_bytes(), "b".as_bytes(), "c".as_bytes()];
let hashed: Vec<_> = leaves.iter()
    .map(|l| leaf_hash(l))
    .collect::<Result<_, _>>()?;
let _ = hashed;
# Ok(())
# }
```

The domain-separation byte is critical — every published Merkle
tree CVE in the last decade has involved skipping it.

## Picking an algorithm

| Use case | Recommended | Why |
|---|---|---|
| Greenfield content-addressing | **BLAKE3** | Fastest, SIMD-parallel, no ecosystem lock-in |
| Git-compatible object storage | **SHA-256** | Required by Git's SHA-256 transition |
| OCI container digests | **SHA-256** | Required by the OCI Image Spec |
| Sigstore Rekor entries | **SHA-256** | Required by the Sigstore protocol |
| NIST-suite cryptographic protocol | **SHA-2 or SHA-3** | Other algorithms aren't NIST-approved |
| HMAC base hash | **SHA-256** | The most-deployed HMAC base; widest interop |
| Post-quantum sponge construction | **SHA-3** (Keccak) | Sponge construction; Grover's algorithm shrinks security margin less than Merkle-Damgård |
| Variable-length output | KangarooTwelve (when impl lands) | Native XOF mode |

If you're not sure: **BLAKE3** for new systems, **SHA-256** if you
need interop with anything that already exists.

## HMAC building block

`hsh-digest` only exposes the digest primitive — for HMAC you
compose with the `hmac` crate from RustCrypto:

```rust
# #[cfg(feature = "sha2")]
# fn demo() {
use hmac::{Hmac, Mac};
use sha2::Sha256;

let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"key-bytes")
    .expect("HMAC accepts any key length");
mac.update(b"message");
let tag = mac.finalize().into_bytes();
let _ = tag;
# }
# fn main() {}
```

For peppered password hashing specifically, use
[`hsh-kms`](../../hsh-kms/) — it wraps `hmac` with the `KeyVersion`
rotation contract.

## Commitment schemes

A *commitment* binds a sender to a value without revealing it. The
digest of `(value, salt)` is the commitment; the sender publishes
the salt at reveal time.

```rust
use hsh_digest::{hash, Algorithm};

# fn main() -> Result<(), hsh_digest::DigestError> {
fn commit(value: &[u8], salt: &[u8]) -> Result<Vec<u8>, hsh_digest::DigestError> {
    let mut input = Vec::with_capacity(value.len() + salt.len() + 1);
    input.extend_from_slice(salt);
    input.push(0xff);  // domain separator
    input.extend_from_slice(value);
    hash(Algorithm::Sha256, &input)
}

let salt: [u8; 32] = [0; 32];  // in real code: getrandom::OsRng
let value = b"chosen card";
let c = commit(value, &salt)?;
assert_eq!(c.len(), 32);
# Ok(())
# }
```

Constant-time comparison at reveal time matters — use
`subtle::ConstantTimeEq` for the equality check, not `==`.

## What NOT to do

```rust
// ❌ DON'T: use SHA-256 (or any digest in this crate) to store
//          passwords. Even with a salt, SHA-256 is GPU-cracked
//          billions of times per second. Use hsh::api::hash.
//
//   let salt = generate_salt();
//   let stored = hash(Algorithm::Sha256, &[salt, password].concat())?;
//                ^^^^ NOT a password hash, no matter how you wrap it.

// ❌ DON'T: compare digests with `==` on the verify path. Use
//          subtle::ConstantTimeEq. Plain `==` short-circuits and
//          leaks timing about how much of the digest matched.
//
//   if digest_a == digest_b { ... }
//                ^^ timing side channel
```
