<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# hsh-digest::DigestError reference

`hsh-digest` is intentionally minimal — the underlying RustCrypto
primitives are themselves nearly infallible, so the error surface
is small.

## Variant reference

| Variant | Display prefix | When emitted | Recovery |
|---|---|---|---|
| `UnsupportedAlgorithm(Algorithm)` | `unsupported algorithm: …` | An `Algorithm` variant was reached whose feature flag isn't enabled in this build | Re-build with the missing feature, e.g. `cargo build --features sha3` |

The enum is `#[non_exhaustive]`. Future runtime-selectable
algorithms (like the stubbed `k12` / `ascon`) may add new variants.

## Why `Hasher::new` is infallible today

Returns `Result<Self, DigestError>` for forward compatibility — the
`Algorithm` variants currently in the enum are all themselves gated
by the *same* feature flags the upstream crate ships with, so
constructing a `Hasher` for a variant that's currently in scope is
infallible.

The `Result` shape is preserved so future runtime-selectable
algorithms (e.g. KangarooTwelve at variable output sizes) can fail
when their parameters are out of range without a SemVer-major bump.

## What `DigestError` does *not* represent

- **Wrong digest.** `hsh-digest` does not verify digests — that's a
  caller responsibility. Use `subtle::ConstantTimeEq::ct_eq` for
  constant-time comparison.
- **Output-length errors.** Each algorithm has a fixed output
  width (32 / 48 / 64 bytes). `finalize` returns a `Vec<u8>` of the
  correct size; callers don't supply an output buffer.

## When to file an issue

| Symptom | File an issue if… |
|---|---|
| `cargo build --features sha2,blake3` fails | The build error mentions an unused import or unreachable code — that's a feature-gating bug |
| `Hasher::update` returns wrong bytes | This is critical — file with the input, algorithm, and your platform |
| KAT vectors fail | This is critical — file immediately; do not ship binaries built from this state |
