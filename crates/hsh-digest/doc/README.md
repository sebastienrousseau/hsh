<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `hsh-digest` deep-dive documentation

Long-form documentation for general-purpose cryptographic digests
(SHA-2 / SHA-3 / BLAKE3). The two-line rule:

- **Reference / API docs** live inline in `src/` as `///` rustdoc
  and render at <https://docs.rs/hsh-digest>.
- **Recipes, picking-an-algorithm guidance, feature-flag rules**
  live here.

> [!IMPORTANT]
> **This crate is NOT for password storage.** For passwords, use
> [`hsh`](../../hsh/). The KDFs in `hsh` are deliberately slow;
> the digests here are deliberately fast. Using the wrong family is
> a security incident.

## What's in this folder

| File | Audience | Covers |
|---|---|---|
| [`recipes.md`](./recipes.md) | Library users | Common patterns: content-addressing, HMAC building blocks, commitment schemes, Merkle leaves, streaming over `Read` |
| [`internals.md`](./internals.md) | Contributors | Feature-gating contract, `Algorithm` vs `HasherInner` split, one-shot vs streaming equivalence, KAT vectors |
| [`errors.md`](./errors.md) | Library users | `DigestError` reference |

## What's NOT in this folder

| Looking for… | Read this instead |
|---|---|
| Password hashing | [`crates/hsh/doc/cookbook.md`](../../hsh/doc/cookbook.md) |
| Picking between SHA-2 / SHA-3 / BLAKE3 | [`recipes.md`](./recipes.md#picking-an-algorithm) |
| KAT vectors | `tests/kat.rs` source — they're locked down by tests, not prose |
| Feature flags (`sha2`, `sha3`, `blake3`, `k12`, `ascon`) | [crate `README.md`](../README.md#cargo-features) + [`internals.md`](./internals.md#feature-gating-contract) |
| KangarooTwelve / Ascon roadmap | [`PLAN.md`](../../../PLAN.md#v0010-candidates) |

## Contributor expectations

If you change a digest wrapper:

- **New algorithm?** See [`internals.md`'s "Adding a new algorithm" checklist](./internals.md#adding-a-new-algorithm).
- **New property invariant?** Add to `tests/properties.rs`; the
  baseline is 256 cases per invariant via `proptest`.
- **KAT vector addition?** Source MUST be a recognised standard
  (NIST CAVP, RFC test vectors, official upstream vectors). Cite
  the source in a comment above the test.
- **Default feature change?** Coordinate with the workspace —
  changing defaults is a semver-major decision.
