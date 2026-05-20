<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# hsh-digest internals

Contributor-facing map of the `hsh-digest` crate — general-purpose
cryptographic digests. **This crate is not for password storage.**
For password hashing, use [`hsh::api`](../../hsh/).

## Module map

```text
crates/hsh-digest/src/
├── lib.rs              # Algorithm + Hasher + hash() one-shot fn
│                       # All feature-gated; at least one of
│                       # sha2/sha3/blake3 must be enabled (enforced
│                       # by a compile_error! macro).
└── error.rs            # DigestError enum
```

## Feature-gating contract

The crate has three "primary" features (`sha2`, `sha3`, `blake3`)
and a top-level `compile_error!` that fires at compile time if all
three are off:

```rust
#[cfg(not(any(feature = "sha2", feature = "sha3", feature = "blake3")))]
compile_error!(
    "hsh-digest requires at least one algorithm feature: \
     `sha2`, `sha3`, or `blake3`."
);
```

Why: with all three off, the `Algorithm` enum has zero variants
(every variant is `#[cfg(feature = "...")]`), which makes
`HasherInner` uninhabited and trips
`non_exhaustive_patterns` + `unreachable_code` errors throughout
the file. Failing fast at the manifest level is friendlier than
30+ confusing rustc errors.

The CI `cargo-hack` feature-powerset job (`feature-checks` in
`ci.yml`) calls `cargo hack check -p hsh-digest --feature-powerset
--at-least-one-of sha2,sha3,blake3` to enforce the contract on
every PR.

## `Algorithm` enum vs `HasherInner`

`Algorithm` is the *public* identifier — callers pass
`Algorithm::Sha256` etc. It derives `Copy` so it's cheap to pass
around. `#[non_exhaustive]` so new variants are non-breaking.

`HasherInner` is the *private* state — one variant per supported
algorithm, holding the upstream RustCrypto crate's incremental
hasher state. Hidden behind `Hasher`'s opaque struct so callers
never have to name it.

## Streaming API

```rust
let mut h = Hasher::new(Algorithm::Sha256)?;
h.update(b"chunk 1");
h.update(b"chunk 2");
let digest = h.finalize();  // Vec<u8>; size depends on Algorithm
```

The `digest::Digest` trait is imported behind `#[cfg(any(feature =
"sha2", feature = "sha3"))]` because BLAKE3 doesn't go through the
`Digest` trait — it has its own inherent API on `blake3::Hasher`.
Without the cfg-gate, the `use` becomes a dead import on
`--no-default-features --features blake3` builds.

## One-shot vs streaming equivalence

The 11 `proptest` invariants in `tests/properties.rs` lock down:

- `hash(alg, input) == Hasher::new(alg).update(input).finalize()`
  for every algorithm.
- N updates of `Σ chunk_i == input` produce the same digest as a
  single `update(input)` (chunking equivalence — catches SIMD
  partial-block bugs).
- Output length is fixed per algorithm regardless of input.
- Same input → same output (determinism; catches state leaks).
- Different algorithms over the same input produce different
  digests (cross-algorithm distinctness).

These run on every PR with the default 256 cases per invariant.

## KAT vectors

`tests/kat.rs` carries 13 Known-Answer Test vectors:

- SHA-256 / 384 / 512 — NIST CAVP samples
- SHA3-256 / 384 / 512 — NIST CAVP samples
- BLAKE3 — RFC test vectors

KAT failures are non-negotiable — if any vector breaks, do NOT ship.

## Adding a new algorithm

1. Add the upstream crate as an `optional` workspace dep.
2. Add a `feature = "<name>"` line in `Cargo.toml` (probably
   default-on).
3. Add a `[<Name>]` variant to `Algorithm` with `#[cfg(feature =
   "<name>")]`.
4. Add a corresponding `<Name>(...)` variant to `HasherInner` with
   the same cfg-gate.
5. Wire match arms in `Hasher::new`, `algorithm`, `update`, and
   `finalize` — also cfg-gated.
6. Update the `compile_error!` macro at the top of `lib.rs` to
   include the new feature in the `any(...)` list if it's a
   "primary" algorithm (i.e. one of the ones the workspace
   needs by default).
7. Add KAT vectors to `tests/kat.rs`.
8. Add property invariants to `tests/properties.rs`.

## Stub algorithms

`k12` (KangarooTwelve / TurboSHAKE, RFC 9861) and `ascon`
(Ascon-Hash256 / Ascon-XOF128, NIST SP 800-232) are stubbed with
just the feature flag declared — the upstream Rust impls aren't
mature enough to wire in. Tracked under
[milestone #2 (v0.0.10)](https://github.com/sebastienrousseau/hsh/milestone/2).
