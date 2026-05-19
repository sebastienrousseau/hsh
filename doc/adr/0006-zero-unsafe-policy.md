# ADR-0006 — Zero-unsafe policy

- **Status:** Accepted
- **Date:** 2026-05-19
- **Deciders:** Sebastien Rousseau
- **Tracking issue:** [#154](https://github.com/sebastienrousseau/hsh/issues/154)

## Context

`hsh` is a password-hashing library. Memory-safety bugs in cryptographic code
are catastrophic: a use-after-free of a derived-key buffer, an off-by-one
when bounds-checking a salt, or a transmute that aliases secret bytes can
turn a "secure" KDF into a kerosene-soaked match.

The Rust memory-safety guarantees that make this crate worth writing in the
first place are voided as soon as a single `unsafe` block enters the picture.
The reference structural surveys of the projects we are modelling
(`noyalib`) both ship under `#![forbid(unsafe_code)]` and treat that as a
load-bearing claim, not a stylistic preference.

We considered three positions:

1. **`#![forbid(unsafe_code)]` workspace-wide.** Strongest signal. Any
   transitively-required unsafe must come from an audited dependency.
2. **`#![deny(unsafe_code)]` per module.** Allows ad-hoc exceptions with
   `#[allow(unsafe_code)]` annotations — too easy to slip past review.
3. **No restriction.** Trust ourselves. We don't.

## Decision

Every crate in this workspace declares `unsafe_code = "forbid"` in its
`[lints.rust]` section of `Cargo.toml` (and the equivalent
`#![forbid(unsafe_code)]` is preserved at the top of each `lib.rs` /
`main.rs` for redundancy / belt-and-braces against build-system bugs).

The forbid is **non-negotiable**. It cannot be overridden per-module via
`#[allow(unsafe_code)]`; `forbid` propagates and `rustc` will reject any
attempt to relax it.

When a future feature genuinely requires `unsafe` (e.g. SIMD intrinsics or
mmap-backed key storage), the implementation lives in an audited upstream
crate and `hsh` consumes the safe wrapper. Where no acceptable upstream
exists, the feature does not ship.

## Consequences

**Accepted trade-offs:**

- **SIMD ceiling set by upstream.** We cannot drop into `core::arch::*`
  intrinsics directly. Argon2 / SHA-2 SIMD performance is whatever the
  RustCrypto and `blake3` crates expose. As of 2026 their hand-vectorised
  paths are within ~10% of the C reference implementations, which we judge
  acceptable.

- **No raw pointer tricks for zeroization.** We rely on the `zeroize`
  crate's compiler-fence-based safe path rather than the historical
  `volatile_set_memory` intrinsic dance.

- **No FFI into C / hand-written assembly.** This rules out an `argonautica`-
  style libargon2 wrapper. Given that `argonautica` is abandoned (2019), and
  the pure-Rust `argon2` crate has caught up performance-wise, this is a
  trivial cost.

- **`aws-lc-rs` integration is borderline.** `aws-lc-rs` itself is a Rust
  wrapper around the AWS-LC C library (FFI through `bindgen`). The wrapper
  crate uses `unsafe` extensively to call into C, but we treat it as a
  vetted third-party boundary that does not require *us* to write `unsafe`.
  The forbid in our own code remains intact; we only consume `aws-lc-rs`'s
  safe API surface.

**Benefits:**

- A reviewer who sees `#![forbid(unsafe_code)]` knows that every memory-
  safety guarantee Rust provides applies, end-to-end, to our code path.
- Audits can focus on cryptographic correctness, not memory hazards.
- Misuse-resistance: a contributor who reaches for `unsafe` is forced to
  justify why, in code review, before any unsafe block can compile.

## Compliance

- Every crate's `Cargo.toml` carries `unsafe_code = "forbid"` in
  `[lints.rust]`.
- `lib.rs` / `main.rs` redundantly declare `#![forbid(unsafe_code)]`.
- CI gates on `cargo clippy --workspace --all-targets --all-features
  -- -D warnings`, which will fail on any attempt to introduce unsafe.

## References

- [The Rust Reference — Unsafety](https://doc.rust-lang.org/reference/unsafety.html)
- [`unsafe_code` lint documentation](https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html#unsafe-code)
- noyalib's ADR-0003 (the precedent we are following).
