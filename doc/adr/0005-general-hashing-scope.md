# ADR-0005 — Adding general-purpose hashing primitives (`hsh-digest`)

- **Status:** Accepted
- **Date:** 2026-05-19
- **Deciders:** Sebastien Rousseau
- **Tracking issue:** [#145](https://github.com/sebastienrousseau/hsh/issues/145)

## Context

`hsh` is a *password hashing* library. From v0.0.9 onwards the
high-level API is `hsh::api::hash` and `hsh::api::verify_and_upgrade`,
backed by Argon2id / bcrypt / scrypt / PBKDF2 — all memory-hard or
iteration-hard KDFs.

Real users routinely ask for a "while you're at it, give me SHA-256"
convenience. They want:

- A consistent feel across hash primitives (`Hasher::new(Algorithm::X)`).
- One dep in `Cargo.toml` instead of `sha2 + sha3 + blake3 + …`.
- Constant-time comparison and zeroize as a default, not as
  remembered-to-import.

If we don't ship that surface, users wire up the RustCrypto crates
directly, often without `subtle::ct_eq` or `zeroize`. So even a thin
wrapper improves real-world security posture.

The danger is **scope creep into a "general crypto" crate**. We need
to draw a clear line.

## Decision

`hsh-digest` is a **new workspace member** that re-exports the
RustCrypto `digest::Digest`-style primitives behind a small
algorithm-selection API, with two non-negotiable rules:

1. **Loud warnings against using it for password storage.** Crate-level
   rustdoc, README, and the `Hasher::new` docstring all point readers
   at `hsh::api::hash` for passwords.
2. **No KDF / MAC / signature primitives.** Strictly fixed-output
   one-shot or streaming hashes. HMAC, HKDF, signatures stay where
   they belong (RustCrypto sibling crates or `hsh` for password
   hashing). `hsh-digest` is not a "general crypto" crate.

### What ships in v0.0.9

- `crates/hsh-digest` with:
  - `Algorithm` enum: SHA-256 / 384 / 512, SHA3-256 / 384 / 512,
    BLAKE3 — each behind its own feature flag (`sha2`, `sha3`,
    `blake3`, all on by default).
  - `Hasher::new / update / finalize` streaming API.
  - One-shot `hash(algorithm, data)` convenience.
  - `constant_time_eq(a, b)` helper backed by `subtle`.
  - 13 KAT integration tests against NIST CAVP / FIPS 202 / BLAKE3
    project test vectors.

### What's reserved for follow-up

- **KangarooTwelve / TurboSHAKE128 / TurboSHAKE256** (RFC 9861,
  October 2025). The `k12` feature flag is declared but currently
  a no-op marker.
- **Ascon-Hash256 / Ascon-XOF128** (NIST SP 800-232 final, August
  2025). The `ascon` feature flag is declared but currently a no-op
  marker.

Both are tracked under Phase 6 follow-up work in
[#145](https://github.com/sebastienrousseau/hsh/issues/145).

## Consequences

**Accepted trade-offs:**

- Slightly more code to maintain. We mitigate by re-exporting the
  RustCrypto primitives directly rather than reimplementing.
- One more workspace member, one more crates.io publish per release.
- Discoverability cost: users may need to learn `hsh` versus
  `hsh-digest`. The README and crate-level docs explicitly route them.

**Benefits:**

- Real users who would have rolled their own SHA-256 + memcmp now
  get constant-time comparison and zeroize for free.
- Single dep in `Cargo.toml` for the common "I need a digest"
  use-case.
- Forward-compat home for K12 / Ascon and any future NIST winner
  — they can land in `hsh-digest` without touching the
  password-hashing API surface.

## Non-goals

- **HMAC / HKDF / SipHash / SHA-1.** Use the RustCrypto sibling
  crates (`hmac`, `hkdf`, `siphasher`). SHA-1 specifically is
  deprecated for all security uses; we won't ship it even behind a
  feature flag.
- **Signatures / KEMs / PQ primitives.** Use `RustCrypto/signatures`
  or `aws-lc-rs`. `hsh-digest` is hashes-only.
- **A trait soup.** We re-export *one* trait (`digest::Digest`
  implicitly via the marker types), present *one* abstraction
  (`Algorithm` + `Hasher`).

## Compliance

- `crates/hsh-digest/src/lib.rs` opens with a "⚠️ This crate is NOT
  for password storage" warning before any other text.
- The crate has `#![forbid(unsafe_code)]` (ADR-0006 applies
  workspace-wide).
- KAT tests against NIST CAVP / FIPS 202 / BLAKE3 project vectors
  gate every release.

## References

- [NIST FIPS 180-4 SHA-2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [NIST FIPS 202 SHA-3 + SHAKE](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [RFC 9861 — KangarooTwelve + TurboSHAKE128/256](https://datatracker.ietf.org/doc/rfc9861/)
- [NIST SP 800-232 — Ascon](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.pdf)
