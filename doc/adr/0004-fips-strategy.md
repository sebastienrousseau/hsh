# ADR-0004 — FIPS 140-3 strategy

- **Status:** Accepted. Phase 4 follow-up (`hsh-backend-awslc`)
  delivered in v0.0.10.
- **Date:** 2026-05-19 (Phase 4 wired up 2026-05-26)
- **Deciders:** Sebastien Rousseau
- **Tracking issue:** [#143](https://github.com/sebastienrousseau/hsh/issues/143)
  (closed in v0.0.10)

## Context

A non-trivial share of `hsh`'s addressable market — federal agencies,
their contractors, regulated financial services, healthcare —
**requires FIPS 140-3 validated cryptographic modules**. NIST's
SP 800-63B Rev. 4 and PCI DSS 4.0 §3.5 both effectively require
either a validated module or a documented compensating control.

Three facts shape the strategy:

1. **Argon2 / bcrypt / scrypt have no FIPS 140-3 validated
   implementation anywhere.** Not in `aws-lc-rs`, not in OpenSSL FIPS,
   not in BoringSSL FIPS. CMVP refuses to certify them. This isn't a
   build-system gap — it's a standards gap.
2. **PBKDF2-HMAC-SHA-256 / SHA-512 *is* FIPS-validated** in AWS-LC FIPS
   3.0 (Cert. #4759), which `aws-lc-rs 1.13`'s `fips` feature pulls in.
3. **Pure-Rust crypto cannot be FIPS-validated.** CMVP's process
   requires evaluating a specific compiled binary; the standard cargo
   pipeline can't produce that artefact reproducibly. The only
   feasible Rust path today is to delegate primitives to a validated
   C library through a vetted FFI wrapper.

A library claiming "FIPS support" without addressing all three is
misleading.

## Decision

`hsh` supports FIPS deployments through a **three-layer contract**:

1. **`Backend` enum** declares the caller's requirement (`Native` or
   `Fips140Required`).
2. **`Policy::fips_140_pbkdf2()` preset** combines `Backend::Fips140Required`
   with `PrimaryAlgorithm::Pbkdf2` and OWASP-2025 parameters (600 000
   iterations, HMAC-SHA-256, 32-byte output).
3. **Runtime refusal** in [`crate::api::hash`] when:
   - The policy demands FIPS but the primary is Argon2 / bcrypt /
     scrypt → `Error::InvalidParameter` mentioning the FIPS contract.
   - The policy demands FIPS but the build can't satisfy it
     (`Backend::fips_available_in_build()` returns `false`) →
     `Error::InvalidParameter` pointing at the build misconfiguration.

The result is that **no `hsh::api::hash` call ever silently produces
non-FIPS output when the caller asked for FIPS**. Either the caller
gets a FIPS-validated hash or they get a typed error.

### What this PR delivers (v0.0.9)

- `Backend::{Native, Fips140Required}` and `Backend::is_fips()`.
- `Backend::fips_available_in_build()` — hardcoded `false` today.
- `Policy.backend` field.
- `Policy::fips_140_pbkdf2()` preset.
- `PrimaryAlgorithm::Pbkdf2` plus a real PBKDF2-HMAC-SHA-256/512
  implementation via the pure-Rust RustCrypto `pbkdf2` crate.
- A custom PHC-string format
  (`$pbkdf2-sha256$i=<iters>,l=<len>$<salt>$<hash>`) that `hsh`
  parses end-to-end. Algorithm drift (Argon2 → PBKDF2), iteration
  drift, and PRF drift all trigger `Outcome::Valid { rehashed: Some(_) }`.
- 8 integration tests in `crates/hsh/tests/test_pbkdf2.rs`.
- A `fips` Cargo feature, currently a no-op marker so callers can lock
  the flag into their `Cargo.toml` today.

### What the Phase 4 follow-up delivered (v0.0.10)

A new `crates/hsh-backend-awslc` companion crate that:

- Depends on `aws-lc-rs = { version = "1.17", features = ["fips"] }`.
- Exposes a stable `pbkdf2_derive(password, salt, prf, iterations,
  dk_len)` function backed by `aws_lc_rs::pbkdf2::derive`.
- Is **excluded from the default workspace** (`members = […]` does
  not include it) so contributors without the FIPS toolchain still
  get a working `cargo build --workspace`.
- Is pulled into `hsh` only when the `fips` Cargo feature is enabled
  (`hsh = { features = ["fips"] }`). With that flag,
  `Backend::fips_available_in_build()` flips to `true` (via
  `cfg!(feature = "fips")`) and `Pbkdf2::hash_with` routes through
  AWS-LC instead of the pure-Rust path.
- Validates parity with the pure-Rust path against RFC 6070-style
  test vectors in `crates/hsh-backend-awslc/tests/derive.rs`.
- Carries documented build prerequisites (Go ≥ 1.21, CMake ≥ 3.18,
  recent clang) in `doc/FIPS.md` and the crate README.

Keeping the backend as a non-member opt-in preserves the original
trade-off: the strict "no fail-open" contract holds, default builds
remain cheap, and downstream consumers can opt into the FIPS path
with a one-line Cargo feature flip.

## Consequences

**Accepted trade-offs:**

- The PBKDF2 PHC format we emit is hand-rolled rather than going
  through `pbkdf2`'s native PHC encoder. Reason: routing through the
  RustCrypto encoder would tightly couple the verify path to its
  internals. With the v0.0.10 swap to `aws-lc-rs`, this choice pays
  off — both backends emit identical PHC strings.
- The `fips` Cargo feature requires a heavyweight build toolchain
  (Go + CMake + clang). Contributors and CI runners without it can
  still build everything else; only `--features fips` triggers the
  AWS-LC sub-build.
- On macOS, rustdoc doctests can't find the AWS-LC dylib at runtime.
  Doctests run **without** the `fips` feature; integration tests
  (which `cargo` sets the rpath for correctly) cover the FIPS path.
  See `doc/FIPS.md` "macOS dylib caveat".

**Benefits:**

- Callers can write `Policy::fips_140_pbkdf2()` today and `hsh` will
  reject any operation that would silently drop the FIPS guarantee.
- The PBKDF2 algorithm itself works **right now** with pure-Rust
  primitives for any caller that doesn't need FIPS validation but
  prefers PBKDF2 (compliance ladder, deterministic verification cost,
  no memory pressure).
- Algorithm drift detection means existing Argon2id/bcrypt/scrypt
  deployments can migrate to PBKDF2 over time via `verify_and_upgrade`
  rather than a flag-day re-hash.
- The Phase 4 follow-up is a pure-additive change — no breaking API
  modifications.

## Non-goals

- **Self-validating module.** `hsh` does not claim to be a FIPS
  module. It is *callable from* FIPS deployments through `aws-lc-rs`'s
  validated boundary.
- **FIPS for Argon2/bcrypt/scrypt.** Not possible today; not on our
  roadmap. If your compliance regime mandates one of those and FIPS,
  you have a contradiction to escalate to your auditor.
- **Re-implementing PBKDF2 ourselves.** We use RustCrypto's
  implementation today (pure Rust) and the AWS-LC implementation
  tomorrow (validated C). We don't hand-roll the primitive.

## Compliance

- [`Backend::fips_available_in_build`](../../crates/hsh/src/backend.rs)
  returns `cfg!(feature = "fips")` — true when `hsh-backend-awslc` is
  in the dep graph, false otherwise. The runtime check in
  `api::hash_unpeppered` uses this to refuse FIPS-tagged minting
  whenever the build can't satisfy the requirement.
- [`crate::api::hash_unpeppered`](../../crates/hsh/src/api.rs) refuses
  to mint Argon2/bcrypt/scrypt under a FIPS policy and refuses to mint
  anything when the feature isn't compiled in.
- 9 integration tests in `crates/hsh/tests/test_pbkdf2.rs` cover both
  refusal paths, the PBKDF2 round-trip / drift cases, and the
  feature-on minting path.
- 7 integration tests in
  `crates/hsh-backend-awslc/tests/derive.rs` validate the AWS-LC
  PBKDF2 wrapper against RFC 6070-style test vectors and confirm
  parameter validation.

## References

- [NIST CMVP FIPS 140-3 cert list](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)
- [AWS-LC FIPS 3.0 announcement](https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation/)
- [`aws-lc-rs` documentation](https://docs.rs/aws-lc-rs)
- [NIST SP 800-63B Rev. 4](https://pages.nist.gov/800-63-4/)
- [PCI DSS 4.0 §3.5](https://www.pcisecuritystandards.org/)
- [`doc/FIPS.md`](../FIPS.md) — deployment guide.
