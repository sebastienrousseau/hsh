# FIPS 140-3 deployment

`hsh` supports FIPS-regulated environments through the **`Backend` /
`Policy::fips_140_pbkdf2()`** contract. This document covers what's
delivered today, what the contract guarantees, and the deployment
playbook.

## TL;DR

| Question                                                | Answer |
| ------------------------------------------------------- | ------ |
| Can I write code today that requires FIPS validation?   | **Yes** — use `Policy::fips_140_pbkdf2()`. |
| Will it silently fall back to non-FIPS crypto?          | **No** — `hsh` returns a typed error if the build can't satisfy the requirement. |
| Is the routing actually validated today?                | **Yes, with the `fips` Cargo feature.** PBKDF2 runs via `aws-lc-rs` inside AWS-LC FIPS 3.0 (CMVP Cert #4759). Without the feature, the runtime check refuses to mint. |
| What hashes work in FIPS mode?                          | **PBKDF2-HMAC-SHA-256/512 only.** Argon2 / bcrypt / scrypt have no FIPS-validated implementation anywhere. |
| Can I verify existing Argon2/bcrypt/scrypt hashes under FIPS? | **Yes** — verification under a FIPS policy still works; only *minting* is restricted. The verifier signals `Outcome::Valid { rehashed: Some(new_phc) }` so old hashes migrate to PBKDF2 on next login. |

## The model

```text
Caller declares                       hsh enforces
─────────────────                     ──────────────
Policy::fips_140_pbkdf2()       ─→   refuse to mint non-PBKDF2 hashes
                                ─→   refuse to mint anything if the
                                     build can't satisfy FIPS
                                ─→   on verify, rehash to PBKDF2
                                     if stored is non-FIPS
```

The contract is **fail closed**: no `hsh::api::hash` call can produce
a non-FIPS hash when the caller asked for FIPS. Either you get a
PBKDF2 hash from a validated module, or you get an error.

## Why only PBKDF2

| Algorithm | FIPS-validated implementation? |
| --------- | ------------------------------ |
| **PBKDF2-HMAC-SHA-2** | ✅ AWS-LC FIPS 3.0 (Cert. #4759), OpenSSL FIPS 3.x, BoringSSL FIPS |
| Argon2id  | ❌ None. CMVP has no certificate for any Argon2 implementation. |
| bcrypt    | ❌ None. |
| scrypt    | ❌ None. |
| SHA-2 / HMAC-SHA-2 | ✅ same module list as PBKDF2 — used internally |

This isn't a build-system gap — it's a standards gap. Argon2 was not
included in the validation cycles for any of the major FIPS modules.

## What's delivered

- `Backend::{Native, Fips140Required}` and `Backend::is_fips()`.
- `Backend::fips_available_in_build()` — returns `true` when the
  `fips` Cargo feature is on (`cfg!(feature = "fips")`), `false`
  otherwise.
- `Policy.backend` field.
- `Policy::fips_140_pbkdf2()` preset: PBKDF2-HMAC-SHA-256, 600 000
  iterations (OWASP-2025 minimum), 32-byte output,
  `Backend::Fips140Required`.
- `PrimaryAlgorithm::Pbkdf2` + a working PBKDF2-HMAC-SHA-256/512
  implementation via pure-Rust RustCrypto (default build) or AWS-LC
  FIPS 3.0 (with the `fips` feature).
- PHC string format `$pbkdf2-sha256$i=<iters>,l=<len>$<salt>$<hash>`
  — identical bytes from either provider.
- Algorithm-drift, iteration-drift, and PRF-drift detection in
  `api::verify_and_upgrade`.
- `crates/hsh-backend-awslc` — companion crate that wraps
  `aws-lc-rs`. Excluded from default workspace `members`; pulled in
  via `--features fips` on the `hsh` crate.
- ADR-0004 documenting the strategy.

## Build requirements (with `--features fips`)

The first build of `hsh` (or downstream) with `--features fips`
compiles the AWS-LC FIPS sub-module from source. Required on the
**build host** (not on the runtime host):

| Tool   | Version  | macOS                           | Linux                                  |
|--------|----------|---------------------------------|----------------------------------------|
| Go     | ≥ 1.21   | `brew install go`               | distro package or `mise use go@1.21`   |
| CMake  | ≥ 3.18   | `brew install cmake`            | distro package                         |
| clang  | ≥ 14     | Xcode Command Line Tools        | distro `clang` / `clang-14`            |

First build takes 2–4 minutes; subsequent builds are cached.

### macOS dylib caveat for doctests

`aws-lc-fips-sys` links AWS-LC as a dynamic library
(`libaws_lc_fips_*_crypto.dylib`). Regular `cargo test` and `cargo
run` set up the rpath correctly, but **rustdoc doctests** run from a
temp directory and the dynamic loader can't find the dylib (the
error reads `Library not loaded: @rpath/libaws_lc_fips_*_crypto.dylib`).
The fix is to run doctests **without** the `fips` feature — the
pure-Rust PBKDF2 path is identical for documentation purposes. CI
follows this split:

```sh
# Integration + unit tests under FIPS feature (works fine):
cargo test -p hsh --features fips --lib --tests

# Doctests without the FIPS feature (avoids the dylib loader issue):
cargo test -p hsh --doc
```

This is an aws-lc-rs / macOS runtime-loader limitation, not a
correctness issue. The output of PBKDF2 derivation is bit-identical
under both providers (verified against RFC 6070 vectors in
`crates/hsh-backend-awslc/tests/derive.rs`).

## Deployment playbook

```toml
[dependencies]
hsh = { version = "0.0.10", features = ["fips"] }
# hsh-backend-awslc is pulled in transitively; no need to list it
# explicitly unless you want to use its derive function directly.
```

```rust
use hsh::{api, Policy};

let policy = Policy::fips_140_pbkdf2();
let stored = api::hash(&policy, password)?;
// stored is now $pbkdf2-sha256$i=600000,l=32$<salt>$<hash>,
// derived through aws-lc-rs's FIPS-validated module.
```

If you can't ship the FIPS toolchain to your build host yet, you
have two options:

1. **Cross-compile** in CI using the toolchain on a Linux runner and
   ship the binary artefact — avoids needing the toolchain on every
   contributor laptop.
2. **Apply a compensating control** — bcrypt or Argon2id under a
   non-FIPS policy, plus a documented justification to your auditor
   explaining that PBKDF2 is the only validated KDF and your team
   has determined the additional brute-force resistance of Argon2id
   outweighs the validation gap. NIST SP 800-63B Rev. 4 explicitly
   permits this with a documented risk acceptance.

## Migration path

If your existing deployment uses Argon2id and you're moving to FIPS:

1. Deploy with `Policy::fips_140_pbkdf2()` on the *verify* side, plus
   `hsh-backend-awslc` in your dep graph.
2. `api::verify_and_upgrade` will accept the existing Argon2id hashes
   (verification under a FIPS policy is permitted), match them, and
   return `Outcome::Valid { rehashed: Some(new_phc) }` with a new
   PBKDF2 hash to persist.
3. As users log in, the corpus migrates from Argon2id → PBKDF2.
4. After a chosen window, audit your DB for rows still on Argon2id
   and force-rotate inactive users.

This is the same shape as the pepper-rotation playbook in
[`KMS-INTEGRATION.md`](KMS-INTEGRATION.md).

## Threat model

The FIPS path protects against:

- **Audit findings** — the regulator can point at a CMVP certificate.
- **Cryptographic-primitive substitution attacks** — the validated
  module's known-answer self-tests fire on every process startup.

It does **not** protect against:

- **The compliance gap** itself — PBKDF2 is weaker against modern
  GPU brute force than Argon2id. FIPS validation says nothing about
  algorithm strength.
- **Side channels at the AWS-LC layer.** AWS-LC is constant-time for
  the primitives we use; we trust their analysis.
- **A compromised FIPS module.** Out of scope.

## References

- [NIST CMVP — FIPS 140-3](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
- [AWS-LC FIPS 140-3 certificate](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4759)
- [`aws-lc-rs` docs](https://docs.rs/aws-lc-rs)
- [`doc/adr/0004-fips-strategy.md`](adr/0004-fips-strategy.md) — the
  full decision record.
