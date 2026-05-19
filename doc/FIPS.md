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
| Is the routing actually validated today?                | **Not yet.** PBKDF2 runs via the pure-Rust RustCrypto `pbkdf2` crate. The `aws-lc-rs` routing lands as a Phase 4 follow-up. |
| What hashes work in FIPS mode?                          | **PBKDF2-HMAC-SHA-256/512 only.** Argon2 / bcrypt / scrypt have no FIPS-validated implementation anywhere. |
| Can I verify existing Argon2/bcrypt/scrypt hashes under FIPS? | **Yes** — verification under a FIPS policy still works; only *minting* is restricted. The verifier signals `Outcome::Valid { needs_rehash: true }` so old hashes migrate to PBKDF2 on next login. |

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

## What's delivered in v0.0.9

- `Backend::{Native, Fips140Required}` and `Backend::is_fips()`.
- `Backend::fips_available_in_build()` — hardcoded `false`.
- `Policy.backend` field.
- `Policy::fips_140_pbkdf2()` preset: PBKDF2-HMAC-SHA-256, 600 000
  iterations (OWASP-2025 minimum), 32-byte output, `Backend::Fips140Required`.
- `PrimaryAlgorithm::Pbkdf2` + a working PBKDF2-HMAC-SHA-256/512
  implementation via pure-Rust RustCrypto.
- PHC string format `$pbkdf2-sha256$i=<iters>,l=<len>$<salt>$<hash>`.
- Algorithm-drift, iteration-drift, and PRF-drift detection in
  `api::verify_and_upgrade`.
- `fips` Cargo feature — currently a no-op marker (see below).
- ADR-0004 documenting the strategy.

## What lands in the Phase 4 follow-up

A new `crates/hsh-backend-awslc` workspace member that:

- Depends on `aws-lc-rs = { version = "1.13", features = ["fips"] }`.
- Routes `Pbkdf2::hash_with` through `aws_lc_rs::pbkdf2::derive`.
- Flips `Backend::fips_available_in_build()` to `true`.

It's a pure-additive change. Application code written today against
`Policy::fips_140_pbkdf2()` works unchanged once the backend lands —
the runtime refusal stops firing because the build can satisfy the
requirement.

## Why the follow-up is separate

The AWS-LC FIPS sub-build requires Go ≥ 1.21, CMake ≥ 3.18, recent
clang, and on macOS the full Xcode toolchain. That's not reliably
available on contributor laptops or default CI runners, so pulling
`aws-lc-rs` into the default workspace would break the build for
~half the contributor base.

Pushing it into a separate crate keeps `hsh`'s default build cheap
while preserving the strict no-fail-open contract.

## Deployment playbook (today)

If you need FIPS *today*, you have three options:

1. **Wait** for the `hsh-backend-awslc` follow-up. The shape of the
   API won't change.
2. **Vendor your own** `Pbkdf2::hash_with` replacement that calls
   `aws-lc-rs` directly, then submit it back as the follow-up.
3. **Apply a compensating control** — bcrypt or Argon2id under a
   non-FIPS policy, plus a documented justification to your auditor
   explaining that PBKDF2 is the only validated KDF and your team
   has determined the additional brute-force resistance of Argon2id
   outweighs the validation gap. NIST SP 800-63B Rev. 4 explicitly
   permits this with a documented risk acceptance.

## Deployment playbook (post-follow-up)

```toml
[dependencies]
hsh                = { version = "0.0.10", features = ["fips"] }
hsh-backend-awslc  = "0.0.10"   # pulls in aws-lc-rs + flips
                                # fips_available_in_build to true
```

```rust
use hsh::{api, Policy};

let policy = Policy::fips_140_pbkdf2();
let stored = api::hash(&policy, password)?;
// stored is now $pbkdf2-sha256$i=600000,l=32$<salt>$<hash>,
// derived through aws-lc-rs's FIPS-validated module.
```

## Migration path

If your existing deployment uses Argon2id and you're moving to FIPS:

1. Deploy with `Policy::fips_140_pbkdf2()` on the *verify* side, plus
   `hsh-backend-awslc` in your dep graph.
2. `api::verify_and_upgrade` will accept the existing Argon2id hashes
   (verification under a FIPS policy is permitted), match them, and
   return `Outcome::Valid { needs_rehash: true }` with a new PBKDF2
   hash to persist.
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
