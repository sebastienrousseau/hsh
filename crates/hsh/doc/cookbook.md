<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `hsh` cookbook

Copy-pasteable patterns for the most common `hsh` deployments. Each
recipe is self-contained and assumes only `hsh = "0.0.9"` in
`Cargo.toml` (plus the named feature where applicable).

For step-by-step onboarding, see [`GETTING_STARTED.md`](../../../GETTING_STARTED.md).
For the conceptual model behind these recipes, see
[`architecture.md`](./architecture.md). For the full API reference,
see <https://docs.rs/hsh>.

## Table of contents

- [Basic round-trip (OWASP 2025)](#basic-round-trip-owasp-2025)
- [Auto-rehash on policy drift](#auto-rehash-on-policy-drift)
- [Bcrypt with the 72-byte safety rail](#bcrypt-with-the-72-byte-safety-rail)
- [Migrating from a legacy bcrypt database](#migrating-from-a-legacy-bcrypt-database)
- [Peppered with `LocalPepper`](#peppered-with-localpepper)
- [Pepper rotation](#pepper-rotation)
- [FIPS 140-3 routing (PBKDF2)](#fips-140-3-routing-pbkdf2)
- [Custom parameters via `PolicyBuilder`](#custom-parameters-via-policybuilder)
- [Non-UTF-8 passwords](#non-utf-8-passwords)
- [Async / multi-threaded usage](#async--multi-threaded-usage)
- [Per-host calibration](#per-host-calibration)

## Basic round-trip (OWASP 2025)

```rust
use hsh::{api, Outcome, Policy};

fn main() -> Result<(), hsh::Error> {
    let policy = Policy::owasp_minimum_2025();
    let stored = api::hash(&policy, "correct horse battery staple")?;

    let outcome = api::verify_and_upgrade(
        &policy,
        "correct horse battery staple",
        &stored,
    )?;

    assert!(outcome.is_valid());
    assert!(!outcome.needs_rehash());
    Ok(())
}
```

The `Policy::owasp_minimum_2025()` preset uses Argon2id with
`m = 19 456 KiB`, `t = 2`, `p = 1` — current as of 2025 and the
right default for greenfield deployments.

## Auto-rehash on policy drift

The whole point of `verify_and_upgrade`: when stored material falls
below current policy, you get the new PHC string back. Persist it.

```rust
use hsh::{api, Outcome, Policy};

fn login(stored: &str, password: &str) -> Result<bool, hsh::Error> {
    let policy = Policy::owasp_minimum_2025();
    let outcome = api::verify_and_upgrade(&policy, password, stored)?;

    match outcome {
        Outcome::Valid { rehashed: Some(new_phc) } => {
            // The stored hash is below policy — persist `new_phc`
            // against the user row. The next login reads the
            // upgraded hash directly.
            db::update_password_hash(&new_phc);
            Ok(true)
        }
        Outcome::Valid { rehashed: None } => Ok(true),
        Outcome::Invalid => Ok(false),
    }
}
# mod db { pub fn update_password_hash(_: &str) {} }
```

Drift detection covers: algorithm (Argon2i → Argon2id), parameter
(low m_cost / t_cost), PBKDF2 PRF (SHA-256 ↔ SHA-512), PBKDF2
iteration count, and pepper-version drift (when the `pepper`
feature is on).

## Bcrypt with the 72-byte safety rail

`hsh` rejects bcrypt inputs over 72 bytes by default — silent
truncation was the CVE-2025-22228 class. For long inputs, opt in
to an HMAC-SHA-256 pre-hash:

```rust
use hsh::{api, Policy};
use hsh::algorithms::bcrypt::{BcryptParams, PrehashAlgorithm};
use hsh::policy::{PolicyBuilder, PrimaryAlgorithm};

fn build_policy() -> Result<Policy, hsh::Error> {
    PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
        .primary(PrimaryAlgorithm::Bcrypt)
        .bcrypt(BcryptParams::new(10).with_prehash(PrehashAlgorithm::Sha256))
        .build()
}
```

With `with_prehash(Sha256)`, inputs of any length are accepted —
`hsh` HMACs them down to 32 bytes (base64 → 44 chars) before
passing to bcrypt. The on-wire bcrypt MCF string is indistinguishable
from a "normal" bcrypt hash; the pre-hash is a deployment-side detail.

## Migrating from a legacy bcrypt database

Already have a column full of `$2b$10$…` bcrypt hashes? Don't
migrate them in a batch. Let the verifier upgrade users on next
login, transparently:

```rust
use hsh::{api, Outcome, Policy};

fn login(legacy_bcrypt: &str, password: &str) -> Result<bool, hsh::Error> {
    // Run under an Argon2id-primary policy.
    let policy = Policy::owasp_minimum_2025();

    let outcome = api::verify_and_upgrade(&policy, password, legacy_bcrypt)?;
    match outcome {
        Outcome::Valid { rehashed: Some(new_argon2id) } => {
            // Algorithm drift detected (Bcrypt → Argon2id).
            // Persist the new hash; the next login uses it directly.
            db::update_password_hash(&new_argon2id);
            Ok(true)
        }
        Outcome::Valid { rehashed: None } => Ok(true), // already migrated
        Outcome::Invalid => Ok(false),
    }
}
# mod db { pub fn update_password_hash(_: &str) {} }
```

After a few login cycles, the bulk of active accounts migrate
themselves. Dormant accounts can be force-rotated (require password
reset) on a schedule.

## Peppered with `LocalPepper`

A *pepper* is a server-side secret HMAC'd over every password before
the KDF. An attacker who steals only your database cannot brute-
force credentials offline because they're missing the pepper.

```rust
# #[cfg(feature = "pepper")]
# fn demo() -> Result<(), hsh::Error> {
use hsh::{api, Policy};
use hsh_kms::{KeyVersion, LocalPepper};

let pepper = LocalPepper::builder()
    .add(KeyVersion::new(1), b"server-pepper-32-bytes-keep-secret".to_vec())
    .current(KeyVersion::new(1))
    .build()
    .map_err(|e| hsh::Error::Pepper(e.to_string().into()))?;

let policy = Policy::owasp_minimum_2025().with_pepper(pepper);

let stored = api::hash(&policy, "user password")?;
assert!(stored.starts_with("hsh-pepper:1:"));
# Ok(()) }
# #[cfg(not(feature = "pepper"))] fn demo() {}
# fn main() { demo(); }
```

Requires `hsh = { version = "0.0.9", features = ["pepper"] }`. For
KMS-backed pepper (AWS / GCP / Azure / Vault), see
[`doc/KMS-INTEGRATION.md`](../../../doc/KMS-INTEGRATION.md).

## Pepper rotation

Add a new key version, mark it current. Existing peppered hashes
(`hsh-pepper:1:...`) still verify; on next successful login they
get rehashed under `hsh-pepper:2:...`.

```rust
# #[cfg(feature = "pepper")]
# fn demo() -> Result<(), hsh::Error> {
use hsh::Policy;
use hsh_kms::{KeyVersion, LocalPepper};

let pepper = LocalPepper::builder()
    .add(KeyVersion::new(1), b"v1-pepper-keep-this-32-bytes-ok!".to_vec())
    .add(KeyVersion::new(2), b"v2-pepper-keep-this-32-bytes-ok!".to_vec())
    .current(KeyVersion::new(2))  // ← rotation happens here
    .build()
    .map_err(|e| hsh::Error::Pepper(e.to_string().into()))?;

let _policy = Policy::owasp_minimum_2025().with_pepper(pepper);

// Stored hashes carrying `hsh-pepper:1:…` continue to verify,
// and `verify_and_upgrade` returns Outcome::Valid { rehashed: Some(_) }
// so the caller persists a fresh `hsh-pepper:2:…` value.
# Ok(()) }
# #[cfg(not(feature = "pepper"))] fn demo() {}
# fn main() { demo(); }
```

The rotation is non-destructive — `KeyVersion(1)` MUST remain in
the keyset until you've audited that all stored values have moved
to `KeyVersion(2)`. Removing an old version before then locks
users out.

## FIPS 140-3 routing (PBKDF2)

For deployments that require FIPS 140-3 validated crypto:

```rust
use hsh::Policy;

let policy = Policy::fips_140_pbkdf2();
// policy.primary  = PrimaryAlgorithm::Pbkdf2
// policy.backend  = Backend::Fips140Required
// policy.pbkdf2   = OWASP-2025: 600 000 iterations, SHA-256, 32-byte dk
```

The `Backend::Fips140Required` contract makes `api::hash` refuse to
mint Argon2 / bcrypt / scrypt hashes — only PBKDF2 has a FIPS-
validated implementation path. **Today the path routes through the
pure-Rust RustCrypto `pbkdf2` crate**; the validated `aws-lc-rs`
backend lands as a follow-up (`hsh-backend-awslc`, v0.0.10+).

Verification under a FIPS policy still accepts every legacy
algorithm so existing Argon2 / bcrypt / scrypt hashes can be
upgraded on next login.

See [`doc/FIPS.md`](../../../doc/FIPS.md) for the deployment runbook.

## Custom parameters via `PolicyBuilder`

When the OWASP preset is too aggressive for your latency budget
(or not aggressive enough):

```rust
use hsh::{Backend, Policy};
use hsh::policy::{PolicyBuilder, PrimaryAlgorithm};

fn build() -> Result<Policy, hsh::Error> {
    PolicyBuilder::new()
        .primary(PrimaryAlgorithm::Argon2id)
        .backend(Backend::Native)
        .argon2(argon2::Params::new(
            65_536,   // m_cost (KiB)
            3,        // t_cost (iterations)
            1,        // p_cost (parallelism)
            Some(32), // output length
        ).expect("valid argon2 params"))
        .build()
}
```

For finding the right parameters for your host, see
[Per-host calibration](#per-host-calibration) below.

## Non-UTF-8 passwords

`api::hash` accepts `impl AsRef<[u8]>` — passwords need not be
UTF-8. Useful for legacy databases or pre-hashed inputs:

```rust
use hsh::{api, Policy};

# fn main() -> Result<(), hsh::Error> {
let policy = Policy::owasp_minimum_2025();

// &str — works as expected.
let _ = api::hash(&policy, "hunter2")?;

// &[u8] — also works.
let _ = api::hash(&policy, &b"hunter2"[..])?;

// Vec<u8> with non-UTF-8 bytes — works for Argon2id / scrypt / PBKDF2.
let bytes: Vec<u8> = vec![0xff, 0xfe, 0x80, 0x81];
let _ = api::hash(&policy, &bytes)?;
# Ok(()) }
```

**Exception**: bcrypt requires UTF-8 internally. Passing non-UTF-8
bytes to a bcrypt-primary policy returns `Error::InvalidPassword`
with a clear message — use `BcryptParams::with_prehash(Sha256)`
to accept arbitrary bytes via HMAC pre-hash.

## Async / multi-threaded usage

`hsh` is synchronous and CPU-bound. From an `async` runtime, use
`spawn_blocking`:

```rust
# #[cfg(feature = "tokio-example")]
async fn hash_async(password: String) -> Result<String, hsh::Error> {
    tokio::task::spawn_blocking(move || {
        let policy = hsh::Policy::owasp_minimum_2025();
        hsh::api::hash(&policy, &password)
    })
    .await
    .map_err(|_| hsh::Error::Verification("hash task panicked".into()))?
}
# fn main() {}
```

`Policy` is `Send + Sync + Clone` — share a single instance across
worker threads. Cloning is cheap (it's an `Arc<dyn Pepper>` + a
handful of `Copy` params).

## Per-host calibration

OWASP's published minimums are conservative — your host can
probably afford more. Use the `hsh` CLI to measure:

```sh
$ hsh calibrate --algorithm argon2id --target-ms 500
argon2id m=131072 t=2 p=1   ≈ 503 ms

$ hsh calibrate --algorithm bcrypt --target-ms 250
bcrypt cost=11              ≈ 247 ms

$ hsh calibrate --algorithm pbkdf2 --target-ms 250
pbkdf2-sha256 iters=2400000 ≈ 251 ms
```

Pass the suggested parameters to `PolicyBuilder` to build a host-
tuned policy. Re-run calibration when you change hosts (CPU
generations / clock speeds shift the optimal parameter set).

See [`doc/BENCHMARKS.md`](../../../doc/BENCHMARKS.md) for the full
methodology.
