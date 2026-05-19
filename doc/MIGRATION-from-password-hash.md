# Migrating from raw `password-hash` to `hsh`

The [`password-hash`](https://crates.io/crates/password-hash) crate
from RustCrypto provides the PHC-string traits (`PasswordHasher`,
`PasswordVerifier`) plus per-algorithm impls in sibling crates
(`argon2`, `scrypt`, `pbkdf2`). It's the lowest-level option in the
Rust ecosystem — `hsh` is built on top of it.

This guide shows what you gain by switching from raw
`password-hash` usage to the `hsh` facade.

## Why migrate

- **Multi-algorithm**: one `api::verify_and_upgrade` handles Argon2id
  / bcrypt / scrypt / PBKDF2 (plus `hsh`'s pepper wrapper). No more
  per-algorithm match arms in your auth code.
- **Auto-rehash**: parameter drift detection across algorithms.
- **PHC + MCF**: bcrypt's `$2b$…` modular crypt format is parsed
  transparently, which `password-hash` itself does not do.
- **Pepper support**: `Policy::with_pepper(...)` adds a KMS-backed
  server secret to every hash.
- **FIPS contract**: `Backend::Fips140Required` fail-closes when the
  build can't satisfy a FIPS requirement.

## Before

```rust
use argon2::{Algorithm, Argon2, Params, Version};
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use rand_core::OsRng;

let salt = SaltString::generate(&mut OsRng);
let argon = Argon2::new(
    Algorithm::Argon2id,
    Version::V0x13,
    Params::new(19_456, 2, 1, Some(32))?,
);
let stored = argon
    .hash_password(b"password123", &salt)?
    .to_string();

let parsed = PasswordHash::new(&stored)?;
let ok = argon.verify_password(b"password123", &parsed).is_ok();
```

## After

```rust
use hsh::{api, Policy};

let policy = Policy::owasp_minimum_2025();
let stored = api::hash(&policy, "password123")?;
let (outcome, _) = api::verify_and_upgrade(&policy, "password123", &stored)?;
assert!(outcome.is_valid());
```

## When to stay on raw `password-hash`

- You're writing a *new* `PasswordHasher` impl — `hsh` consumes the
  trait, doesn't replace it.
- You need fine-grained control over a single algorithm and you
  don't want any of `hsh`'s opinions (presets, pepper, rotation).

## Cargo.toml swap

```diff
-argon2        = "0.5"
-password-hash = "0.5"
-rand_core     = "0.6"
+hsh = "0.0.9"
```

## Breaking-change checklist

- [ ] `Argon2::new(...).hash_password(...)` → `api::hash(&policy, pw)`.
- [ ] `Argon2::new(...).verify_password(...)` →
  `api::verify_and_upgrade(&policy, pw, stored)`.
- [ ] Salt generation: handled internally by `api::hash`.
- [ ] PHC string parsing: handled internally by
  `api::verify_and_upgrade`.
