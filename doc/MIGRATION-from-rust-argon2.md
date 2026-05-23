# Migrating from `rust-argon2` to `hsh`

The [`rust-argon2`](https://crates.io/crates/rust-argon2) crate
(distinct from RustCrypto's `argon2`) is a popular pure-Rust Argon2
implementation. It's still maintained but provides only Argon2; this
guide shows how `hsh` builds on top of it (via the RustCrypto stack)
and what you gain by switching.

## Why migrate

- **Multi-algorithm:** `hsh` provides Argon2id / bcrypt / scrypt /
  PBKDF2 behind one API, with auto-rehash on algorithm migration.
- **PHC compliance:** drops the version-prefix juggling.
- **Rotatable peppers:** `hsh-kms` pepper providers with KMS
  integrations.
- **Constant-time verify** is guaranteed across all algorithms.

## Before

```rust
use argon2::{self, Config, Variant, Version};

let config = Config {
    variant: Variant::Argon2id,
    version: Version::Version13,
    mem_cost: 19_456,
    time_cost: 2,
    lanes: 1,
    ..Config::default()
};
let salt = generate_salt();
let stored = argon2::hash_encoded(b"password123", &salt, &config)?;

let ok = argon2::verify_encoded(&stored, b"password123")?;
```

## After

```rust
use hsh::{api, Policy};

let policy = Policy::owasp_minimum_2025();
let stored = api::hash(&policy, "password123")?;

let outcome = api::verify_and_upgrade(&policy, "password123", &stored)?;
assert!(outcome.is_valid());
```

## Verifying existing `rust-argon2` hashes

`rust-argon2`'s `hash_encoded` already emits PHC strings, so
`hsh::api::verify_and_upgrade` accepts them as-is. No data
migration required.

## Cargo.toml swap

```diff
-rust-argon2 = "3.0"
+hsh = "0.0.9"
```

## Breaking-change checklist

- [ ] `Config` struct → `Policy.argon2` field (which is
  `argon2::Params` from the RustCrypto crate). The two are
  shape-equivalent.
- [ ] `hash_raw` → `hsh::algorithms::argon2id::Argon2id::hash_password`
  for raw bytes.
- [ ] `verify_raw` → `hsh::api::verify_and_upgrade` is the
  recommended path (constant-time verify + rotation signalling).
- [ ] No equivalent of `lanes`; we use `argon2::Params::p_cost()`
  semantically.
