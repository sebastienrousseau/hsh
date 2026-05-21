# Migrating from `argonautica` to `hsh`

[`argonautica`](https://crates.io/crates/argonautica) was a popular
Rust binding to the C reference Argon2 implementation. Its last
release was in **March 2019** and it has been unmaintained ever since.
This guide shows how to swap it for `hsh` without breaking existing
hashes.

## Why migrate

- **Maintenance:** no security updates since 2019.
- **FFI surface:** depends on `libargon2` via C bindings. `hsh` uses
  the audited pure-Rust RustCrypto `argon2` crate.
- **No PHC compliance:** argonautica emits a custom string format
  that doesn't follow PHC. `hsh` emits standard PHC strings that
  Django, libsodium, the Argon2 CLI, etc., can verify.

## Before

```rust
use argonautica::{Hasher, Verifier};

let mut hasher = Hasher::default();
hasher.opt_out_of_secret_key(true);
let stored = hasher
    .with_password("password123")
    .hash()?;

let mut verifier = Verifier::default();
verifier.opt_out_of_secret_key(true);
let ok = verifier
    .with_hash(&stored)
    .with_password("password123")
    .verify()?;
```

## After

```rust
use hsh::{api, Policy, Outcome};

let policy = Policy::owasp_minimum_2025();
let stored = api::hash(&policy, "password123")?;

let outcome = api::verify_and_upgrade(&policy, "password123", &stored)?;
assert!(matches!(outcome, Outcome::Valid { .. }));
```

## Verifying existing argonautica hashes

argonautica's storage format is `$argon2id$v=19$m=…$<salt>$<hash>` —
a **valid PHC string**. `hsh::api::verify_and_upgrade` parses it
directly:

```rust
use hsh::{api, Policy};

let policy = Policy::owasp_minimum_2025();
let legacy_hash = read_from_db_column();
let outcome =
    api::verify_and_upgrade(&policy, &candidate, &legacy_hash)?;

if let Outcome::Valid { rehashed } = outcome {
    if let Some(new_phc) = rehashed {
        // Persist `new_phc` — the parameters used by argonautica
        // probably drift below your current Policy, so we just
        // rotated to a fresh hash transparently.
        update_user_password_hash(user_id, &new_phc);
    }
}
```

## Pepper migration

If you used argonautica's `secret_key` for peppering:

```rust
// Before
hasher.with_secret_key("server-pepper-bytes")
```

Use `hsh-kms` instead:

```rust
use std::sync::Arc;
use hsh_kms::{KeyVersion, LocalPepper};
use hsh::{Policy, api};

let pepper = LocalPepper::builder()
    .add(KeyVersion::new(1), b"server-pepper-bytes-32+ chars".to_vec())
    .current(KeyVersion::new(1))
    .build()?;

let policy = Policy::owasp_minimum_2025()
    .with_pepper(Arc::new(pepper));

let stored = api::hash(&policy, "password123")?;
// Stored has the form: hsh-pepper:1:$argon2id$…
```

See [`KMS-INTEGRATION.md`](KMS-INTEGRATION.md) for AWS / GCP / Azure /
Vault pepper providers.

## Cargo.toml swap

```diff
-argonautica = "0.2.0"
+hsh = "0.0.9"
```

## Breaking-change checklist

- [ ] `Hasher` / `Verifier` builders → `hsh::api::{hash, verify_and_upgrade}`.
- [ ] `with_secret_key()` → `Policy::with_pepper()` (requires `pepper` feature).
- [ ] `additional_data()` → drop; not needed under PHC strings.
- [ ] Custom parameter tuning → `Policy.argon2` field accepts `argon2::Params` directly.
- [ ] Drop the `cc`/`make` build dependency — `hsh` is pure Rust.
