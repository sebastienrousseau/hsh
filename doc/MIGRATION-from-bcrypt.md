# Migrating from `bcrypt` to `hsh`

The [`bcrypt`](https://crates.io/crates/bcrypt) crate is the most
common bcrypt implementation in the Rust ecosystem. `hsh` uses it
internally; this guide shows how to switch *callers* over to `hsh`
to get multi-algorithm verify, rotation-on-verify, and the
**72-byte safety rail** that prevents CVE-2025-22228-class bugs.

## Why migrate

- **CVE-2025-22228 mitigation:** `hsh` rejects passwords longer than
  72 bytes by default (`Error::InvalidPassword`) and offers an
  explicit `Bcrypt::with_prehash(Sha256)` opt-in. Bare `bcrypt`
  truncates silently.
- **Algorithm migration:** `verify_and_upgrade` accepts existing
  bcrypt `$2b$…` MCF strings and signals `needs_rehash` when your
  policy moves to Argon2id.
- **One uniform API** across Argon2id / bcrypt / scrypt / PBKDF2 —
  no need to switch crates if compliance pushes you off bcrypt.

## Before

```rust
use bcrypt::{hash, verify, DEFAULT_COST};

let stored = hash("password123", DEFAULT_COST)?;
let ok = verify("password123", &stored)?;
```

## After (still on bcrypt)

```rust
use hsh::{api, Policy, PrimaryAlgorithm};

let mut policy = Policy::owasp_minimum_2025();
policy.primary = PrimaryAlgorithm::Bcrypt;
// policy.bcrypt.cost = 12;  // override default if you want

let stored = api::hash(&policy, "password123")?;
let outcome = api::verify_and_upgrade(&policy, "password123", &stored)?;
```

## After (migrating to Argon2id)

```rust
use hsh::{api, Outcome, Policy};

let policy = Policy::owasp_minimum_2025();  // Argon2id primary
let legacy_bcrypt_hash = read_from_db_column();

let outcome =
    api::verify_and_upgrade(&policy, &candidate, &legacy_bcrypt_hash)?;

if let Outcome::Valid { rehashed: Some(new_phc) } = outcome {
    // The cross-algorithm drift trigger fired; the new PHC is
    // $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
    update_user_password_hash(user_id, &new_phc);
}
```

This is the recommended migration path: keep accepting existing
bcrypt hashes, but mint Argon2id for everything new and rotate
on-verify.

## Handling 72-byte passwords

If your application sometimes receives passwords longer than 72 bytes
(very long passphrases, password managers that pass derived secrets,
or upgraded-from-SHA-1-hex flows like the Okta delegated-auth
incident):

```rust
use hsh::algorithms::bcrypt::{BcryptParams, PrehashAlgorithm};
use hsh::{api, Policy, PrimaryAlgorithm};

let mut policy = Policy::owasp_minimum_2025();
policy.primary = PrimaryAlgorithm::Bcrypt;
policy.bcrypt = BcryptParams::new(12)
    .with_prehash(PrehashAlgorithm::Sha256);

// Now long passwords are HMAC-SHA-256'd to 32 bytes before bcrypt.
let stored = api::hash(&policy, "0123456789..............ABCDEFGHIJKL")?;
```

## Cargo.toml swap

```diff
-bcrypt = "0.16"
+hsh = "0.0.9"
```

## Breaking-change checklist

- [ ] `bcrypt::hash` → `api::hash(&policy, &pw)` with
  `PrimaryAlgorithm::Bcrypt` in the policy.
- [ ] `bcrypt::verify` → `api::verify_and_upgrade(...)`.
- [ ] `DEFAULT_COST` → `BcryptParams::new(10)` (OWASP-2025 minimum).
- [ ] Add explicit prehash if any input might exceed 72 bytes.
