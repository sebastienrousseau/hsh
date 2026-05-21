# Migrating from `djangohashers` to `hsh`

[`djangohashers`](https://crates.io/crates/djangohashers) implements
Django's password-hash format so a Rust service can verify hashes
produced by a Python/Django sibling. If you're consolidating onto
Rust-only services and `hsh`, this guide shows the migration path.

## Why migrate

- **Modern KDF defaults:** Django defaults to PBKDF2-HMAC-SHA-256
  with 870 000 iterations as of Django 5; `hsh::Policy::fips_140_pbkdf2()`
  matches the FIPS path or `Policy::owasp_minimum_2025()` gives
  Argon2id.
- **Rotation:** `verify_and_upgrade` migrates Django's
  `pbkdf2_sha256$870000$…` to whichever current policy you set,
  transparently.
- **One stack:** drop the Django format-specific dep.

## Django hash anatomy

Django stores passwords as:

```
<algorithm>$<iterations>$<salt>$<hash_b64>
```

- `algorithm` ∈ `{pbkdf2_sha256, pbkdf2_sha1, argon2, bcrypt_sha256, scrypt}`
- The format isn't quite PHC — note the **underscore** in
  `pbkdf2_sha256` instead of the PHC hyphenated `pbkdf2-sha256`.

## Before

```rust
use djangohashers::{make_password, check_password};

let stored = make_password("password123");
// stored = "pbkdf2_sha256$870000$<salt>$<hash>"

let ok = check_password("password123", &stored)?;
```

## After (one-shot migration)

Translate Django's format into PHC at read time and run everything
through `hsh::api::verify_and_upgrade`:

```rust
use hsh::{api, Policy, Outcome};

fn django_to_phc(django: &str) -> String {
    // pbkdf2_sha256 → pbkdf2-sha256
    // pbkdf2_sha512 → pbkdf2-sha512
    django.replacen("pbkdf2_sha", "pbkdf2-sha", 1)
}

let policy = Policy::owasp_minimum_2025();
let legacy = read_from_django_users_table();
let phc = django_to_phc(&legacy);

let outcome = api::verify_and_upgrade(&policy, &candidate, &phc)?;

if let Outcome::Valid { rehashed: Some(new_phc) } = outcome {
    // new_phc is $argon2id$... — write it back.
    update_user_password_hash(user_id, &new_phc);
}
```

## Compatibility window

For the migration period where Django still owns *writes* and Rust
owns *reads*, just keep the format translator in place. Once the
Rust service has rotated all rows to Argon2id via `verify_and_upgrade`,
delete the translator.

## Cargo.toml swap

```diff
-djangohashers = "1.8"
+hsh = "0.0.9"
```

## Breaking-change checklist

- [ ] `make_password` → `api::hash`.
- [ ] `check_password` → `api::verify_and_upgrade` after format
  translation.
- [ ] `is_password_usable` → check the prefix yourself; `hsh`
  doesn't model Django's "unusable password" sentinel.
- [ ] If you used `Algorithm::Argon2`, switch to
  `Policy.primary = PrimaryAlgorithm::Argon2id`.
