<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# hsh internals

A contributor-facing map of how the `hsh` core library is laid out.
This is distinct from the workspace-level architectural decisions
captured under [`doc/adr/`](../../../doc/adr/), which cover the
*why* — this file covers the *where*. If you're trying to figure
out which file to open to make a change, start here.

## Module map

```text
crates/hsh/src/
├── lib.rs                 # crate root: re-exports + crate-level //! docs
├── api.rs                 # public high-level API: hash + verify_and_upgrade
├── backend.rs             # Backend enum: Native / Fips140Required + is_fips()
├── error.rs               # Error enum, HashingError, HashingErrorKind, DecodeError
├── outcome.rs             # Outcome enum: Valid { rehashed } / Invalid
├── policy.rs              # Policy struct, PrimaryAlgorithm, PolicyBuilder
├── algorithms/
│   ├── mod.rs             # re-exports
│   ├── argon2id.rs        # Argon2id/i/d wrappers; owasp_minimum_2025() preset
│   ├── bcrypt.rs          # BcryptParams + 72-byte safety rail + prehash adapter
│   ├── pbkdf2.rs          # Pbkdf2Params + Prf::{Sha256, Sha512}
│   └── scrypt.rs          # ScryptParams (log_n, r, p, dk_len)
└── models/
    ├── mod.rs             # re-exports
    ├── hash.rs            # legacy Hash type + HashBuilder (compat-v0_0_x)
    └── hash_algorithm.rs  # HashAlgorithm + HashingAlgorithm trait
```

## Where to make a change

| Change | Where |
|---|---|
| Add a new KDF algorithm | `algorithms/<name>.rs` + `PrimaryAlgorithm::<Name>` variant in `policy.rs` + dispatch in `api::hash_unpeppered` and `api::verify_dispatch_inner` |
| Add a new error variant | `error.rs::Error` (mark `#[non_exhaustive]` is already there) + thread through `?` chains |
| Change a default parameter | `algorithms/<name>.rs::owasp_minimum_2025()` (or equivalent preset) |
| Add a new Policy preset | `policy.rs::Policy::<preset_name>()` constructor |
| Change auto-rehash logic | `api.rs::needs_rehash()` |
| Add a new pepper provider | `crates/hsh-kms/src/<provider>.rs` (feature-gated) |

## The `api::verify_and_upgrade` dispatch flow

This is the central choke-point. It's worth understanding before
making any non-trivial change to verify behaviour.

```text
verify_and_upgrade(policy, password, stored)
  │
  ├─ stored starts with "hsh-pepper:<keyver>:" ?
  │     ├─ no pepper on policy → Outcome::Invalid (fail-closed)
  │     ├─ parse keyver, HMAC the password under that key version
  │     ├─ recurse into the inner PHC with the HMAC tag as "password"
  │     └─ if inner valid: needs_rehash if keyver != current OR inner.needs_rehash
  │
  ├─ policy has pepper but stored is unpeppered ?
  │     └─ verify the raw hash, then rehash under pepper on success
  │
  ├─ stored starts with $2a$ / $2b$ / $2x$ / $2y$ ?  (bcrypt MCF)
  │     ├─ reject non-UTF-8 password bytes
  │     ├─ bcrypt::verify with the configured PrehashAlgorithm
  │     └─ if policy.primary != Bcrypt: rehash under primary
  │
  ├─ password_hash::PasswordHash::new(stored) — PHC parse
  │     └─ dispatch on algorithm id:
  │         argon2id / argon2i / argon2d → Argon2::verify_password
  │         scrypt                       → Scrypt::verify_password
  │         pbkdf2-sha256 / pbkdf2-sha512 → verify_pbkdf2_phc (manual,
  │                                          to keep FIPS routing alive)
  │
  └─ if verify succeeds AND needs_rehash() → fresh PHC under current policy
```

## The `needs_rehash` predicate

Located at `api.rs::needs_rehash`. Four kinds of drift trigger
rehash:

1. **Algorithm drift** — stored algorithm doesn't match
   `policy.primary`.
2. **Parameter drift (Argon2id)** — stored `m_cost`, `t_cost`,
   `p_cost`, or `output_len` is below the policy's. Checked via
   `policy.argon2_satisfies(stored_params)`.
3. **PRF drift (PBKDF2)** — stored uses SHA-256 but policy is
   SHA-512 (or vice versa).
4. **Iteration drift (PBKDF2)** — stored iteration count is below
   the policy's.

Pepper-version drift is handled separately, in the peppered branch
of `verify_dispatch`.

## The peppered hash wire format

```
hsh-pepper:<keyver>:<inner-phc-or-mcf>
            │       │
            │       └─ Whatever the inner KDF produces. Verified
            │          against the HMAC-derived "password", not the
            │          raw user password.
            │
            └─ Decimal `KeyVersion` (u32). Drives both the apply()
               call (which key the HMAC uses) and the rotation
               check (`stored_version != pepper.current()`).
```

The wrapper exists because:
- PHC strings have no native pepper field, and embedding the
  pepper key version inside the salt or hash payload would break
  PHC interop.
- A bespoke wrapper keeps the per-algorithm PHC string untouched
  so it can be peeled off and verified by any PHC-compliant
  consumer once the pepper is applied externally.

## Compile-time assertions

`error.rs` and `outcome.rs` carry compile-time `T: Send + Sync +
Clone + 'static` assertions for `Error`, `DecodeError`,
`HashingError`, `HashingErrorKind`, and `Outcome`. These are
duplicated as runtime test functions in `tests/test_error.rs` /
`tests/test_outcome.rs` so they show up in coverage and run on every
PR.

## Testing strategy

| Test binary | What it covers |
|---|---|
| `test_api.rs` | Happy-path round trips for every primary algorithm |
| `test_api_branches.rs` | Error / unhappy / malformed-PHC paths |
| `test_argon2id.rs` | Argon2id-specific KAT vectors |
| `test_backend_policy.rs` | Backend + Policy + PolicyBuilder surface |
| `test_bcrypt.rs` | Bcrypt 72-byte safety rail + prehash |
| `test_error.rs` | Error enum surface (Display, From, source, Clone) |
| `test_hash.rs` | Legacy `Hash` type round trip (compat-v0_0_x) |
| `test_hash_algorithm.rs` | HashAlgorithm enum + HashingAlgorithm trait |
| `test_hash_branches.rs` | hash.rs setters + builder + verify branches |
| `test_lib.rs` | Crate-level run() entry |
| `test_outcome.rs` | Outcome accessors (is_valid, needs_rehash, rehashed) |
| `test_pbkdf2.rs` | PBKDF2 + FIPS dispatch contract |
| `test_pepper.rs` | Pepper integration + rotation + legacy-upgrade |
| `test_properties.rs` | 7 proptest invariants |
| `test_scrypt.rs` | Scrypt parameter validation |
| `test_algorithms.rs` | Per-algorithm wrapper coverage |

Property tests use `proptest` with `cases = 6` per invariant so the
suite finishes in reasonable wall-time at OWASP-minimum costs.

## When to touch `compat-v0_0_x`

The `compat-v0_0_x` feature exists only for one release cycle. Do
NOT add new code paths gated on it; the file-level rule is "only
mark existing surface `#[deprecated]` and gate it behind the
feature; new public surface lands without the feature gate". The
feature will be removed in v0.2.0 per [`doc/API-STABILITY.md`](../../../doc/API-STABILITY.md).
