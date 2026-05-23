<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `hsh` architecture

The mental model required to reason about the `hsh` library — the
flow of data through it, the invariants enforced at each layer, and
the reasoning behind the public API shape. Pairs with
[`internals.md`](./internals.md) (the "where" — module map),
[`cookbook.md`](./cookbook.md) (the "how" — recipes), and the
ADRs under [`doc/adr/`](../../../doc/adr/) (the "why" — decisions).

## The four-layer cake

`hsh` is structured as four layers, top-down:

```text
┌─────────────────────────────────────────────────────────────────┐
│  api::hash / api::verify_and_upgrade                            │
│     ↑ Public, policy-driven, multi-algorithm dispatch           │
└────────────────────────────────────────────┬────────────────────┘
                                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  policy::Policy + policy::PolicyBuilder                         │
│     ↑ Versioned snapshot: which algorithm, which params         │
└────────────────────────────────────────────┬────────────────────┘
                                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  algorithms::{argon2id, bcrypt, scrypt, pbkdf2}                 │
│     ↑ Thin wrappers over RustCrypto primitives with explicit    │
│       safety rails (bcrypt 72-byte, FIPS dispatch, etc.)        │
└────────────────────────────────────────────┬────────────────────┘
                                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  RustCrypto crates (argon2, bcrypt, scrypt, pbkdf2, sha2, hmac) │
│     ↑ Cryptographic primitives — pure Rust, no FFI              │
└─────────────────────────────────────────────────────────────────┘
```

Callers normally interact with the top layer only. The lower layers
are public for advanced use cases (calibrating raw parameters,
implementing a custom `Policy` preset, etc.) but the policy-driven
top layer should be the default mental model.

## Data flow: `api::hash`

```text
api::hash(&policy, password)
  │
  ├── feature("pepper") AND policy.pepper.is_some() ?
  │     ├── version = pepper.current()
  │     ├── tag = HMAC-SHA-256(key[version], password)         (32 bytes)
  │     ├── b64tag = base64(tag)
  │     ├── inner_phc = hash_unpeppered(policy, b64tag.bytes())
  │     └── return "hsh-pepper:<version>:<inner_phc>"
  │
  └── hash_unpeppered(policy, password)
        │
        ├── FIPS contract check:
        │   ├── policy.backend.is_fips() AND policy.primary != Pbkdf2
        │   │   → Err(InvalidParameter("FIPS demands Pbkdf2"))
        │   └── policy.backend.is_fips() AND !fips_available_in_build()
        │       → Err(InvalidParameter("fips feature not built"))
        │
        └── match policy.primary {
             Argon2id  → Argon2::hash_password(...)  → PHC string
             Bcrypt    → Bcrypt::hash_with(...)      → MCF string
             Scrypt    → Scrypt::hash_password(...)  → PHC string
             Pbkdf2    → Pbkdf2::hash_with(...)      → custom PHC
                                                       (kept under our
                                                        control for
                                                        FIPS routing)
           }
```

## Data flow: `api::verify_and_upgrade`

The verify path is intentionally larger than the hash path — it
handles four kinds of input (peppered prefix, raw bcrypt MCF, PHC
strings, legacy unpeppered-with-peppered-policy) and four kinds of
drift (algorithm, parameter, PRF, pepper-version). The full diagram
lives in [`internals.md`](./internals.md#the-apiverify_and_upgrade-dispatch-flow);
the conceptual summary:

1. **Decode the wire format.** Detect `hsh-pepper:` prefix → bcrypt
   MCF → PHC string. Reject anything else with `InvalidHashString`.

2. **Verify the candidate.** Each branch calls into the appropriate
   RustCrypto verifier with constant-time comparison via `subtle`.
   Wrong-password returns `Outcome::Invalid` — never `Err(_)`.

3. **Detect drift.** If verify succeeded, ask `needs_rehash(...)`
   whether the stored hash falls below current policy:
   - Algorithm drift (stored isn't `policy.primary`).
   - Parameter drift (m_cost / t_cost / p_cost / iterations below
     policy minimum).
   - PRF drift (PBKDF2 stored under SHA-256 but policy demands
     SHA-512, or vice versa).
   - Pepper-version drift (stored under v1, policy current = v2).

4. **Mint the new PHC if drift detected.** Returned as
   `Outcome::Valid { rehashed: Some(new_phc) }`. The invariant
   `needs_rehash ⇔ rehashed.is_some()` is enforced by the type
   system — the enum's variant shape makes invalid states
   unrepresentable.

## The peppered hash wire format

```text
hsh-pepper:<keyver>:<inner-phc-or-mcf>
            │       │
            │       └─ Whatever the inner KDF produced. Verified
            │          against the *HMAC tag* as the candidate
            │          "password", not the raw user input.
            │
            └─ Decimal KeyVersion (u32). Drives both:
               1. The `pepper.apply(version, password)` call at
                  verify time (so we use the right HMAC key).
               2. The rotation check: if `version != pepper.current()`,
                  trigger rehash so the next stored value uses the
                  current key.
```

The wrapper exists because:

- PHC strings have no native pepper field. Embedding a key version
  in the params section would break interop with non-`hsh` PHC
  consumers.
- A bespoke outer wrapper keeps the inner PHC verifiable by any
  RustCrypto-compatible consumer once the HMAC is applied externally.
- The split lets `hsh-kms` own *how to HMAC* and `hsh` own *how to
  encode* — clean separation of concerns.

See [ADR-0003 — Pepper key versioning](../../../doc/adr/0003-pepper-key-versioning.md)
for the original design discussion.

## The `Backend` contract

`Backend::Fips140Required` is a *requirement the caller declares*,
not a runtime capability the library auto-detects. Two checks
enforce it:

1. **Algorithm gate** — `api::hash` refuses to mint a hash if
   `policy.backend.is_fips()` and the primary isn't PBKDF2.
   Argon2 / bcrypt / scrypt have no FIPS-validated implementation
   anywhere; minting under those algorithms under a FIPS policy
   would be fail-open.

2. **Build gate** — `api::hash` refuses if
   `policy.backend.is_fips()` and `Backend::fips_available_in_build()`
   returns false. Today the function returns `false` unconditionally
   — the `fips` Cargo feature is a forward-compat marker, not a
   delivered route. When the planned `hsh-backend-awslc` crate lands
   in v0.0.10, it flips the constant to `true` and routes PBKDF2
   through the FIPS-validated `aws-lc-rs` module without changing
   the public API.

See [`doc/FIPS.md`](../../../doc/FIPS.md) for the full FIPS
deployment guide and [ADR-0004 — FIPS strategy](../../../doc/adr/0004-fips-strategy.md)
for the design rationale.

## Why `Outcome` folds the rehash payload into `Valid`

The pre-0.0.9 API returned `(Outcome, Option<String>)` — a tuple
of "what happened" and "if rehash, here's the new PHC". This made
the invariant *"the second element is Some iff `needs_rehash` is
true"* a documentation-only constraint that callers could trivially
violate.

The v0.0.9 shape:

```rust
pub enum Outcome {
    Valid { rehashed: Option<String> },
    Invalid,
}
```

…folds the payload into the `Valid` variant. The invariant
"rehashed-Some iff a fresh PHC exists" is now structurally
enforceable by the type system. The accessor `needs_rehash()` is
exactly `matches!(self, Valid { rehashed: Some(_) })`.

Migration from the pre-0.0.9 shape is mechanical:

```diff
-let (outcome, rehashed) = api::verify_and_upgrade(...)?;
-match outcome {
-    Outcome::Valid { needs_rehash: true } => persist(rehashed.unwrap()),
-    Outcome::Valid { needs_rehash: false } => { /* OK */ }
-    Outcome::Invalid => deny(),
-}
+let outcome = api::verify_and_upgrade(...)?;
+match outcome {
+    Outcome::Valid { rehashed: Some(new_phc) } => persist(new_phc),
+    Outcome::Valid { rehashed: None } => { /* OK */ }
+    Outcome::Invalid => deny(),
+}
```

## Why `password: impl AsRef<[u8]>`

The pre-0.0.9 API required `password: &str`. This excluded valid
use cases:

- **Legacy databases** with Latin-1 / Windows-1252 password
  encodings. Forcing UTF-8 would silently lossily convert.
- **Pre-hashed inputs** (e.g. HMAC tags fed directly to the KDF
  in a peppered deployment) — these are arbitrary 32-byte blobs.
- **`Vec<u8>` callers** had to ferry passwords through `str::from_utf8`
  with custom error handling.

The v0.0.9 shape accepts anything that yields `&[u8]` — `&str`,
`String`, `Vec<u8>`, `&[u8; N]`, `Cow<[u8]>`. The bcrypt code path
internally converts to `&str` (bcrypt's MCF format requires it) and
returns `Error::InvalidPassword` with a clear message if the bytes
aren't UTF-8.

## Compile-time safety guarantees

The crate enforces these at compile time:

- **`#![forbid(unsafe_code)]`** at the crate root. Any new `unsafe`
  block fails compilation, not just CI. See [ADR-0006](../../../doc/adr/0006-zero-unsafe-policy.md).
- **`missing_docs = "deny"`** workspace-wide. Every `pub` item has
  `///` rustdoc.
- **Send + Sync + Clone + 'static** on `Error`, `DecodeError`,
  `HashingError`, `HashingErrorKind`. Asserted in
  `tests/test_error.rs::error_is_send_and_sync`.
- **Send + Sync** on `Outcome`. Asserted in
  `tests/test_outcome.rs::outcome_is_send_and_sync`.
- **`clippy::all = warn` + targeted `allow`s.** Pedantic / nursery
  groups are intentionally off — they generate false positives on
  crypto-style code (constant-time comparison patterns,
  zeroize-on-drop, etc.).

## What this library deliberately does NOT do

- **No I/O.** The library never touches files / sockets / clocks.
  Callers control all input. (`hsh-cli` does I/O — that's the
  binary's job.)
- **No async.** Password hashing is CPU-bound and inherently
  serialized; `async` adds no value. Callers wrap the synchronous
  `api::hash` call in `tokio::task::spawn_blocking` themselves if
  they need to offload from a runtime thread.
- **No logging.** The library returns structured errors; the caller
  decides what to log. Logging password material (or hashes) is a
  caller-side decision with security implications — `hsh` never
  makes it for them.
- **No metrics.** Same rationale as logging. Time the calls in your
  application layer.
- **No general-purpose digest** (SHA-256 for content addressing,
  BLAKE3 for Merkle trees). For that, use the companion
  [`hsh-digest`](../../hsh-digest/) crate.
