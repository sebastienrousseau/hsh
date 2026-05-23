<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# hsh::Error reference

Every error variant the library can emit, what triggers it, and
how to recover. The `Error` enum is `#[non_exhaustive]` — downstream
`match` should always have a `_` arm — so this list captures the
surface as of v0.0.9; future variants may be added in a minor
release.

The `Display` output and the variant *names* are part of the public
API and follow semver. Internal `detail` strings are stability tier 2
(may rephrase between minor versions); downstream `match` should
discriminate on the variant, not parse the message.

## Variant reference

| Variant | Display prefix | When emitted | Recovery |
|---|---|---|---|
| `UnsupportedAlgorithm(Cow<'static, str>)` | `unsupported hash algorithm: …` | PHC string algorithm tag isn't one of `argon2id`, `argon2i`, `argon2d`, `bcrypt`, `scrypt`, `pbkdf2-sha256`, `pbkdf2-sha512` | Inspect the stored hash; if it's a hash from another ecosystem, write a custom migration path |
| `InvalidHashString(Cow<'static, str>)` | `invalid hash string: …` | PHC / MCF parser couldn't decode the input — malformed structure, missing fields, bad base64 | Check the stored value at the database layer; typically indicates corruption |
| `InvalidParameter(Cow<'static, str>)` | `invalid parameter: …` | Cost / memory / iteration parameter is outside the algorithm's valid range, or a `Backend::Fips140Required` policy was used with a non-PBKDF2 primary | If FIPS-related: switch `policy.primary` to `PrimaryAlgorithm::Pbkdf2` or relax `policy.backend` to `Backend::Native`. Otherwise inspect the parameter set against the algorithm's RFC |
| `InvalidPassword(Cow<'static, str>)` | `password rejected: …` | Password is invalid by precondition — most commonly: bcrypt input > 72 bytes without `with_prehash`; or bcrypt verify with non-UTF-8 bytes | For bcrypt with long inputs: call `BcryptParams::with_prehash(PrehashAlgorithm::Sha256)`. For non-UTF-8 input bytes with bcrypt: convert to UTF-8 upstream or use a pre-hash |
| `InvalidSalt(Cow<'static, str>)` | `invalid salt: …` | Salt could not be decoded or had the wrong shape | Check the stored hash; typically corruption |
| `Hashing(HashingError)` | `hashing failed: <kind>: <detail>` | Underlying primitive (Argon2 / bcrypt / scrypt / PBKDF2) reported a failure — usually means an internal invariant was violated by crafted input | Inspect `HashingError::kind` for which primitive failed; the variant is `Clone` so you can fan it out |
| `Verification(Cow<'static, str>)` | `verification failed: …` | Stored hash was corrupt enough to fail verification setup (not "wrong password" — that returns `Outcome::Invalid`). For example, bcrypt's `verify` couldn't even parse the MCF | Inspect the stored material at the database layer |
| `InvalidPolicy(Cow<'static, str>)` | `invalid policy: …` | `PolicyBuilder::build()` was called without all required fields (typically `primary`) | Add the missing setter call before `.build()` |
| `Decode(DecodeError)` | (transparent — passes through to inner) | Inner UTF-8, base64, or JSON decode failed during PHC parsing | Match on the inner `DecodeError` variant |
| `Pepper(Cow<'static, str>)` *(feature `pepper`)* | `pepper provider: …` | KMS / HSM backend failed — unknown key version, transport error, etc. | Inspect the message; typically retriable if it's a transient network error |

## `HashingError` discriminant

When you get `Error::Hashing(e)`, downcast via `e.kind`:

```rust
use hsh::error::{Error, HashingErrorKind};

match err {
    Error::Hashing(hashing_err) => match hashing_err.kind {
        HashingErrorKind::Argon2 => { /* argon2 primitive failed */ }
        HashingErrorKind::Bcrypt => { /* bcrypt primitive failed */ }
        HashingErrorKind::Scrypt => { /* scrypt primitive failed */ }
        HashingErrorKind::Pbkdf2 => { /* pbkdf2 primitive failed */ }
        HashingErrorKind::PhcEncoder => { /* password_hash PHC encoder failed */ }
        _ => { /* future variants */ }
    }
    _ => { /* future variants */ }
}
```

`HashingError` itself is `#[non_exhaustive]`. The `kind` and `detail`
fields are stable; new fields may be added without a major bump.

## `DecodeError` sub-enum

When `Error::Decode(e)` is returned:

| Variant | When emitted |
|---|---|
| `DecodeError::Utf8(Cow<'static, str>)` | Salt / password bytes weren't valid UTF-8 in a context that required it |
| `DecodeError::Base64(Cow<'static, str>)` | PHC hash or salt field had invalid base64 padding / characters |
| `DecodeError::Json(Cow<'static, str>)` | Legacy `Hash::parse` serde-JSON input was malformed |

## Stability + threading

- `Error`, `DecodeError`, `HashingError`, and `HashingErrorKind` all
  implement `Send + Sync + Clone + 'static`.
- `Clone` means you can fan an error out to multiple sinks (tower
  middleware, retry budgets, fallible streams) without `Arc`-wrapping.
- `Send + Sync` means the error can cross `tokio::spawn` /
  `std::thread::spawn` / `async fn` boundaries without issue.

## Source chains

`std::error::Error::source()` returns `Some(_)` for:

- `Error::Decode(_)` — points at the inner `DecodeError`.
- `Error::Hashing(_)` — does NOT chain to an underlying typed source
  because the upstream RustCrypto error types aren't `Clone` and we
  preserve `Clone`-ability on `Error`. The original message is in
  `HashingError::detail`.

For all other variants, `source()` returns `None`.

## What `Error` does *not* represent

- **Wrong password.** That's `Outcome::Invalid`, returned by
  `api::verify_and_upgrade` as the `Ok` value. Authentication
  failures are not errors at the type level — they're a successful
  verification outcome.
- **Policy drift.** That's `Outcome::Valid { rehashed: Some(_) }`,
  also an `Ok` value. The presence of a new PHC string in `rehashed`
  is the signal to persist a fresh hash.

This separation matters because callers should `?`-propagate `Error`
(it indicates a real fault — corrupt storage, FIPS misconfiguration,
KMS outage) but `match` on `Outcome` (it represents normal control
flow).
