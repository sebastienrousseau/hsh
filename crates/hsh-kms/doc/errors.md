<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# hsh-kms::PepperError reference

Every error variant `hsh-kms` can emit, what triggers it, and how
to recover.

## Variant reference

| Variant | Display prefix | When emitted | Recovery |
|---|---|---|---|
| `UnknownVersion(KeyVersion)` | `unknown pepper key version: <n>` | `apply()` called with a version that isn't in the provider's keyset | Add the requested version via the builder, or use a different version |
| `KeyTooShort { version, actual, minimum }` | `pepper key for version <n> too short: <actual> < <minimum>` | Builder validation rejected a key shorter than the 16-byte minimum | Use a key with at least 16 bytes of cryptographic-quality entropy |
| `EmptyKeyset` | `pepper keyset is empty` | Builder called `build()` with no `add()` calls | Add at least one key via `add(KeyVersion, key_bytes)` |
| `Backend(String)` | `pepper backend failed: …` | KMS / HSM provider returned an error — transport failure, permission denied, throttling | Inspect the inner message; transient errors are usually retryable |

The enum is `#[non_exhaustive]`; future providers may add new typed
variants.

## When you get `Error::Pepper(_)` in `hsh`

`hsh::Error::Pepper(Cow<'static, str>)` is the wrapper around any
`PepperError` returned during `api::hash` / `api::verify_and_upgrade`.
The inner string is `pepper_err.to_string()` — for structured
downcasting in the `hsh` crate's error chain, call into `hsh-kms`
directly rather than going through the `hsh` API.

## Threading + cloning

`PepperError` derives `Clone + Debug + thiserror::Error` and is
`Send + Sync + 'static`. It composes with tower-middleware-style
error fan-out without `Arc`-wrapping.

## What `PepperError` does *not* represent

- **Wrong password.** `Pepper::apply` is a deterministic HMAC — it
  cannot fail on "wrong" input. Authentication failure is signalled
  by `hsh::api::verify_and_upgrade` returning `Outcome::Invalid`,
  not by a `PepperError`.
- **Network timeouts inside an HMAC call.** Today's providers
  compute HMAC locally via `LocalPepper`; once the real KMS
  providers land in v0.0.10+, transport errors will surface as
  `PepperError::Backend(_)`.
