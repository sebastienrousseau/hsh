# ADR-0003 — Pepper key-versioning scheme

- **Status:** Accepted
- **Date:** 2026-05-19
- **Deciders:** Sebastien Rousseau
- **Tracking issue:** [#142](https://github.com/sebastienrousseau/hsh/issues/142)

## Context

`hsh` v0.0.9 adds optional **server-side pepper** support: a secret key
held outside the password database (typically in AWS KMS, GCP Cloud
KMS, Azure Key Vault, or HashiCorp Vault) that is mixed into every
password before it is hashed. This is a defence-in-depth measure
recommended by PCI DSS 4.0 §3.5.1.1 and the OWASP Password Storage
Cheat Sheet.

Peppers create a versioning problem the KDFs don't have: when the
operator rotates the pepper key, *every existing hash in the database
references the old key*. We must either:

1. Refuse to rotate (operationally untenable),
2. Re-hash every row at rotation time (requires every user's
   plaintext, which we don't have),
3. Carry the key version alongside each hash and rotate-on-verify.

Option 3 is the de-facto industry pattern. This ADR documents the
specific encoding we chose for `hsh`.

## Decision

### 1. The trait

`hsh_kms::Pepper::apply(version, password) → [u8; 32]` computes
`HMAC-SHA-256(key_at_version, password)`. The output is a 32-byte tag
that the calling layer can substitute for the password before passing
it to the KDF. Implementations are responsible for resolving
`version → key bytes` and refusing if the version is unknown.

### 2. The storage format

A peppered hash is stored as:

```
hsh-pepper:<keyver>:<inner>
```

where `<keyver>` is the decimal `KeyVersion::get()` and `<inner>` is
the per-algorithm encoding that would have been produced **without** a
pepper — i.e. a PHC string for Argon2/scrypt, or an MCF string for
bcrypt.

We deliberately do **not** smuggle the keyver into the PHC `data`
field, even though Argon2 supports it. Reasons:

- The PHC `data` field is algorithm-specific (bcrypt's MCF has no
  equivalent), so it can't be uniform across our three primaries.
- Existing PHC verifiers (Django, libsodium, Argon2 CLI) would
  silently ignore the field, leading to incorrect verifies elsewhere.
- A bare prefix is greppable / queryable from SQL, which helps
  operators audit which rows still need rotation.

### 3. Rotation semantics

`hsh::api::verify_and_upgrade` triggers `needs_rehash = true` whenever:

- The stored `<keyver>` differs from `policy.pepper.current()`, **or**
- The stored hash is **not** peppered but the policy now carries a
  pepper (legacy → peppered upgrade), **or**
- The underlying PHC parameters fell below `policy` (existing
  algorithm-level rehash logic).

In all three cases the rehashed value is built under
`policy.pepper.current()`, gradually migrating the corpus on each
successful login.

### 4. Refusing peppered hashes when the policy has no pepper

If a stored hash carries the `hsh-pepper:` prefix but the policy
passed to `verify_and_upgrade` has `pepper = None`, the verifier
returns `Outcome::Invalid` — **not** an error and **not** a
fail-open. The rationale: an attacker who learns the pepper-prefix
format must not be able to bypass pepper checks by stripping or
forging the prefix; the only way to verify a peppered hash is to
present the correct pepper key.

### 5. What is *not* in scope

- **Auto-discovery of older versions.** If a stored row claims
  `keyver=N` and `N` is not in the pepper's keyset, we refuse rather
  than silently trying every known version. This is a strict-mode
  default; an explicit "fallback" mode could be added if real
  deployments need it.
- **Online key fetching during verify.** The pepper is fetched
  out-of-band at app startup (`hsh_kms::aws::fetch_pepper` etc.) and
  cached in `LocalPepper`. The verify hot path stays sync and
  CPU-bound; no KMS roundtrip per password attempt.

## Consequences

**Accepted trade-offs:**

- Storage rows grow by `hsh-pepper:<keyver>:` (≈ 14 bytes including a
  one-digit version). For databases that store hashes column-wise,
  this is negligible.
- The format is `hsh`-specific. Migrating *away* from `hsh` requires
  either re-hashing under the new system or teaching the new system
  to understand our prefix.
- We do not currently use Argon2's native `secret` parameter. This is
  a deliberate choice for portability — applying the HMAC up-front
  works the same way across Argon2id / bcrypt / scrypt.

**Benefits:**

- Operators can rotate the pepper key without coordinated downtime.
- Failed rotations are recoverable — the old key is still in the
  keyset until manually purged.
- Stored hashes self-describe their pepper version, so audits and
  partial-migration tooling can target specific keyvers in SQL.
- The pepper trait is small and provider-agnostic, so swapping AWS
  KMS for HashiCorp Vault is a deployment-level decision, not a code
  change.

## Compliance

- `crates/hsh-kms/src/lib.rs::LocalPepper::Drop` zeroizes key bytes
  on drop.
- `hsh-kms` mirrors the workspace `#![forbid(unsafe_code)]` policy.
- The pepper key never enters logs, error messages, or `Debug` output
  (`LocalPepper`'s `Debug` impl shows only version metadata).
- Integration tests in `crates/hsh/tests/test_pepper.rs` cover the
  six material scenarios: round-trip, wrong-password rejection,
  refused-when-no-pepper, rotation-triggers-rehash, legacy-upgrade,
  and unknown-version handling.

## References

- [OWASP Password Storage Cheat Sheet — peppering](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [PCI DSS 4.0 §3.5.1.1](https://www.pcisecuritystandards.org/document_library)
- [RFC 9106 §4 — Argon2 parameter recommendations](https://datatracker.ietf.org/doc/rfc9106/)
- [`doc/KMS-INTEGRATION.md`](../KMS-INTEGRATION.md) for provider-specific deployment guides.
