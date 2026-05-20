<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Pepper key rotation runbook

A step-by-step playbook for rotating the server-side HMAC pepper
key without locking users out. Applies whether the pepper backend
is `LocalPepper` or one of the KMS providers — the mechanism is the
same.

## When to rotate

| Trigger | Severity | Timeline |
|---|---|---|
| Suspected key compromise (breach, insider risk, key residue in logs) | Critical | Immediately; treat as a security incident |
| Periodic rotation per compliance policy (e.g. annual) | Routine | Plan a 4-6 week window |
| KMS / HSM migration (e.g. AWS KMS → HashiCorp Vault) | Routine | Plan a 4-6 week window |
| `KeyVersion` schema change in `hsh-kms` itself | Routine | Hard to imagine; would coincide with a major version bump |

## The four-phase pattern

Rotation has four phases. The point of all four is to keep stored
hashes verifiable throughout — never remove a key while there are
still hashes under that version.

```text
Phase 1: Add v2 to keyset, current=v1
        ↓
Phase 2: Mark v2 current
        ↓ (verify traffic transparently rehashes old → new)
Phase 3: Audit DB; confirm 0 rows still on v1
        ↓
Phase 4: Remove v1 from keyset
```

## Phase 1 — Add the new version (current=v1)

Deploy a build of your application carrying both key versions but
still treating v1 as current:

```rust
use hsh_kms::{KeyVersion, LocalPepper};

let pepper = LocalPepper::builder()
    .add(KeyVersion::new(1), v1_bytes_from_kms()?.to_vec())
    .add(KeyVersion::new(2), v2_bytes_from_kms()?.to_vec())
    .current(KeyVersion::new(1))    // ← still v1
    .build()?;
```

Why this exists: it's a no-op release that verifies your deployment
pipeline can ship both keys. If `v2_bytes_from_kms` fails (KMS
permissions, key alias misconfig), you catch it here, before users
start minting under v2.

Verify in production: no `hsh-pepper:2:` strings should appear in
the database yet.

## Phase 2 — Mark v2 current

```rust
let pepper = LocalPepper::builder()
    .add(KeyVersion::new(1), v1_bytes_from_kms()?.to_vec())
    .add(KeyVersion::new(2), v2_bytes_from_kms()?.to_vec())
    .current(KeyVersion::new(2))    // ← rotation happens here
    .build()?;
```

From this deploy forward:

- New hashes mint under `hsh-pepper:2:`.
- Existing `hsh-pepper:1:` hashes still verify (v1 is still in the
  keyset).
- On every successful login under v1, `api::verify_and_upgrade`
  returns `Outcome::Valid { rehashed: Some(new_phc) }` where
  `new_phc` starts with `hsh-pepper:2:`. Persist it.

## Phase 3 — Audit

Wait until the long tail of active users has logged in. The exact
duration depends on your active-user distribution:

- A B2C product with daily-active users: 4-6 weeks covers the
  monthly-active band.
- A B2B product with weekly-active accounts: 8-12 weeks covers
  most rare accessors.
- Dormant accounts (no login in 90+ days): force a password reset
  rather than wait — they'll never verify.

Query your password column for `LIKE 'hsh-pepper:1:%'` periodically;
the count drops asymptotically toward zero.

Inspect any survivors with `hsh inspect`:

```sh
$ hsh inspect 'hsh-pepper:1:$argon2id$…'
format: hsh-pepper
keyver: 1
inner: $argon2id$…
```

## Phase 4 — Retire v1

Once Phase 3 shows zero stored hashes under v1 *and* you've
confirmed a force-reset path for any holdouts:

```rust
let pepper = LocalPepper::builder()
    .add(KeyVersion::new(2), v2_bytes_from_kms()?.to_vec())
    // v1 removed; only v2 remains
    .current(KeyVersion::new(2))
    .build()?;
```

After this deploy, any hash still on v1 fails verification with
`Outcome::Invalid` (the verifier can't compute the HMAC tag). This
is why Phase 3's audit step is non-negotiable.

Destroy the v1 key material in the KMS — schedule a `ScheduleKey
Deletion` (AWS), disable + delete the key version (GCP), or remove
the secret (Vault). Hold the deletion request for the KMS's grace
period (typically 7-30 days) so you can recover from an
accidentally-overzealous Phase 3 audit.

## Emergency rotation (suspected compromise)

If you have to assume the pepper is in the attacker's hands:

1. **Mint v2 in the KMS** under a new alias.
2. **Deploy Phase 2 immediately** — don't wait for a Phase 1 dry-run.
3. **Force password reset for all users** — there's no way to know
   which hashes the attacker has had time to crack offline.
4. **Skip Phase 3's audit window** — go straight to Phase 4 once
   the password column is empty (every row reset).
5. **Disclose** per [`SECURITY.md`](../../../SECURITY.md)'s policy.

Emergency rotation is destructive — accept that users will need to
re-authenticate. This is the worst-case scenario the pepper exists
to defend against; using it correctly is the right call even if it
inconveniences users.

## Common mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Skipping Phase 1 (the dry-run) | KMS-permissions or wrong-alias issues surface at peak traffic | Always do the no-op deploy first |
| Removing v1 before Phase 3 audit completes | Users with old hashes get `Outcome::Invalid` (look like wrong-password attempts) | Keep v1 in the keyset until 0 rows remain |
| Not setting `current` to the new version | New hashes still mint under v1 | The builder rejects this — `current` must be in the keyset |
| Reusing a `KeyVersion` value after retiring it | Future rotations get confused; old hashes recover unexpectedly | `KeyVersion` is monotonic by convention — never reuse |
| Deploying Phase 2 to a fraction of instances | Hashes minted under v2 fail to verify on instances still on v1 | All instances must be on Phase 2 before mint traffic flows |

## Provider-specific notes

### AWS KMS

- Use a *key alias* (not the underlying key ID). Aliases let you
  point at a new key without redeploying.
- The `aws-kms` `hsh-kms` feature is a stub today; v0.0.10+ wires up
  the actual `aws-sdk-kms` calls. Until then, use `LocalPepper`
  seeded from the KMS at process start.

### GCP Cloud KMS

- Cloud KMS supports automatic key rotation at a configurable
  cadence. Set `cryptoKeys.rotationPeriod` and let GCP mint new
  versions; you map each GCP version to a `KeyVersion(N)` in
  `LocalPepper`'s seed.

### Azure Key Vault

- Use a *managed HSM* if you need FIPS 140-3 Level 3 for the pepper
  itself. The default Key Vault (Standard / Premium) is Level 1/2.

### HashiCorp Vault Transit

- Vault Transit has first-class versioned keys (`min_decryption_version`,
  `min_encryption_version`). The `hashicorp-vault` `hsh-kms` feature
  maps cleanly onto these.
