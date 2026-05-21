<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `hsh` in the passkey era

This document explains where `hsh` fits in a 2026 authentication
stack that has, or is about to have, passkeys as its primary
factor. The summary: **passkeys do not eliminate password hashing
— they shrink it from "every user" to "fallback and recovery"**,
and that smaller surface is where most credential-breach risk now
concentrates because it is the only path an attacker can replay
remotely.

## The 2026 baseline

- **NIST SP 800-63-4** finalised July 2025. It explicitly
  integrates *syncable authenticators* (i.e. passkeys) into the
  identity-assurance ladder, and continues to require salted +
  iterated memory-hard hashing for any retained password. See
  [pages.nist.gov/800-63-4][nist-63-4] and the B-document
  [SP 800-63B][nist-63b].
- **OWASP Password Storage Cheat Sheet** still recommends Argon2id
  baseline with the OWASP-2025 minimum parameters, and a fallback
  ladder of scrypt / bcrypt / PBKDF2-HMAC-SHA-256
  ([cheatsheetseries.owasp.org][owasp]).
- **FIDO Passkey Index, October 2025** reports passkey eligibility
  reaching the majority of consumer accounts at the largest IdPs,
  and a measurable UX lift over passwords ([FIDO 2025 PDF][fido]).
- **Microsoft, May 2026** declared phishing-resistant factors the
  default for new Microsoft accounts and described the staged
  retirement of password-first sign-in
  ([microsoft.com/security/blog][msft]).

[nist-63-4]: https://pages.nist.gov/800-63-4/
[nist-63b]: https://pages.nist.gov/800-63-4/sp800-63b.html
[owasp]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[fido]: https://fidoalliance.org/wp-content/uploads/2025/10/FIDO-Passkey-Index-October-2025.pdf
[msft]: https://www.microsoft.com/en-us/security/blog/2026/05/07/world-passkey-day-advancing-passwordless-authentication/

Net effect for an application owner: the *volume* of password
hashing drops, but the *consequence* of mis-hashing rises because
the remaining password rows are disproportionately associated with
recovery, support-channel, and rarely-used accounts — exactly the
rows an attacker targets when phishing the passkey-protected path
no longer works.

## Where `hsh` fits in the stack

```text
┌──────────────────────────────────────────────────────────────────────┐
│  Sign-in                                                             │
│  ┌────────────────────────┐   ┌──────────────────────────────────┐   │
│  │ Passkey (WebAuthn /    │   │  Password fallback path          │   │
│  │ FIDO2) — primary       │   │  ────────────────────────        │   │
│  │ phishing-resistant,    │ → │  - user has no passkey on this   │   │
│  │ device-bound           │   │    device                        │   │
│  │                        │   │  - user is signing in from a     │   │
│  │  webauthn-rs, etc.     │   │    browser that won't support    │   │
│  │                        │   │    syncing                       │   │
│  │                        │   │  - account recovery channel      │   │
│  └────────────────────────┘   │                                  │   │
│                               │  hsh::api::verify_and_upgrade    │   │
│                               │  + Argon2id (or PBKDF2 for FIPS) │   │
│                               │  + optional KMS-backed pepper    │   │
│                               └──────────────────────────────────┘   │
├──────────────────────────────────────────────────────────────────────┤
│  Recovery                                                            │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Recovery credential (one-time code, recovery passphrase,     │    │
│  │ delegated identity verification)                             │    │
│  │ ─────────────────────────────────────────────────────────── │    │
│  │ Hashed with hsh — same Policy, but typically with a higher   │    │
│  │ work factor *and* a peppered hsh-pepper:<keyver>: wrapper    │    │
│  │ so an attacker with read-only DB access cannot brute-force   │    │
│  │ the recovery code offline without also breaching the KMS.   │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

`hsh` is the engine for both the orange and the green boxes — the
two places a remote attacker can still try to *replay* a credential.

## Recipe 1: passkey primary + password fallback

Goal: most users sign in with a passkey; users without a passkey on
the device sign in with a password and are nudged to enrol a
passkey.

```rust,ignore
use hsh::{api, Outcome, Policy};

enum SignInAttempt {
    Passkey { /* webauthn assertion */ },
    Password { username: String, password: String },
}

fn sign_in(attempt: SignInAttempt, store: &impl UserStore) -> SignInResult {
    match attempt {
        SignInAttempt::Passkey { /* … */ } => {
            // Delegate to webauthn-rs (or your library of choice).
            // On success, return a session with `factor = "passkey"`.
            verify_passkey_assertion(/* … */)
        }
        SignInAttempt::Password { username, password } => {
            let user = store.lookup(&username)?;
            let policy = Policy::owasp_minimum_2025()
                .with_pepper(store.pepper());          // optional but recommended

            match api::verify_and_upgrade(&policy, &password, &user.stored)? {
                Outcome::Invalid => SignInResult::Denied,
                Outcome::Valid { rehashed } => {
                    if let Some(new_phc) = rehashed {
                        // Policy drift (cost regression, pepper rotation, or
                        // missing prehash) — persist the upgrade transparently.
                        store.update_password_hash(user.id, &new_phc)?;
                    }
                    SignInResult::Allowed {
                        session: user.session(),
                        // Drive UX nudge here. The auth result carries no
                        // marketing logic; surfacing "enrol a passkey" is the
                        // application layer's call.
                        enrol_passkey_nudge: true,
                    }
                }
            }
        }
    }
}
```

The key property is the auto-rehash arm. Because the policy ladder
in v0.0.9 detects drift on *every* parameter dimension (algorithm,
Argon2 m/t/p, bcrypt cost + prehash mode, scrypt log_n/r/p/dk_len,
PBKDF2 iter/dk_len/PRF, pepper key version), each successful
password sign-in either confirms the stored hash is current or
quietly migrates it to current — with no forced password reset, no
background batch job, and no dead-in-DB weak hashes that survive
the next breach.

In a passkey-primary world this matters more, not less. The
password fallback rows are increasingly the long-tail accounts an
ops team has *not* touched in years — exactly the rows where you
need the migration to happen on next login without operator
intervention.

## Recipe 2: recovery credential hardening

Goal: a user who has lost all passkeys (lost devices, KeyChain
reset, etc.) needs a recovery path that an attacker with DB
read-only access cannot replay offline.

```rust,ignore
use hsh::{api, Outcome, Policy, PolicyBuilder, PrimaryAlgorithm};
use hsh::algorithms::pbkdf2::{Pbkdf2Params, Prf};
use argon2::Params as Argon2Params;

/// Recovery-credential policy: tighter than the sign-in policy.
/// Hits a deliberately slow target (≈ 1 s wall-time per verify) so
/// offline GPU attacks are uneconomic, and *always* layers a
/// KMS-backed pepper so a DB-only compromise can't brute-force.
fn recovery_policy(pepper: std::sync::Arc<dyn hsh_kms::Pepper>) -> Policy {
    PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
        .primary(PrimaryAlgorithm::Argon2id)
        .argon2(Argon2Params::new(65_536, 3, 1, Some(32)).unwrap())
        .build()
        .expect("recovery policy")
        .with_pepper(pepper)
}

fn issue_recovery_code(user: &User, pepper: std::sync::Arc<dyn hsh_kms::Pepper>)
    -> anyhow::Result<RecoveryGrant>
{
    // Generate a 128-bit random recovery code, base32-encoded so the
    // user can transcribe it. Never stored in plaintext.
    let code = generate_recovery_code_base32();
    let policy = recovery_policy(pepper);
    let stored = api::hash(&policy, &code)?;       // hsh-pepper:N:$argon2id$…
    store.persist_recovery(user.id, &stored)?;

    // Hand the plaintext code to the user *once*, never log it,
    // never write it to durable storage.
    Ok(RecoveryGrant { code })
}

fn consume_recovery_code(
    user_id: UserId,
    candidate: &str,
    pepper: std::sync::Arc<dyn hsh_kms::Pepper>,
) -> anyhow::Result<bool> {
    let stored = store.fetch_recovery(user_id)?;
    let policy = recovery_policy(pepper);
    let ok = matches!(
        api::verify_and_upgrade(&policy, candidate, &stored)?,
        Outcome::Valid { .. }
    );
    if ok {
        store.invalidate_recovery(user_id)?;       // single-use.
    }
    Ok(ok)
}
```

Three guarantees this gives the recovery flow:

1. **Offline-attack-resistant.** The Argon2id parameters are well
   above OWASP-2025 minimum (`m=64 MiB, t=3, p=1`) and the pepper
   means the attacker needs both the DB *and* the KMS key to
   brute-force; either alone is useless.
2. **Single-use.** `invalidate_recovery` after a successful match
   removes the row; replay is prevented at the storage layer.
3. **Rotatable.** Because the stored format is
   `hsh-pepper:<keyver>:$argon2id$…`, rotating the pepper key
   (see [`KMS-INTEGRATION.md`](KMS-INTEGRATION.md)) re-hardens
   *every* recovery credential on the next consume — no batch job
   required.

## Recipe 3: staged migration off passwords

Goal: an application currently uses passwords for everything; the
team wants to land passkeys as the new primary factor and
progressively retire password sign-in for active accounts.

```text
Phase A — passkeys optional (today)
  ──────────────────────────────────
  - Every account has a password hash via hsh.
  - Some accounts also have one or more passkeys.
  - Sign-in tries passkey first if the browser offers it; falls
    back to password.
  - Recovery: password reset email (legacy).

Phase B — passkeys primary, passwords secondary (3–6 months)
  ──────────────────────────────────────────────────────────
  - New account creation requires a passkey; password is optional.
  - Existing accounts are prompted to enrol a passkey on next
    successful sign-in.
  - Recovery: recovery code issued at passkey-enrolment time
    (Recipe 2 above) — the email-reset path is deprecated for
    accounts that have a recovery code.

Phase C — passwordless default (6–18 months)
  ───────────────────────────────────────────
  - Accounts with ≥ 1 passkey have password sign-in disabled.
  - Their password hash row is *not deleted* — keep it as a tombstone
    flagged "auth disabled" until the account itself is closed, so
    a future support-channel recovery can't impersonate via a stale
    leaked hash.
  - Accounts without a passkey continue to sign in with a password
    (and are pestered to enrol).

Phase D — opt-out only (18 months+)
  ──────────────────────────────────
  - New accounts cannot enable password sign-in.
  - Legacy accounts can opt out of password sign-in via a
    settings toggle.
  - The remaining password-enabled accounts are the long-tail; the
    auto-rehash arm continues to migrate them silently to the
    current policy ladder. The set shrinks over time without
    operator intervention.
```

In every phase the moving parts are the same:

- **`hsh::api::hash`** to mint, **`hsh::api::verify_and_upgrade`**
  to verify and silently upgrade. The policy is a single source of
  truth that you can tighten over time without touching call sites.
- **`hsh inspect-backend --policy <preset>`** as a deploy gate so
  the binary going to prod is actually delivering the contract its
  policy declares (see [`OPERATIONS.md`](OPERATIONS.md)).
- **`hsh calibrate --json`** with the new `ladder` + `runner`
  blocks tied to the hardware so sizing decisions follow the
  fleet, not the developer's laptop.

## What `hsh` deliberately does *not* do

- **`hsh` is not a WebAuthn / FIDO2 library.** It owns the password
  side of the stack. Pair it with [`webauthn-rs`][webauthn-rs] or
  your IdP's FIDO library for the passkey side.
- **`hsh` is not a session manager.** It returns `Outcome::Valid`
  and a fresh hash to persist; minting cookies / JWTs / opaque
  session tokens is the application's job.
- **`hsh` does not phone home.** No telemetry, no remote feature
  gates, no opaque update channels. Calibration measurements stay
  on the host that ran them (the `runner` block in calibrate JSON
  is local provenance, not an upload).

[webauthn-rs]: https://github.com/kanidm/webauthn-rs

## Further reading inside this repo

- [`OPERATIONS.md`](OPERATIONS.md) — day-2 runbook for the CLI.
- [`KMS-INTEGRATION.md`](KMS-INTEGRATION.md) — pepper key rotation
  and the provider matrix.
- [`FIPS.md`](FIPS.md) — `Backend::Fips140Required` contract and
  the `aws-lc-rs` runtime roadmap.
- [`COMPARISON.md`](COMPARISON.md) — feature matrix vs. other
  Rust password-hashing crates.
- [ADR-0003](adr/0003-pepper-key-versioning.md) — why the
  `hsh-pepper:<keyver>:<inner>` wrapper format exists.
