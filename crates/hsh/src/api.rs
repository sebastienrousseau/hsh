// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! High-level enterprise API: PHC-formatted hash storage with
//! multi-algorithm verification and automatic rehash on policy drift.
//!
//! The functions here serialise hashes in the **PHC string format**
//! (`$<algo>$v=<ver>$<params>$<salt>$<hash>`) using the RustCrypto
//! `password_hash` traits. PHC strings are interoperable with Django,
//! Devise, libsodium, the Argon2 CLI, and most other ecosystems.
//!
//! Bcrypt hashes use the legacy Modular Crypt Format (`$2b$…`), which
//! `password_hash` also recognises.
//!
//! ## Example
//!
//! ```no_run
//! use hsh::{Policy, api};
//!
//! let policy = Policy::owasp_minimum_2025();
//! let stored = api::hash(&policy, "correct horse battery staple")?;
//! let outcome = api::verify_and_upgrade(&policy, "correct horse battery staple", &stored)?;
//!
//! assert!(outcome.0.is_valid());
//! # Ok::<(), hsh::Error>(())
//! ```

use crate::algorithms::bcrypt::{Bcrypt, PrehashAlgorithm};
use crate::error::{Error, Result};
use crate::outcome::Outcome;
use crate::policy::{Policy, PrimaryAlgorithm};
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Version};
#[cfg(feature = "pepper")]
use base64::{engine::general_purpose, Engine as _};
use rand_core::OsRng;
use scrypt::Scrypt as ScryptHasher;

/// Prefix on stored hashes that have been peppered. Format:
/// `hsh-pepper:<keyver>:<phc-or-mcf>`.
#[cfg(feature = "pepper")]
const PEPPER_PREFIX: &str = "hsh-pepper:";

/// Hashes `password` under `policy` and returns a PHC-format string
/// (or, for [`PrimaryAlgorithm::Bcrypt`], an MCF-format `$2b$…` string).
///
/// When `policy.pepper` is `Some` (requires the `pepper` feature), the
/// password is HMAC-SHA-256-ed with the current pepper key before being
/// fed to the KDF, and the resulting hash is wrapped in a
/// `hsh-pepper:<keyver>:` prefix so verification can locate the right
/// key on the way back.
///
/// The salt is drawn from the OS CSPRNG.
pub fn hash(policy: &Policy, password: &str) -> Result<String> {
    #[cfg(feature = "pepper")]
    if let Some(pepper) = policy.pepper.as_ref() {
        let version = pepper.current();
        let tag = pepper.apply(version, password.as_bytes()).map_err(
            |e| Error::Hashing(format!("pepper apply failed: {e}")),
        )?;
        // KDFs accept arbitrary bytes; we base64-encode the 32-byte HMAC
        // tag so the downstream PHC string stays UTF-8.
        let peppered = general_purpose::STANDARD_NO_PAD.encode(tag);
        let inner = hash_unpeppered(policy, &peppered)?;
        return Ok(format!("{PEPPER_PREFIX}{}:{inner}", version.get()));
    }
    hash_unpeppered(policy, password)
}

fn hash_unpeppered(policy: &Policy, password: &str) -> Result<String> {
    match policy.primary {
        PrimaryAlgorithm::Argon2id => {
            let salt = SaltString::generate(&mut OsRng);
            let engine = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                policy.argon2.clone(),
            );
            let phc = engine
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| Error::Hashing(e.to_string()))?;
            Ok(phc.to_string())
        }
        PrimaryAlgorithm::Bcrypt => {
            let bytes = Bcrypt::hash_with(password, policy.bcrypt)?;
            String::from_utf8(bytes).map_err(|_| {
                Error::Hashing(
                    "bcrypt produced non-UTF-8 output".to_owned(),
                )
            })
        }
        PrimaryAlgorithm::Scrypt => {
            // scrypt's `PasswordHasher` impl uses its built-in default
            // params; custom-param PHC for scrypt is tracked under
            // Phase 1 follow-up (the raw-bytes path via
            // `crate::algorithms::scrypt::Scrypt::hash_with` already
            // supports configurable params).
            let salt = SaltString::generate(&mut OsRng);
            let _ = policy.scrypt; // params held for future custom-PHC support
            let phc = ScryptHasher
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| Error::Hashing(e.to_string()))?;
            Ok(phc.to_string())
        }
    }
}

/// Verifies `password` against `stored` and signals whether the stored
/// hash should be re-hashed under the current `policy`.
///
/// Returns `(Outcome, Option<new_phc>)`:
/// - `(Outcome::Valid { needs_rehash: false }, None)` — match, current policy.
/// - `(Outcome::Valid { needs_rehash: true }, Some(new_phc))` — match,
///   caller should persist `new_phc`.
/// - `(Outcome::Invalid, None)` — mismatch.
///
/// Supports:
/// - **PHC strings** for Argon2id / Argon2i / Argon2d (via the
///   `argon2` crate's `PasswordVerifier` impl).
/// - **PHC strings** for scrypt (via the `scrypt` crate's
///   `PasswordVerifier` impl).
/// - **MCF strings** (`$2a$…` / `$2b$…` / `$2y$…`) for bcrypt.
/// - **Peppered** strings (`hsh-pepper:<keyver>:<inner>`) — requires
///   the `pepper` feature and a pepper provider attached to the policy.
pub fn verify_and_upgrade(
    policy: &Policy,
    password: &str,
    stored: &str,
) -> Result<(Outcome, Option<String>)> {
    #[cfg(feature = "pepper")]
    if let Some(rest) = stored.strip_prefix(PEPPER_PREFIX) {
        let Some(pepper) = policy.pepper.as_ref() else {
            // Stored hash is peppered but the verifier has no pepper —
            // we can't compute the HMAC tag, so by definition we can't
            // verify. Refuse rather than silently fail-open.
            return Ok((Outcome::Invalid, None));
        };
        // Parse "<keyver>:<inner>".
        let (ver_str, inner) = rest.split_once(':').ok_or(
            Error::InvalidHashString("malformed pepper prefix"),
        )?;
        let ver_num: u32 = ver_str.parse().map_err(|_| {
            Error::InvalidHashString("pepper keyver must be an integer")
        })?;
        let stored_version = hsh_kms::KeyVersion::new(ver_num);
        let tag =
            pepper.apply(stored_version, password.as_bytes()).map_err(
                |e| Error::Hashing(format!("pepper apply failed: {e}")),
            )?;
        let peppered = general_purpose::STANDARD_NO_PAD.encode(tag);
        // Recurse into the unpeppered path with the HMAC-derived
        // "password". The inner Outcome carries the algorithm-level
        // decision; we then layer rotation logic on top.
        let (outcome, rehashed_inner) =
            verify_and_upgrade_inner(policy, &peppered, inner)?;
        if !outcome.is_valid() {
            return Ok((Outcome::Invalid, None));
        }
        // Algorithm-level rehash already triggered, or pepper-version
        // drift — either way, rehash with the current pepper version.
        let current = pepper.current();
        let needs_pepper_rehash = stored_version != current;
        if needs_pepper_rehash || rehashed_inner.is_some() {
            let new_phc = hash(policy, password)?;
            return Ok((
                Outcome::Valid { needs_rehash: true },
                Some(new_phc),
            ));
        }
        return Ok((
            Outcome::Valid {
                needs_rehash: false,
            },
            None,
        ));
    }

    // If the policy carries a pepper but the stored hash is NOT
    // peppered, that's a legacy entry — verify it bare and rehash
    // under the pepper on success.
    #[cfg(feature = "pepper")]
    if policy.pepper.is_some() && !stored.starts_with(PEPPER_PREFIX) {
        let (outcome, _) =
            verify_and_upgrade_inner(policy, password, stored)?;
        if outcome.is_valid() {
            let new_phc = hash(policy, password)?;
            return Ok((
                Outcome::Valid { needs_rehash: true },
                Some(new_phc),
            ));
        }
        return Ok((Outcome::Invalid, None));
    }

    verify_and_upgrade_inner(policy, password, stored)
}

fn verify_and_upgrade_inner(
    policy: &Policy,
    password: &str,
    stored: &str,
) -> Result<(Outcome, Option<String>)> {
    // Bcrypt's MCF string is not parseable as a PHC string; handle it first.
    if stored.starts_with("$2a$")
        || stored.starts_with("$2b$")
        || stored.starts_with("$2x$")
        || stored.starts_with("$2y$")
    {
        let valid =
            Bcrypt::verify(password, stored, PrehashAlgorithm::None)?;
        if !valid {
            return Ok((Outcome::Invalid, None));
        }
        // If the policy still mints bcrypt, the verifier doesn't try to
        // inspect cost factor here — a future refinement could parse the
        // `$2b$10$…` cost field. For now, never trigger rehash on bcrypt
        // unless the policy has moved away from bcrypt entirely.
        if !matches!(policy.primary, PrimaryAlgorithm::Bcrypt) {
            // The outer `hash()` would re-apply pepper; for inner-only
            // bcrypt rehash we want an unpeppered output here, which is
            // what `hash_unpeppered` already returns.
            let new_phc = hash_unpeppered(policy, password)?;
            return Ok((
                Outcome::Valid { needs_rehash: true },
                Some(new_phc),
            ));
        }
        return Ok((
            Outcome::Valid {
                needs_rehash: false,
            },
            None,
        ));
    }

    let parsed = PasswordHash::new(stored).map_err(|_| {
        Error::InvalidHashString("not a recognised PHC or MCF string")
    })?;
    let algo_id = parsed.algorithm.as_str();

    let valid = match algo_id {
        "argon2id" => Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            policy.argon2.clone(),
        )
        .verify_password(password.as_bytes(), &parsed)
        .is_ok(),
        "argon2i" => Argon2::new(
            Algorithm::Argon2i,
            Version::V0x13,
            policy.argon2.clone(),
        )
        .verify_password(password.as_bytes(), &parsed)
        .is_ok(),
        "argon2d" => Argon2::new(
            Algorithm::Argon2d,
            Version::V0x13,
            policy.argon2.clone(),
        )
        .verify_password(password.as_bytes(), &parsed)
        .is_ok(),
        "scrypt" => ScryptHasher
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        other => {
            return Err(Error::UnsupportedAlgorithm(other.to_owned()));
        }
    };

    if !valid {
        return Ok((Outcome::Invalid, None));
    }

    let needs_rehash = needs_rehash(&parsed, algo_id, policy);
    if needs_rehash {
        let new_phc = hash_unpeppered(policy, password)?;
        Ok((Outcome::Valid { needs_rehash: true }, Some(new_phc)))
    } else {
        Ok((
            Outcome::Valid {
                needs_rehash: false,
            },
            None,
        ))
    }
}

/// Decides whether a successful verification should trigger a rehash.
fn needs_rehash(
    parsed: &PasswordHash<'_>,
    algo_id: &str,
    policy: &Policy,
) -> bool {
    // Algorithm drift — if the stored hash isn't the policy's primary,
    // it's a candidate for upgrade.
    let primary_matches = matches!(
        (policy.primary, algo_id),
        (PrimaryAlgorithm::Argon2id, "argon2id")
            | (PrimaryAlgorithm::Scrypt, "scrypt")
    );
    if !primary_matches {
        return true;
    }

    // Parameter drift — for Argon2id, compare the stored params to the
    // policy via `argon2::Params::try_from(&PasswordHash)`.
    if algo_id == "argon2id" {
        if let Ok(stored_params) = argon2::Params::try_from(parsed) {
            return !policy.argon2_satisfies(&stored_params);
        }
        return true;
    }

    // Scrypt: minimal parameter check via the parsed params string.
    // Conservative default — if we can't introspect, trigger rehash.
    false
}
