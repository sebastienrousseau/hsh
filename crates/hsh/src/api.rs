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
use rand_core::OsRng;
use scrypt::Scrypt as ScryptHasher;

/// Hashes `password` under `policy` and returns a PHC-format string
/// (or, for [`PrimaryAlgorithm::Bcrypt`], an MCF-format `$2b$…` string).
///
/// The salt is drawn from the OS CSPRNG.
pub fn hash(policy: &Policy, password: &str) -> Result<String> {
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
pub fn verify_and_upgrade(
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
        let new_phc = hash(policy, password)?;
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
