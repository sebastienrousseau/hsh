// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! High-level enterprise API: PHC-formatted hash storage with
//! multi-algorithm verification and automatic rehash on policy drift.
//!
//! ## Example
//!
//! ```
//! use hsh::{Outcome, Policy, api};
//!
//! fn main() -> Result<(), hsh::Error> {
//!     let policy = Policy::owasp_minimum_2025();
//!     let stored = api::hash(&policy, "correct horse battery staple")?;
//!
//!     let outcome = api::verify_and_upgrade(
//!         &policy,
//!         "correct horse battery staple",
//!         &stored,
//!     )?;
//!
//!     assert!(outcome.is_valid());
//!     assert!(!outcome.needs_rehash());  // fresh hash matches current policy
//!     Ok(())
//! }
//! ```

use crate::algorithms::bcrypt::{Bcrypt, PrehashAlgorithm};
use crate::algorithms::pbkdf2::{Pbkdf2, Pbkdf2Params, Prf};
use crate::backend::Backend;
use crate::error::{Error, HashingErrorKind, Result};
use crate::outcome::Outcome;
use crate::policy::{Policy, PrimaryAlgorithm};
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Version};
use base64::{engine::general_purpose, Engine as _};
use rand_core::OsRng;
use scrypt::Scrypt as ScryptHasher;
use subtle::ConstantTimeEq;

/// Prefix on stored hashes that have been peppered. Format:
/// `hsh-pepper:<keyver>:<phc-or-mcf>`.
#[cfg(feature = "pepper")]
const PEPPER_PREFIX: &str = "hsh-pepper:";

/// Hashes `password` under `policy` and returns a PHC-format string
/// (or, for [`PrimaryAlgorithm::Bcrypt`], an MCF-format `$2b$…` string).
///
/// `password` accepts anything that yields `&[u8]` — `&str`, `String`,
/// `Vec<u8>`, `&[u8; N]`, or `Cow`. Passwords need not be valid UTF-8
/// (except for the bcrypt path, where the underlying crate requires
/// `&str`; non-UTF-8 inputs to bcrypt return [`Error::InvalidPassword`]).
///
/// The salt is drawn from the OS CSPRNG.
///
/// # Errors
///
/// Returns [`Error::InvalidParameter`] if the policy declares
/// [`Backend::Fips140Required`] but the build can't satisfy it, or if
/// the primary algorithm is not the only FIPS-routed KDF (PBKDF2).
/// Returns [`Error::Hashing`] (with a [`HashingErrorKind`]
/// discriminant) if the underlying primitive rejects the input.
///
/// [`HashingErrorKind`]: crate::error::HashingErrorKind
///
/// # Examples
///
/// ```
/// use hsh::{Policy, api};
///
/// fn main() -> Result<(), hsh::Error> {
///     let policy = Policy::owasp_minimum_2025();
///
///     // Works with &str:
///     let stored_a = api::hash(&policy, "hunter2")?;
///     // …and with &[u8] (Latin-1 password, raw bytes, etc.):
///     let stored_b = api::hash(&policy, &b"hunter2"[..])?;
///
///     assert!(stored_a.starts_with("$argon2id$"));
///     assert!(stored_b.starts_with("$argon2id$"));
///     Ok(())
/// }
/// ```
pub fn hash(
    policy: &Policy,
    password: impl AsRef<[u8]>,
) -> Result<String> {
    let password = password.as_ref();

    #[cfg(feature = "pepper")]
    if let Some(pepper) = policy.pepper.as_ref() {
        let version = pepper.current();
        let tag = pepper.apply(version, password)?;
        let peppered = general_purpose::STANDARD_NO_PAD.encode(tag);
        let inner = hash_unpeppered(policy, peppered.as_bytes())?;
        return Ok(format!("{PEPPER_PREFIX}{}:{inner}", version.get()));
    }

    hash_unpeppered(policy, password)
}

fn hash_unpeppered(policy: &Policy, password: &[u8]) -> Result<String> {
    if policy.backend.is_fips()
        && !matches!(policy.primary, PrimaryAlgorithm::Pbkdf2)
    {
        return Err(Error::InvalidParameter(
            format!(
                "Backend::Fips140Required cannot mint hashes with {:?} — \
                 only PBKDF2 has a FIPS 140-3 validated implementation. \
                 Switch policy.primary to PrimaryAlgorithm::Pbkdf2 or relax \
                 policy.backend.",
                policy.primary
            )
            .into(),
        ));
    }
    if policy.backend.is_fips() && !Backend::fips_available_in_build() {
        return Err(Error::InvalidParameter(
            "Backend::Fips140Required policy supplied but the `fips` Cargo \
             feature is not enabled in this build. Rebuild with `--features \
             fips` or relax policy.backend to Backend::Native."
                .into(),
        ));
    }

    match policy.primary {
        PrimaryAlgorithm::Argon2id => {
            let salt = SaltString::generate(&mut OsRng);
            let engine = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                policy.argon2.clone(),
            );
            let phc =
                engine.hash_password(password, &salt).map_err(|e| {
                    Error::hashing(
                        HashingErrorKind::Argon2,
                        e.to_string(),
                    )
                })?;
            Ok(phc.to_string())
        }
        PrimaryAlgorithm::Bcrypt => {
            let pw_str = std::str::from_utf8(password).map_err(|_| {
                Error::InvalidPassword(
                    "bcrypt requires UTF-8 passwords; supply pre-hash via \
                     PrehashAlgorithm for arbitrary bytes"
                        .into(),
                )
            })?;
            let bytes = Bcrypt::hash_with(pw_str, policy.bcrypt)?;
            String::from_utf8(bytes).map_err(|_| {
                Error::hashing(
                    HashingErrorKind::Bcrypt,
                    "bcrypt produced non-UTF-8 output",
                )
            })
        }
        PrimaryAlgorithm::Scrypt => {
            let salt = SaltString::generate(&mut OsRng);
            let _ = policy.scrypt;
            let phc = ScryptHasher
                .hash_password(password, &salt)
                .map_err(|e| {
                    Error::hashing(
                        HashingErrorKind::Scrypt,
                        e.to_string(),
                    )
                })?;
            Ok(phc.to_string())
        }
        PrimaryAlgorithm::Pbkdf2 => {
            let salt = SaltString::generate(&mut OsRng);
            let raw = Pbkdf2::hash_with(
                password,
                salt.as_str().as_bytes(),
                policy.pbkdf2,
            )?;
            let salt_b64 = salt.as_str();
            let hash_b64 =
                general_purpose::STANDARD_NO_PAD.encode(&raw);
            Ok(format!(
                "${alg}$i={iters},l={len}${salt_b64}${hash_b64}",
                alg = match policy.pbkdf2.prf {
                    Prf::Sha256 => "pbkdf2-sha256",
                    Prf::Sha512 => "pbkdf2-sha512",
                },
                iters = policy.pbkdf2.iterations,
                len = policy.pbkdf2.dk_len,
            ))
        }
    }
}

/// Verifies `password` against `stored` and signals whether the stored
/// hash should be re-hashed under the current `policy`.
///
/// `password` accepts anything that yields `&[u8]`; `stored` accepts
/// anything that yields `&str`.
///
/// Returns an [`Outcome`]:
/// - `Outcome::Valid { rehashed: None }` — match, current policy.
/// - `Outcome::Valid { rehashed: Some(new_phc) }` — match, caller persists `new_phc`.
/// - `Outcome::Invalid` — mismatch.
///
/// # Errors
///
/// Returns [`Error::InvalidHashString`] if `stored` is not a recognised
/// PHC or MCF string; [`Error::UnsupportedAlgorithm`] for valid PHC but
/// unknown algorithm; [`Error::Hashing`] / [`Error::Pepper`] for
/// primitive / KMS failures.
///
/// # Examples
///
/// ```
/// use hsh::{Outcome, Policy, api};
///
/// fn main() -> Result<(), hsh::Error> {
///     let policy = Policy::owasp_minimum_2025();
///     let stored = api::hash(&policy, "hunter2")?;
///
///     let outcome = api::verify_and_upgrade(&policy, "wrong", &stored)?;
///     assert!(matches!(outcome, Outcome::Invalid));
///
///     let outcome = api::verify_and_upgrade(&policy, "hunter2", &stored)?;
///     assert!(outcome.is_valid());
///     assert!(!outcome.needs_rehash());
///     Ok(())
/// }
/// ```
pub fn verify_and_upgrade(
    policy: &Policy,
    password: impl AsRef<[u8]>,
    stored: impl AsRef<str>,
) -> Result<Outcome> {
    verify_dispatch(policy, password.as_ref(), stored.as_ref())
}

fn verify_dispatch(
    policy: &Policy,
    password: &[u8],
    stored: &str,
) -> Result<Outcome> {
    #[cfg(feature = "pepper")]
    if let Some(rest) = stored.strip_prefix(PEPPER_PREFIX) {
        let Some(pepper) = policy.pepper.as_ref() else {
            return Ok(Outcome::Invalid);
        };
        let (ver_str, inner) =
            rest.split_once(':').ok_or_else(|| {
                Error::InvalidHashString(
                    "malformed pepper prefix".into(),
                )
            })?;
        let ver_num: u32 = ver_str.parse().map_err(|_| {
            Error::InvalidHashString(
                "pepper keyver must be an integer".into(),
            )
        })?;
        let stored_version = hsh_kms::KeyVersion::new(ver_num);
        let tag = pepper.apply(stored_version, password)?;
        let peppered = general_purpose::STANDARD_NO_PAD.encode(tag);
        let inner_outcome =
            verify_dispatch_inner(policy, peppered.as_bytes(), inner)?;
        if !inner_outcome.is_valid() {
            return Ok(Outcome::Invalid);
        }
        let current = pepper.current();
        let needs_rotate =
            stored_version != current || inner_outcome.needs_rehash();
        if needs_rotate {
            let new_phc = hash(policy, password)?;
            return Ok(Outcome::Valid {
                rehashed: Some(new_phc),
            });
        }
        return Ok(Outcome::Valid { rehashed: None });
    }

    #[cfg(feature = "pepper")]
    if policy.pepper.is_some() && !stored.starts_with(PEPPER_PREFIX) {
        let outcome = verify_dispatch_inner(policy, password, stored)?;
        if outcome.is_valid() {
            let new_phc = hash(policy, password)?;
            return Ok(Outcome::Valid {
                rehashed: Some(new_phc),
            });
        }
        return Ok(Outcome::Invalid);
    }

    verify_dispatch_inner(policy, password, stored)
}

fn verify_dispatch_inner(
    policy: &Policy,
    password: &[u8],
    stored: &str,
) -> Result<Outcome> {
    if stored.starts_with("$2a$")
        || stored.starts_with("$2b$")
        || stored.starts_with("$2x$")
        || stored.starts_with("$2y$")
    {
        let pw_str = std::str::from_utf8(password).map_err(|_| {
            Error::InvalidPassword(
                "bcrypt verification requires UTF-8 passwords".into(),
            )
        })?;
        let valid =
            Bcrypt::verify(pw_str, stored, PrehashAlgorithm::None)?;
        if !valid {
            return Ok(Outcome::Invalid);
        }
        if !matches!(policy.primary, PrimaryAlgorithm::Bcrypt) {
            let new_phc = hash_unpeppered(policy, password)?;
            return Ok(Outcome::Valid {
                rehashed: Some(new_phc),
            });
        }
        return Ok(Outcome::Valid { rehashed: None });
    }

    let parsed = PasswordHash::new(stored).map_err(|_| {
        Error::InvalidHashString(
            "not a recognised PHC or MCF string".into(),
        )
    })?;
    let algo_id = parsed.algorithm.as_str();

    let valid = match algo_id {
        "argon2id" => Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            policy.argon2.clone(),
        )
        .verify_password(password, &parsed)
        .is_ok(),
        "argon2i" => Argon2::new(
            Algorithm::Argon2i,
            Version::V0x13,
            policy.argon2.clone(),
        )
        .verify_password(password, &parsed)
        .is_ok(),
        "argon2d" => Argon2::new(
            Algorithm::Argon2d,
            Version::V0x13,
            policy.argon2.clone(),
        )
        .verify_password(password, &parsed)
        .is_ok(),
        "scrypt" => {
            ScryptHasher.verify_password(password, &parsed).is_ok()
        }
        "pbkdf2-sha256" | "pbkdf2-sha512" => {
            verify_pbkdf2_phc(&parsed, password, algo_id)?
        }
        other => {
            return Err(Error::UnsupportedAlgorithm(
                other.to_owned().into(),
            ));
        }
    };

    if !valid {
        return Ok(Outcome::Invalid);
    }

    if needs_rehash(&parsed, algo_id, policy) {
        let new_phc = hash_unpeppered(policy, password)?;
        Ok(Outcome::Valid {
            rehashed: Some(new_phc),
        })
    } else {
        Ok(Outcome::Valid { rehashed: None })
    }
}

fn verify_pbkdf2_phc(
    parsed: &PasswordHash<'_>,
    password: &[u8],
    algo_id: &str,
) -> Result<bool> {
    let salt = parsed.salt.ok_or_else(|| {
        Error::InvalidHashString("PBKDF2 PHC missing salt".into())
    })?;
    let stored = parsed.hash.ok_or_else(|| {
        Error::InvalidHashString("PBKDF2 PHC missing hash".into())
    })?;

    let mut iterations: u32 = 0;
    let mut dk_len: usize = stored.as_bytes().len();
    for p in parsed.params.iter() {
        match p.0.as_str() {
            "i" => {
                iterations = p.1.decimal().map_err(|_| {
                    Error::InvalidHashString(
                        "PBKDF2 PHC bad iteration count".into(),
                    )
                })?;
            }
            "l" => {
                dk_len = p.1.decimal().map_err(|_| {
                    Error::InvalidHashString(
                        "PBKDF2 PHC bad output length".into(),
                    )
                })? as usize;
            }
            _ => {}
        }
    }
    if iterations == 0 {
        return Err(Error::InvalidHashString(
            "PBKDF2 PHC missing iteration count".into(),
        ));
    }

    // Defensive: the caller filters algo_id to one of the two known
    // tags, but a typed return is preferred over `unreachable!()` so
    // future callers can't accidentally trip an abort.
    let prf = match algo_id {
        "pbkdf2-sha256" => Prf::Sha256,
        "pbkdf2-sha512" => Prf::Sha512,
        other => {
            return Err(Error::UnsupportedAlgorithm(
                other.to_owned().into(),
            ));
        }
    };
    let params = Pbkdf2Params {
        prf,
        iterations,
        dk_len,
    };
    let calculated =
        Pbkdf2::hash_with(password, salt.as_str().as_bytes(), params)?;
    Ok(bool::from(calculated.ct_eq(stored.as_bytes())))
}

fn needs_rehash(
    parsed: &PasswordHash<'_>,
    algo_id: &str,
    policy: &Policy,
) -> bool {
    let primary_matches = matches!(
        (policy.primary, algo_id),
        (PrimaryAlgorithm::Argon2id, "argon2id")
            | (PrimaryAlgorithm::Scrypt, "scrypt")
            | (
                PrimaryAlgorithm::Pbkdf2,
                "pbkdf2-sha256" | "pbkdf2-sha512"
            )
    );
    if !primary_matches {
        return true;
    }

    if algo_id == "argon2id" {
        return argon2::Params::try_from(parsed)
            .map(|stored| !policy.argon2_satisfies(&stored))
            .unwrap_or(true);
    }

    if algo_id == "pbkdf2-sha256" || algo_id == "pbkdf2-sha512" {
        let policy_prf_id = match policy.pbkdf2.prf {
            Prf::Sha256 => "pbkdf2-sha256",
            Prf::Sha512 => "pbkdf2-sha512",
        };
        if algo_id != policy_prf_id {
            return true;
        }
        let stored_iters = parsed
            .params
            .iter()
            .find(|p| p.0.as_str() == "i")
            .and_then(|p| p.1.decimal().ok())
            .unwrap_or(0);
        return stored_iters < policy.pbkdf2.iterations;
    }

    false
}
