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

/// Prefix on stored bcrypt hashes whose input was HMAC-SHA-256 pre-hashed
/// before bcrypt saw it. Format: `hsh-bcrypt-sha256:<bcrypt-mcf>`. The
/// envelope is needed because bcrypt's MCF has no parameter slot for a
/// pre-hash marker, and the prehash mode must round-trip from `api::hash`
/// to `api::verify_and_upgrade` for verification to agree with hashing.
/// Composes with [`PEPPER_PREFIX`]: a peppered + pre-hashed bcrypt hash
/// is stored as `hsh-pepper:<keyver>:hsh-bcrypt-sha256:<bcrypt-mcf>`.
const BCRYPT_PREHASH_SHA256_PREFIX: &str = "hsh-bcrypt-sha256:";

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
        return Err(fips_primary_must_be_pbkdf2(policy.primary));
    }
    if policy.backend.is_fips() && !Backend::fips_available_in_build() {
        return Err(fips_feature_not_built());
    }

    match policy.primary {
        PrimaryAlgorithm::Argon2id => {
            let salt = SaltString::generate(&mut OsRng);
            let engine = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                policy.argon2.clone(),
            );
            let phc = engine
                .hash_password(password, &salt)
                .map_err(map_argon2_err)?;
            Ok(phc.to_string())
        }
        PrimaryAlgorithm::Bcrypt => {
            let pw_str = std::str::from_utf8(password)
                .map_err(|_| bcrypt_requires_utf8())?;
            let bytes = Bcrypt::hash_with(pw_str, policy.bcrypt)?;
            let mcf = String::from_utf8(bytes)
                .map_err(map_bcrypt_utf8_err)?;
            Ok(match policy.bcrypt.prehash {
                PrehashAlgorithm::None => mcf,
                PrehashAlgorithm::Sha256 => {
                    format!("{BCRYPT_PREHASH_SHA256_PREFIX}{mcf}")
                }
            })
        }
        PrimaryAlgorithm::Scrypt => {
            let salt = SaltString::generate(&mut OsRng);
            let native = policy.scrypt.to_native()?;
            let phc = ScryptHasher
                .hash_password_customized(
                    password, None, None, native, &salt,
                )
                .map_err(map_scrypt_err)?;
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
            rest.split_once(':').ok_or_else(pepper_malformed_prefix)?;
        let ver_num: u32 =
            ver_str.parse().map_err(|_| pepper_keyver_not_int())?;
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
    // hsh-bcrypt-sha256:<mcf> envelope — the input was HMAC-SHA-256
    // pre-hashed before bcrypt saw it. Strip the envelope, verify with
    // the matching prehash mode, then evaluate drift.
    if let Some(inner_mcf) =
        stored.strip_prefix(BCRYPT_PREHASH_SHA256_PREFIX)
    {
        return verify_bcrypt(
            policy,
            password,
            inner_mcf,
            PrehashAlgorithm::Sha256,
        );
    }

    if stored.starts_with("$2a$")
        || stored.starts_with("$2b$")
        || stored.starts_with("$2x$")
        || stored.starts_with("$2y$")
    {
        return verify_bcrypt(
            policy,
            password,
            stored,
            PrehashAlgorithm::None,
        );
    }

    let parsed =
        PasswordHash::new(stored).map_err(|_| phc_not_recognised())?;
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

/// Verifies a bcrypt MCF string and decides whether the stored format
/// drifted from the current policy along any of cost / prehash mode /
/// primary-algo dimensions. Triggers rehash on any drift.
fn verify_bcrypt(
    policy: &Policy,
    password: &[u8],
    mcf: &str,
    stored_prehash: PrehashAlgorithm,
) -> Result<Outcome> {
    let pw_str = std::str::from_utf8(password)
        .map_err(|_| bcrypt_verify_requires_utf8())?;
    let valid = Bcrypt::verify(pw_str, mcf, stored_prehash)?;
    if !valid {
        return Ok(Outcome::Invalid);
    }

    let policy_is_bcrypt =
        matches!(policy.primary, PrimaryAlgorithm::Bcrypt);
    let cost_drift = policy_is_bcrypt
        && !parse_bcrypt_cost(mcf)
            .map(|c| policy.bcrypt_satisfies(c))
            .unwrap_or(false);
    let prehash_drift =
        policy_is_bcrypt && stored_prehash != policy.bcrypt.prehash;

    if !policy_is_bcrypt || cost_drift || prehash_drift {
        let new_phc = hash_unpeppered(policy, password)?;
        return Ok(Outcome::Valid {
            rehashed: Some(new_phc),
        });
    }
    Ok(Outcome::Valid { rehashed: None })
}

fn verify_pbkdf2_phc(
    parsed: &PasswordHash<'_>,
    password: &[u8],
    algo_id: &str,
) -> Result<bool> {
    // PasswordHash::new() validates that salt + hash are present at
    // the outer parser level. We trust that contract here — any
    // PBKDF2 PHC string that reached this function via the dispatch
    // in `verify_dispatch_inner` had both fields parsed.
    let salt = parsed.salt.ok_or_else(pbkdf2_missing_salt)?;
    let stored = parsed.hash.ok_or_else(pbkdf2_missing_hash)?;

    let (iterations, dk_len) =
        parse_pbkdf2_params(parsed, stored.as_bytes().len())?;
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

    if algo_id == "scrypt" {
        let stored = match parse_scrypt_phc_params(parsed) {
            Some(s) => s,
            None => return true,
        };
        return !policy.scrypt_satisfies(&stored);
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
        let stored_dk_len = parsed
            .params
            .iter()
            .find(|p| p.0.as_str() == "l")
            .and_then(|p| p.1.decimal().ok().map(|d| d as usize))
            .or_else(|| parsed.hash.map(|h| h.as_bytes().len()))
            .unwrap_or(0);
        return !policy.pbkdf2_satisfies(stored_iters, stored_dk_len);
    }

    false
}

/// Parses a bcrypt MCF cost factor (the two-digit field between the
/// second and third `$`). Returns `None` if the input is not a
/// recognisable bcrypt MCF string.
fn parse_bcrypt_cost(stored: &str) -> Option<u32> {
    // Expected layout: `$2{a,b,x,y}$<cost>$<salt+hash>`.
    let mut parts = stored.splitn(4, '$');
    let _empty = parts.next()?; // leading ""
    let _ident = parts.next()?; // "2a"/"2b"/"2x"/"2y"
    let cost_str = parts.next()?;
    cost_str.parse::<u32>().ok()
}

/// Extracts scrypt `(log_n, r, p, dk_len)` from a parsed PHC. Returns
/// `None` if a required field is missing or unparseable; the caller
/// treats `None` as a rehash trigger.
fn parse_scrypt_phc_params(
    parsed: &PasswordHash<'_>,
) -> Option<crate::algorithms::scrypt::ScryptParams> {
    let mut log_n: Option<u8> = None;
    let mut r: Option<u32> = None;
    let mut p: Option<u32> = None;
    for (k, v) in parsed.params.iter() {
        match k.as_str() {
            "ln" => {
                log_n =
                    v.decimal().ok().and_then(|d| u8::try_from(d).ok())
            }
            "r" => r = v.decimal().ok(),
            "p" => p = v.decimal().ok(),
            _ => {}
        }
    }
    Some(crate::algorithms::scrypt::ScryptParams {
        log_n: log_n?,
        r: r?,
        p: p?,
        dk_len: parsed.hash.map(|h| h.as_bytes().len())?,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers — extracted from inline `.map_err(|e| { ... })` closures
// so they're individually unit-testable. The closures themselves were
// defensive code that only fired on internal-primitive failures
// (argon2 params validation rejecting after `Params::new` already
// accepted, scrypt engine constructor refusing valid params, etc.) and
// therefore unreachable from external input. Pulling them into named
// functions makes that contract explicit and gives the test suite a
// handle.
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub fn map_argon2_err(e: password_hash::Error) -> Error {
    Error::hashing(HashingErrorKind::Argon2, e.to_string())
}

#[doc(hidden)]
pub fn map_scrypt_err(e: password_hash::Error) -> Error {
    Error::hashing(HashingErrorKind::Scrypt, e.to_string())
}

#[doc(hidden)]
pub fn map_bcrypt_utf8_err(_e: std::string::FromUtf8Error) -> Error {
    Error::hashing(
        HashingErrorKind::Bcrypt,
        "bcrypt produced non-UTF-8 output",
    )
}

#[doc(hidden)]
pub fn pbkdf2_missing_salt() -> Error {
    Error::InvalidHashString("PBKDF2 PHC missing salt".into())
}

#[doc(hidden)]
pub fn pbkdf2_missing_hash() -> Error {
    Error::InvalidHashString("PBKDF2 PHC missing hash".into())
}

/// Parse the `i=<N>,l=<M>` parameters out of a PBKDF2 PHC string.
/// Returns `(iterations, dk_len)`. Unknown PHC params are silently
/// ignored. Bad decimal values surface `Error::InvalidHashString`.
#[doc(hidden)]
pub fn parse_pbkdf2_params(
    parsed: &PasswordHash<'_>,
    default_dk_len: usize,
) -> Result<(u32, usize)> {
    let mut iterations: u32 = 0;
    let mut dk_len: usize = default_dk_len;
    for p in parsed.params.iter() {
        match p.0.as_str() {
            "i" => {
                iterations =
                    p.1.decimal().map_err(|_| pbkdf2_bad_iter())?;
            }
            "l" => {
                dk_len =
                    p.1.decimal().map_err(|_| pbkdf2_bad_dk_len())?
                        as usize;
            }
            _ => {}
        }
    }
    Ok((iterations, dk_len))
}

#[doc(hidden)]
pub fn pbkdf2_bad_iter() -> Error {
    Error::InvalidHashString("PBKDF2 PHC bad iteration count".into())
}

#[doc(hidden)]
pub fn pbkdf2_bad_dk_len() -> Error {
    Error::InvalidHashString("PBKDF2 PHC bad output length".into())
}

#[doc(hidden)]
pub fn bcrypt_requires_utf8() -> Error {
    Error::InvalidPassword(
        "bcrypt requires UTF-8 passwords; supply pre-hash via \
         PrehashAlgorithm for arbitrary bytes"
            .into(),
    )
}

#[doc(hidden)]
pub fn bcrypt_verify_requires_utf8() -> Error {
    Error::InvalidPassword(
        "bcrypt verification requires UTF-8 passwords".into(),
    )
}

#[doc(hidden)]
pub fn pepper_malformed_prefix() -> Error {
    Error::InvalidHashString("malformed pepper prefix".into())
}

#[doc(hidden)]
pub fn pepper_keyver_not_int() -> Error {
    Error::InvalidHashString("pepper keyver must be an integer".into())
}

#[doc(hidden)]
pub fn phc_not_recognised() -> Error {
    Error::InvalidHashString(
        "not a recognised PHC or MCF string".into(),
    )
}

#[doc(hidden)]
pub fn fips_primary_must_be_pbkdf2(primary: PrimaryAlgorithm) -> Error {
    Error::InvalidParameter(
        format!(
            "Backend::Fips140Required cannot mint hashes with {primary:?} \
             — only PBKDF2 has a FIPS 140-3 validated implementation. \
             Switch policy.primary to PrimaryAlgorithm::Pbkdf2 or relax \
             policy.backend."
        )
        .into(),
    )
}

#[doc(hidden)]
pub fn fips_feature_not_built() -> Error {
    Error::InvalidParameter(
        "Backend::Fips140Required policy supplied but the `fips` Cargo \
         feature is not enabled in this build. Rebuild with `--features \
         fips` or relax policy.backend to Backend::Native."
            .into(),
    )
}
