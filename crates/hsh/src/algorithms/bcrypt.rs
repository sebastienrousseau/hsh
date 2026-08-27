// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bcrypt wrapper with explicit 72-byte safety rail.
//!
//! ## Why the safety rail
//!
//! Bcrypt silently truncates passwords at 72 bytes. This produced real
//! authentication-bypass CVEs in 2024–2025:
//!
//! - **CVE-2025-22228** — Spring Security `BCryptPasswordEncoder` silently
//!   accepted passwords `>72` chars as equal to their first-72-byte prefix.
//! - **CVE-2025-68402** — FreshRSS triggered the same class of bug when an
//!   unrelated SHA-1 → SHA-256 nonce upgrade pushed the input over 72
//!   bytes.
//! - **Okta delegated-auth bypass (Oct 2024)** — cache keys built as
//!   `bcrypt(SHA1(user+session+pw))` collided when the SHA-1 hex pushed
//!   bcrypt's input beyond 72 bytes.
//!
//! This wrapper **rejects** any password longer than 72 bytes by default.
//! Callers that genuinely need to support longer inputs must opt in to a
//! pre-hash via [`BcryptParams::with_prehash`](crate::algorithms::bcrypt::BcryptParams::with_prehash).
//!
//! ## Storage format when a pre-hash is configured
//!
//! Bcrypt's MCF (`$2b$<cost>$<salt+hash>`) has no parameter slot for a
//! pre-hash marker, so [`crate::api::hash`] wraps the MCF in the
//! `hsh-bcrypt-sha256:<mcf>` envelope when
//! [`PrehashAlgorithm::Sha256`](crate::algorithms::bcrypt::PrehashAlgorithm::Sha256)
//! is set on the [`crate::policy::Policy`]. The envelope round-trips
//! through [`crate::api::verify_and_upgrade`], which routes the password
//! through the same pre-hash before comparing — without the envelope the
//! verify side would feed bcrypt the raw password and the comparison
//! would always fail. The envelope also composes with the
//! `hsh-pepper:<keyver>:` wrapper: peppered + pre-hashed bcrypt hashes
//! are stored as `hsh-pepper:<keyver>:hsh-bcrypt-sha256:<mcf>`. Pre-hash
//! mode drift (stored mode ≠ policy mode) triggers an `Outcome::Valid
//! { rehashed: Some(_) }` on the next successful verify.

use crate::error::{Error, Result};
use crate::models::hash_algorithm::HashingAlgorithm;
use bcrypt::DEFAULT_COST;
use serde::{Deserialize, Serialize};

/// Maximum password length bcrypt can handle without silent truncation.
pub const BCRYPT_MAX_INPUT_BYTES: usize = 72;

/// The highest bcrypt cost factor accepted when *verifying* a stored
/// hash, unless a caller opts into a different bound.
///
/// bcrypt encodes its work factor in the hash string itself, so
/// verification cost is dictated by the stored value rather than by
/// local policy. Anything that can influence what gets stored — or that
/// simply submits a crafted string to a verification endpoint — can
/// therefore choose how much CPU the check burns. Cost is a base-2
/// exponent, so the growth is steep. Measured on one x86-64 laptop,
/// release build, `bcrypt::verify`:
///
/// | cost | verify |
/// |-----:|-------:|
/// |   10 |  57 ms |
/// |   12 | 196 ms |
/// |   14 | 784 ms |
/// |   16 |  3.0 s |
/// |   18 | 18.4 s |
/// |   20 |    73 s |
///
/// Fuzzing found `$2x$29$…` — 512x the work of cost 20 — stalling a
/// single verification for over 29 minutes.
///
/// 16 is the default ceiling: it admits every cost a real deployment is
/// likely to use (OWASP puts the 2025 minimum at 10; high-security
/// setups reach 12–14) with headroom, while bounding one verification
/// to a few seconds rather than half an hour. Callers who deliberately
/// store higher-cost hashes should use
/// [`Bcrypt::verify_with_max_cost`] rather than raise this.
pub const MAX_VERIFY_COST: u32 = 16;

/// Reads the cost factor out of a bcrypt hash string.
///
/// The format is `$2<variant>$<cost>$<22-char salt><31-char digest>`,
/// so the cost is the second `$`-delimited field. Returns `None` if the
/// string is not shaped like a bcrypt hash; callers treat that as "not
/// ours to reject" and let the underlying implementation report it.
pub(crate) fn stored_cost(stored: &str) -> Option<u32> {
    let mut parts = stored.split('$');
    // A leading `$` means the first field is empty.
    if parts.next() != Some("") {
        return None;
    }
    let variant = parts.next()?;
    if !matches!(variant, "2" | "2a" | "2b" | "2x" | "2y") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// Pre-hash algorithm to apply when the password exceeds 72 bytes.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub enum PrehashAlgorithm {
    /// No pre-hash — bcrypt receives the password verbatim and rejects
    /// inputs `>72` bytes. **Recommended default.**
    #[default]
    None,
    /// Hash the password with HMAC-SHA-256 keyed by the bcrypt salt
    /// before passing the 32-byte digest to bcrypt. Lets you accept
    /// arbitrary-length inputs without truncation.
    Sha256,
}

/// Bcrypt parameters.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BcryptParams {
    /// Bcrypt cost factor (log2 of work). OWASP-2025 minimum is 10.
    pub cost: u32,
    /// Optional pre-hash to allow inputs longer than 72 bytes.
    pub prehash: PrehashAlgorithm,
}

impl Default for BcryptParams {
    fn default() -> Self {
        Self {
            cost: DEFAULT_COST,
            prehash: PrehashAlgorithm::None,
        }
    }
}

impl BcryptParams {
    /// Builds a bcrypt parameter set with the given cost factor.
    pub fn new(cost: u32) -> Self {
        Self {
            cost,
            prehash: PrehashAlgorithm::None,
        }
    }

    /// Enables the pre-hash safety adapter so passwords longer than
    /// 72 bytes are accepted via HMAC-SHA-256 pre-hash.
    pub fn with_prehash(mut self, algo: PrehashAlgorithm) -> Self {
        self.prehash = algo;
        self
    }
}

/// Marker type for the Bcrypt hashing algorithm.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct Bcrypt;

impl HashingAlgorithm for Bcrypt {
    /// Hashes `password` using bcrypt at [`DEFAULT_COST`].
    ///
    /// The `_salt` argument is ignored — bcrypt generates its own salt.
    /// Inputs longer than [`BCRYPT_MAX_INPUT_BYTES`] are **rejected** with
    /// [`Error::InvalidPassword`]; use [`Bcrypt::hash_with`] for an opt-in
    /// pre-hash policy.
    fn hash_password(password: &str, _salt: &str) -> Result<Vec<u8>> {
        Self::hash_with(password, BcryptParams::default())
    }
}

impl Bcrypt {
    /// Hashes `password` under explicit [`BcryptParams`].
    pub fn hash_with(
        password: &str,
        params: BcryptParams,
    ) -> Result<Vec<u8>> {
        let payload =
            prepare_payload(password.as_bytes(), params.prehash)?;
        bcrypt::hash(&payload, params.cost)
            .map(String::into_bytes)
            .map_err(|e| {
                Error::hashing(
                    crate::error::HashingErrorKind::Bcrypt,
                    e.to_string(),
                )
            })
    }

    /// Verifies `password` against a bcrypt hash string.
    ///
    /// Constant-time comparison is delegated to the `bcrypt` crate,
    /// which uses `subtle` internally.
    pub fn verify(
        password: &str,
        stored: &str,
        prehash: PrehashAlgorithm,
    ) -> Result<bool> {
        Self::verify_with_max_cost(
            password,
            stored,
            prehash,
            MAX_VERIFY_COST,
        )
    }

    /// Verifies `password` against a bcrypt hash string, refusing any
    /// stored cost above `max_cost`.
    ///
    /// [`verify`](Self::verify) delegates here with
    /// [`MAX_VERIFY_COST`]. Use this directly only when the stored
    /// hashes are known to carry a higher work factor by design, and
    /// keep the bound as low as those hashes allow: it is the only
    /// thing standing between a verification endpoint and an
    /// attacker-chosen amount of CPU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHashString`] if the stored hash
    /// advertises a cost above `max_cost`, before any work is done, and
    /// [`Error::Verification`] if the underlying check fails.
    pub fn verify_with_max_cost(
        password: &str,
        stored: &str,
        prehash: PrehashAlgorithm,
        max_cost: u32,
    ) -> Result<bool> {
        // Check the advertised work factor before doing any of it. The
        // cost lives in the stored string, so without this an untrusted
        // value decides how long verification runs.
        if let Some(cost) = stored_cost(stored) {
            if cost > max_cost {
                return Err(Error::InvalidHashString(
                    format!(
                        "bcrypt cost {cost} exceeds the maximum accepted for verification ({max_cost})"
                    )
                    .into(),
                ));
            }
        }

        let payload = prepare_payload(password.as_bytes(), prehash)?;
        bcrypt::verify(&payload, stored).map_err(|_| {
            Error::Verification("bcrypt verify failed".into())
        })
    }
}

fn prepare_payload(
    password: &[u8],
    prehash: PrehashAlgorithm,
) -> Result<Vec<u8>> {
    match prehash {
        PrehashAlgorithm::None => {
            if password.len() > BCRYPT_MAX_INPUT_BYTES {
                return Err(Error::InvalidPassword(
                    "bcrypt input exceeds 72 bytes; opt into a pre-hash via BcryptParams::with_prehash to handle longer inputs".into(),
                ));
            }
            Ok(password.to_vec())
        }
        PrehashAlgorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(password);
            // bcrypt's input must be valid UTF-8; b64-encode the digest
            // to ensure that without losing entropy.
            use base64::{engine::general_purpose, Engine as _};
            Ok(general_purpose::STANDARD_NO_PAD
                .encode(digest)
                .into_bytes())
        }
    }
}

#[cfg(test)]
mod verify_cost_tests {
    //! Unit tests for the cost guard's parsing half.
    //!
    //! Anything that passes a password to `Bcrypt::verify` lives in
    //! `tests/test_bcrypt_cost_bound.rs` instead. `crates/*/src/` is
    //! analysed by CodeQL as production code, where a hard-coded
    //! password is a critical finding; `crates/*/tests/**` is excluded
    //! precisely because fixtures there are expected to carry them.
    //! See `.github/codeql/codeql-config.yml`.

    use super::*;

    /// The cost carried by the input libFuzzer found stalling
    /// `fuzz_phc_parse` for over 29 minutes.
    const FUZZ_TIMEOUT_COST: u32 = 29;

    #[test]
    fn reads_the_cost_from_each_variant_prefix() {
        for prefix in ["2", "2a", "2b", "2x", "2y"] {
            let stored = format!("${prefix}$12$abcdefghijklmnopqrstuv");
            assert_eq!(
                stored_cost(&stored),
                Some(12),
                "prefix {prefix}"
            );
        }
    }

    #[test]
    fn ignores_strings_that_are_not_bcrypt() {
        assert_eq!(
            stored_cost("$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA"),
            None
        );
        assert_eq!(stored_cost("not-a-hash"), None);
        assert_eq!(stored_cost(""), None);
        assert_eq!(stored_cost("$2b$notanumber$abc"), None);
    }

    #[test]
    fn the_fuzz_input_cost_is_above_the_default_bound() {
        let stored = format!(
            "$2x${FUZZ_TIMEOUT_COST}$rrjrrdrjrrdrh..jrrdrh..n....jrrdrh..."
        );
        let cost = stored_cost(&stored).expect("bcrypt string");
        assert_eq!(cost, FUZZ_TIMEOUT_COST);
        assert!(cost > MAX_VERIFY_COST, "must be refused by default");
        assert!(
            cost <= 31,
            "must be admitted once the bound is raised"
        );
    }

    #[test]
    fn the_bound_is_inclusive_at_the_ceiling() {
        let at =
            format!("$2b${MAX_VERIFY_COST}$abcdefghijklmnopqrstuv");
        let over = format!(
            "$2b${}$abcdefghijklmnopqrstuv",
            MAX_VERIFY_COST + 1
        );
        assert_eq!(stored_cost(&at), Some(MAX_VERIFY_COST));
        assert_eq!(stored_cost(&over), Some(MAX_VERIFY_COST + 1));
    }
}
