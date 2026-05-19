// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Versioned `Policy` describing the primary algorithm and per-algorithm
//! parameters used by the high-level [`crate::api`] surface.
//!
//! Construct a policy in one of three ways:
//!
//! 1. A **preset** for the common case — [`Policy::owasp_minimum_2025`],
//!    [`Policy::rfc9106_first_recommended`], [`Policy::fips_140_pbkdf2`].
//! 2. The **builder** for explicit configuration —
//!    `PolicyBuilder::new` starting from scratch, or
//!    `PolicyBuilder::from_preset` starting from a preset and
//!    overriding select fields.
//! 3. Combinator methods on a `Policy` for one-off overrides —
//!    `Policy::with_pepper` (requires the `pepper` feature).
//!
//! Fields are non-public; adding new ones is a non-breaking change
//! per `doc/API-STABILITY.md`.

use crate::algorithms::argon2id;
use crate::algorithms::bcrypt::BcryptParams;
use crate::algorithms::pbkdf2::Pbkdf2Params;
use crate::algorithms::scrypt::ScryptParams;
use crate::backend::Backend;
use crate::error::Error;
use argon2::Params as Argon2Params;
#[cfg(feature = "pepper")]
use std::sync::Arc;

/// Which algorithm a [`Policy`] uses for *new* hashes.
///
/// Verification accepts any of the supported algorithms (Argon2i/d/id,
/// bcrypt, scrypt, PBKDF2) regardless of the policy's primary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum PrimaryAlgorithm {
    /// **Argon2id** — recommended; the only sensible default for
    /// new password hashes per RFC 9106 §4.
    Argon2id,
    /// **Bcrypt** — useful for ecosystems already on bcrypt.
    Bcrypt,
    /// **Scrypt** — memory-hard, simpler parameter story than Argon2.
    Scrypt,
    /// **PBKDF2** — the only KDF with a FIPS 140-3 validated path
    /// (via `aws-lc-rs` behind the `fips` feature). Use this when
    /// compliance dictates and Argon2id is unavailable.
    Pbkdf2,
}

/// Versioned policy snapshot: the algorithm to use for new hashes plus
/// the parameter ladders for every supported variant.
///
/// Construct via [`Policy::owasp_minimum_2025`],
/// [`Policy::rfc9106_first_recommended`], [`Policy::fips_140_pbkdf2`],
/// or [`PolicyBuilder`]. Internal fields are non-public; use the
/// accessor methods for introspection.
#[derive(Clone, Debug)]
pub struct Policy {
    pub(crate) primary: PrimaryAlgorithm,
    pub(crate) backend: Backend,
    pub(crate) argon2: Argon2Params,
    pub(crate) bcrypt: BcryptParams,
    pub(crate) scrypt: ScryptParams,
    pub(crate) pbkdf2: Pbkdf2Params,
    #[cfg(feature = "pepper")]
    pub(crate) pepper: Option<Arc<dyn hsh_kms::Pepper>>,
}

impl Policy {
    /// OWASP Password Storage Cheat Sheet 2025 minimum for all three KDFs.
    ///
    /// - **Argon2id**: `m = 19 456 KiB (19 MiB)`, `t = 2`, `p = 1`
    /// - **Bcrypt**: `cost = 10`, no pre-hash
    /// - **Scrypt**: `N = 2^17`, `r = 8`, `p = 1`
    /// - **PBKDF2**: `iters = 600 000`, `dk_len = 32`
    #[must_use]
    pub fn owasp_minimum_2025() -> Self {
        Self {
            primary: PrimaryAlgorithm::Argon2id,
            backend: Backend::Native,
            argon2: argon2id::owasp_minimum_2025(),
            bcrypt: BcryptParams::new(10),
            scrypt: ScryptParams::default(),
            pbkdf2: Pbkdf2Params::owasp_minimum_2025(),
            #[cfg(feature = "pepper")]
            pepper: None,
        }
    }

    /// RFC 9106 §4 first-recommended for Argon2id: `m = 2^21 (2 GiB)`,
    /// `t = 1`, `p = 4`. Bcrypt and scrypt fall back to OWASP-2025.
    #[must_use]
    pub fn rfc9106_first_recommended() -> Self {
        Self {
            primary: PrimaryAlgorithm::Argon2id,
            backend: Backend::Native,
            argon2: argon2id::rfc9106_first_recommended(),
            bcrypt: BcryptParams::new(10),
            scrypt: ScryptParams::default(),
            pbkdf2: Pbkdf2Params::owasp_minimum_2025(),
            #[cfg(feature = "pepper")]
            pepper: None,
        }
    }

    /// FIPS 140-3 deployment preset: **PBKDF2-HMAC-SHA-256, 600 000
    /// iterations** (OWASP-2025 minimum), with
    /// [`Backend::Fips140Required`].
    ///
    /// Argon2 / bcrypt / scrypt remain present in this preset's
    /// parameter ladder for verifying legacy hashes, but
    /// [`crate::api::hash`] will refuse to mint new hashes under those
    /// algorithms when `backend == Backend::Fips140Required` because
    /// they have no FIPS-validated implementation anywhere.
    #[must_use]
    pub fn fips_140_pbkdf2() -> Self {
        Self {
            primary: PrimaryAlgorithm::Pbkdf2,
            backend: Backend::Fips140Required,
            argon2: argon2id::owasp_minimum_2025(),
            bcrypt: BcryptParams::new(10),
            scrypt: ScryptParams::default(),
            pbkdf2: Pbkdf2Params::owasp_minimum_2025(),
            #[cfg(feature = "pepper")]
            pepper: None,
        }
    }

    /// Returns the primary algorithm new hashes are minted under.
    #[must_use]
    pub const fn primary(&self) -> PrimaryAlgorithm {
        self.primary
    }

    /// Returns the crypto-validation requirement.
    #[must_use]
    pub const fn backend(&self) -> Backend {
        self.backend
    }

    /// Returns a reference to the Argon2 parameter set.
    #[must_use]
    pub const fn argon2_params(&self) -> &Argon2Params {
        &self.argon2
    }

    /// Returns the bcrypt parameter set.
    #[must_use]
    pub const fn bcrypt_params(&self) -> BcryptParams {
        self.bcrypt
    }

    /// Returns the scrypt parameter set.
    #[must_use]
    pub const fn scrypt_params(&self) -> ScryptParams {
        self.scrypt
    }

    /// Returns the PBKDF2 parameter set.
    #[must_use]
    pub const fn pbkdf2_params(&self) -> Pbkdf2Params {
        self.pbkdf2
    }

    /// Returns whether a pepper provider is attached. Always `false`
    /// without the `pepper` feature.
    #[must_use]
    pub fn has_pepper(&self) -> bool {
        #[cfg(feature = "pepper")]
        {
            self.pepper.is_some()
        }
        #[cfg(not(feature = "pepper"))]
        {
            false
        }
    }

    /// Attaches a pepper provider to this policy and returns the
    /// updated value.
    ///
    /// Accepts any `impl hsh_kms::Pepper + 'static` so callers don't
    /// have to wrap their provider in `Arc` manually — the wrap is
    /// applied internally. Pass an already-wrapped `Arc<dyn Pepper>`
    /// via [`Self::with_pepper_arc`] when sharing across instances.
    ///
    /// New hashes will be peppered with `provider.current()`. Old
    /// hashes carrying earlier key versions remain verifiable, and
    /// [`crate::api::verify_and_upgrade`] will signal `needs_rehash`
    /// when an old version is detected.
    #[cfg(feature = "pepper")]
    #[must_use]
    pub fn with_pepper(
        mut self,
        provider: impl hsh_kms::Pepper + 'static,
    ) -> Self {
        self.pepper = Some(Arc::new(provider));
        self
    }

    /// Variant of [`Self::with_pepper`] that accepts an already-wrapped
    /// `Arc<dyn Pepper>` — useful when the same provider instance is
    /// shared across multiple policies.
    #[cfg(feature = "pepper")]
    #[must_use]
    pub fn with_pepper_arc(
        mut self,
        provider: Arc<dyn hsh_kms::Pepper>,
    ) -> Self {
        self.pepper = Some(provider);
        self
    }

    /// Returns a [`PolicyBuilder`] seeded with the fields of this
    /// policy, suitable for forking + overriding select values.
    #[must_use]
    pub fn to_builder(&self) -> PolicyBuilder {
        PolicyBuilder::from_preset(self)
    }

    /// Returns `true` if `stored_params` are at least as strong as the
    /// current policy's Argon2 params. Used by [`crate::api::verify_and_upgrade`]
    /// to decide whether a successful verify should trigger a rehash.
    pub(crate) fn argon2_satisfies(
        &self,
        stored: &Argon2Params,
    ) -> bool {
        stored.m_cost() >= self.argon2.m_cost()
            && stored.t_cost() >= self.argon2.t_cost()
            && stored.p_cost() >= self.argon2.p_cost()
            && stored.output_len() == self.argon2.output_len()
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::owasp_minimum_2025()
    }
}

/// Fluent builder for [`Policy`].
///
/// Construct via [`PolicyBuilder::new`] for a blank slate (in which
/// case [`PolicyBuilder::build`] requires at least `primary`), or via
/// [`PolicyBuilder::from_preset`] to start from one of the presets and
/// override individual fields.
///
/// ## Example
///
/// ```
/// use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};
///
/// let policy = PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
///     .primary(PrimaryAlgorithm::Pbkdf2)
///     .build()
///     .expect("valid policy");
///
/// assert_eq!(policy.primary(), PrimaryAlgorithm::Pbkdf2);
/// ```
#[derive(Clone, Debug, Default)]
pub struct PolicyBuilder {
    primary: Option<PrimaryAlgorithm>,
    backend: Option<Backend>,
    argon2: Option<Argon2Params>,
    bcrypt: Option<BcryptParams>,
    scrypt: Option<ScryptParams>,
    pbkdf2: Option<Pbkdf2Params>,
    #[cfg(feature = "pepper")]
    pepper: Option<Arc<dyn hsh_kms::Pepper>>,
}

impl PolicyBuilder {
    /// Starts a blank builder. [`build`](Self::build) will error if at
    /// least the primary algorithm isn't set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeds the builder from an existing policy so individual fields
    /// can be overridden without re-listing the others.
    #[must_use]
    pub fn from_preset(policy: &Policy) -> Self {
        Self {
            primary: Some(policy.primary),
            backend: Some(policy.backend),
            argon2: Some(policy.argon2.clone()),
            bcrypt: Some(policy.bcrypt),
            scrypt: Some(policy.scrypt),
            pbkdf2: Some(policy.pbkdf2),
            #[cfg(feature = "pepper")]
            pepper: policy.pepper.clone(),
        }
    }

    /// Sets the primary algorithm new hashes are minted under.
    #[must_use]
    pub fn primary(mut self, primary: PrimaryAlgorithm) -> Self {
        self.primary = Some(primary);
        self
    }

    /// Sets the crypto-validation requirement (FIPS / Native).
    #[must_use]
    pub fn backend(mut self, backend: Backend) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Overrides the Argon2 parameter set.
    #[must_use]
    pub fn argon2(mut self, params: Argon2Params) -> Self {
        self.argon2 = Some(params);
        self
    }

    /// Overrides the bcrypt parameter set.
    #[must_use]
    pub fn bcrypt(mut self, params: BcryptParams) -> Self {
        self.bcrypt = Some(params);
        self
    }

    /// Overrides the scrypt parameter set.
    #[must_use]
    pub fn scrypt(mut self, params: ScryptParams) -> Self {
        self.scrypt = Some(params);
        self
    }

    /// Overrides the PBKDF2 parameter set.
    #[must_use]
    pub fn pbkdf2(mut self, params: Pbkdf2Params) -> Self {
        self.pbkdf2 = Some(params);
        self
    }

    /// Attaches a pepper provider. Requires the `pepper` feature.
    ///
    /// Accepts any `impl Pepper + 'static`; the `Arc` wrap is internal.
    #[cfg(feature = "pepper")]
    #[must_use]
    pub fn pepper(
        mut self,
        provider: impl hsh_kms::Pepper + 'static,
    ) -> Self {
        self.pepper = Some(Arc::new(provider));
        self
    }

    /// Variant of [`Self::pepper`] for callers holding an already-
    /// wrapped `Arc<dyn Pepper>` (e.g. sharing across many builders).
    #[cfg(feature = "pepper")]
    #[must_use]
    pub fn pepper_arc(
        mut self,
        provider: Arc<dyn hsh_kms::Pepper>,
    ) -> Self {
        self.pepper = Some(provider);
        self
    }

    /// Removes any attached pepper provider. Requires the `pepper`
    /// feature.
    #[cfg(feature = "pepper")]
    #[must_use]
    pub fn no_pepper(mut self) -> Self {
        self.pepper = None;
        self
    }

    /// Finalises the builder into a [`Policy`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPolicy`] if the builder was started
    /// from [`new`](Self::new) without calling [`primary`](Self::primary).
    pub fn build(self) -> Result<Policy, Error> {
        Ok(Policy {
            primary: self.primary.ok_or(Error::InvalidPolicy(
                "primary algorithm required".into(),
            ))?,
            backend: self.backend.unwrap_or_default(),
            argon2: self
                .argon2
                .unwrap_or_else(argon2id::owasp_minimum_2025),
            bcrypt: self
                .bcrypt
                .unwrap_or_else(|| BcryptParams::new(10)),
            scrypt: self.scrypt.unwrap_or_default(),
            pbkdf2: self.pbkdf2.unwrap_or_default(),
            #[cfg(feature = "pepper")]
            pepper: self.pepper,
        })
    }
}
