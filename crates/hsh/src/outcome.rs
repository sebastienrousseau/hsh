// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The [`Outcome`] of a verification — used by
//! [`crate::api::verify_and_upgrade`] to signal whether the caller should
//! re-hash the password under the current [`crate::Policy`].
//!
//! The rehashed PHC string is folded into the `Valid` variant so the
//! invariant *"rehashed payload exists iff needs_rehash"* is enforced by
//! the type system, not by callers reading docs.

/// Result of verifying a candidate password against a stored hash.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Outcome {
    /// The candidate password matches the stored hash.
    Valid {
        /// `Some(new_phc)` when the stored hash falls below current
        /// policy — caller persists the value. `None` when no rehash
        /// is needed.
        rehashed: Option<String>,
    },
    /// The candidate password does not match. Constant-time path —
    /// timing does not leak how much of the candidate matched.
    Invalid,
}

impl Outcome {
    /// Returns `true` if the verification succeeded.
    ///
    /// # Examples
    ///
    /// ```
    /// use hsh::Outcome;
    ///
    /// assert!(Outcome::Valid { rehashed: None }.is_valid());
    /// assert!(!Outcome::Invalid.is_valid());
    /// ```
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Outcome::Valid { .. })
    }

    /// Returns `true` if the verification succeeded *and* the caller
    /// should re-hash to bring stored material up to current policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use hsh::Outcome;
    ///
    /// assert!(!Outcome::Valid { rehashed: None }.needs_rehash());
    /// assert!(Outcome::Valid { rehashed: Some(String::new()) }.needs_rehash());
    /// assert!(!Outcome::Invalid.needs_rehash());
    /// ```
    #[must_use]
    pub const fn needs_rehash(&self) -> bool {
        matches!(self, Outcome::Valid { rehashed: Some(_) })
    }

    /// Returns the new PHC string to persist, if any.
    #[must_use]
    pub fn rehashed(&self) -> Option<&str> {
        match self {
            Outcome::Valid { rehashed: Some(p) } => Some(p.as_str()),
            _ => None,
        }
    }

    /// Consumes the outcome and yields the new PHC string to persist.
    #[must_use]
    pub fn into_rehashed(self) -> Option<String> {
        match self {
            Outcome::Valid { rehashed } => rehashed,
            Outcome::Invalid => None,
        }
    }
}

// Send + Sync of Outcome is asserted at test-time via
// `crates/hsh/tests/test_outcome.rs::outcome_is_send_and_sync`. The
// test-fn does exactly the same compile-time work as a `const _ = ||
// fn assert<T: Send + Sync>(){}; assert::<Outcome>();` block, but
// cargo-llvm-cov counts the latter as an uncovered runtime line.
