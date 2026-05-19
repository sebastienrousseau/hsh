// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The [`Outcome`] of a verification — used by
//! [`crate::api::verify_and_upgrade`] to signal whether the caller should
//! re-hash the password under the current [`crate::Policy`].

/// Result of verifying a candidate password against a stored hash.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Outcome {
    /// The candidate password matches the stored hash. `needs_rehash`
    /// is `true` when the stored hash's algorithm or parameters are
    /// weaker than the current [`crate::Policy`] — the caller should
    /// persist a fresh hash to keep stored material at the current bar.
    Valid {
        /// Whether the stored hash is now below policy.
        needs_rehash: bool,
    },
    /// The candidate password does not match. Constant-time path —
    /// timing does not leak how much of the candidate matched.
    Invalid,
}

impl Outcome {
    /// Returns `true` if the verification succeeded.
    pub fn is_valid(self) -> bool {
        matches!(self, Outcome::Valid { .. })
    }

    /// Returns `true` if the verification succeeded *and* the caller
    /// should re-hash to bring stored material up to current policy.
    pub fn needs_rehash(self) -> bool {
        matches!(self, Outcome::Valid { needs_rehash: true })
    }
}
