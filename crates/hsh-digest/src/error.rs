// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Structured error type for the `hsh-digest` crate.

use thiserror::Error;

/// Errors returned by [`crate::Hasher`] and [`crate::hash`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DigestError {
    /// The requested algorithm wasn't compiled into this build (its
    /// Cargo feature was disabled).
    ///
    /// Today this is unreachable because the [`crate::Algorithm`]
    /// variants are themselves feature-gated. Kept for forward
    /// compatibility with the planned runtime-selectable algorithm
    /// table.
    #[error("algorithm {0:?} is not available in this build")]
    Unavailable(&'static str),
}
