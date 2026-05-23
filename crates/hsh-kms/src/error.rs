// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Structured error type for the `hsh-kms` crate.

use thiserror::Error;

use crate::KeyVersion;

/// Errors returned by [`Pepper`](crate::Pepper) implementations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PepperError {
    /// The provider does not hold a key for the requested version.
    #[error("unknown key version: {0}")]
    UnknownVersion(KeyVersion),

    /// The provider has no keys registered at all — typically a builder
    /// configuration error.
    #[error("pepper provider has no keys registered")]
    EmptyKeyset,

    /// A registered key was shorter than the 16-byte safety floor.
    #[error("pepper key version {version} is {actual} bytes; must be at least {minimum}")]
    KeyTooShort {
        /// Version that failed validation.
        version: KeyVersion,
        /// Actual length in bytes.
        actual: usize,
        /// Required minimum.
        minimum: usize,
    },

    /// The underlying KMS / HSM backend returned an error.
    #[error("pepper backend error: {0}")]
    Backend(String),
}
