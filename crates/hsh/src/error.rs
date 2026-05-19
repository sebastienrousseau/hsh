// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Structured error type for the `hsh` crate.
//!
//! Replaces the legacy `Result<T, String>` returns with a `thiserror`-based
//! enum that implements [`std::error::Error`], so callers can pattern-match
//! and use `?` across crates.

use thiserror::Error;

/// The error type returned by all fallible `hsh` operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The requested algorithm string did not match any supported variant.
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The PHC / serialized hash string could not be parsed.
    #[error("invalid hash string: {0}")]
    InvalidHashString(&'static str),

    /// A supplied parameter (cost, memory, iterations…) was outside the
    /// algorithm's valid range.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    /// The provided password did not meet a length / encoding precondition.
    #[error("password rejected: {0}")]
    InvalidPassword(&'static str),

    /// The supplied salt could not be decoded or was the wrong shape.
    #[error("invalid salt: {0}")]
    InvalidSalt(&'static str),

    /// The underlying primitive (Argon2 / bcrypt / scrypt) reported a failure.
    #[error("hashing failed: {0}")]
    Hashing(String),

    /// Verification failed for an internal reason (not a wrong password —
    /// that returns `Ok(false)`). For example, the stored hash was corrupt.
    #[error("verification failed: {0}")]
    Verification(&'static str),

    /// The [`crate::policy::PolicyBuilder`] could not produce a valid
    /// [`crate::Policy`] — typically because a required field was missing.
    #[error("invalid policy: {0}")]
    InvalidPolicy(&'static str),

    /// Generic I/O or codec error (base64 decode, UTF-8, JSON).
    #[error(transparent)]
    Decode(#[from] DecodeError),
}

/// Sub-category for decoding-class errors so callers can distinguish them
/// without parsing strings.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Bytes were not valid UTF-8.
    #[error("utf-8 decode: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// Base64 decode failed.
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),

    /// JSON decode failed.
    #[error("json decode: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience `Result` alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

// Ergonomic conversions so call-sites stay terse.
impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Error::Decode(DecodeError::Utf8(e))
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Decode(DecodeError::Base64(e))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Decode(DecodeError::Json(e))
    }
}
