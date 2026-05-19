// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Structured error type for the `hsh` crate.
//!
//! Every variant carries either a `Cow<'static, str>` (zero-alloc context
//! for constant messages, owned for dynamic ones) or a typed `#[source]`
//! so callers can downcast to the underlying error and discriminate
//! without parsing strings.

use std::borrow::Cow;
use thiserror::Error;

/// The error type returned by all fallible `hsh` operations.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The requested algorithm string did not match any supported variant.
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(Cow<'static, str>),

    /// The PHC / serialized hash string could not be parsed.
    #[error("invalid hash string: {0}")]
    InvalidHashString(Cow<'static, str>),

    /// A supplied parameter (cost, memory, iterations…) was outside the
    /// algorithm's valid range.
    #[error("invalid parameter: {0}")]
    InvalidParameter(Cow<'static, str>),

    /// The provided password did not meet a length / encoding precondition.
    #[error("password rejected: {0}")]
    InvalidPassword(Cow<'static, str>),

    /// The supplied salt could not be decoded or was the wrong shape.
    #[error("invalid salt: {0}")]
    InvalidSalt(Cow<'static, str>),

    /// The underlying primitive (Argon2 / bcrypt / scrypt / PBKDF2)
    /// reported a failure. The source error is preserved for structured
    /// downcasting.
    #[error("hashing failed: {0}")]
    Hashing(HashingError),

    /// Verification failed for an internal reason (not a wrong password —
    /// that returns [`crate::Outcome::Invalid`]). For example, the
    /// stored hash was corrupt.
    #[error("verification failed: {0}")]
    Verification(Cow<'static, str>),

    /// The [`crate::policy::PolicyBuilder`] could not produce a valid
    /// [`crate::Policy`] — typically because a required field was missing.
    #[error("invalid policy: {0}")]
    InvalidPolicy(Cow<'static, str>),

    /// Generic I/O or codec error (base64 decode, UTF-8, JSON).
    #[error(transparent)]
    Decode(#[from] DecodeError),

    /// Optional pepper provider (KMS / HSM) reported a failure.
    #[cfg(feature = "pepper")]
    #[error("pepper provider: {0}")]
    Pepper(Cow<'static, str>),
}

/// Wrapper carrying the underlying primitive's error for structured
/// downcasting. `Clone` is preserved by stringifying the source — KDF
/// errors are rare so the alloc is acceptable.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct HashingError {
    /// Which primitive surfaced the error.
    pub kind: HashingErrorKind,
    /// Human-readable detail from the upstream crate.
    pub detail: Cow<'static, str>,
}

impl std::fmt::Display for HashingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for HashingError {}

/// Which primitive surfaced a [`HashingError`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum HashingErrorKind {
    /// `argon2` crate.
    Argon2,
    /// `bcrypt` crate.
    Bcrypt,
    /// `scrypt` crate.
    Scrypt,
    /// `pbkdf2` crate.
    Pbkdf2,
    /// `password_hash` PHC encoder.
    PhcEncoder,
}

impl std::fmt::Display for HashingErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Argon2 => f.write_str("argon2"),
            Self::Bcrypt => f.write_str("bcrypt"),
            Self::Scrypt => f.write_str("scrypt"),
            Self::Pbkdf2 => f.write_str("pbkdf2"),
            Self::PhcEncoder => f.write_str("phc encoder"),
        }
    }
}

/// Sub-category for decoding-class errors so callers can distinguish
/// them without parsing strings.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Bytes were not valid UTF-8.
    #[error("utf-8 decode: {0}")]
    Utf8(Cow<'static, str>),

    /// Base64 decode failed.
    #[error("base64 decode: {0}")]
    Base64(Cow<'static, str>),

    /// JSON decode failed.
    #[error("json decode: {0}")]
    Json(Cow<'static, str>),
}

/// Convenience `Result` alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Ergonomic conversions
// ---------------------------------------------------------------------------

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Error::Decode(DecodeError::Utf8(e.to_string().into()))
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Decode(DecodeError::Base64(e.to_string().into()))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Decode(DecodeError::Json(e.to_string().into()))
    }
}

#[cfg(feature = "pepper")]
impl From<hsh_kms::PepperError> for Error {
    fn from(e: hsh_kms::PepperError) -> Self {
        Error::Pepper(e.to_string().into())
    }
}

impl Error {
    /// Constructs an [`Error::Hashing`] for the named primitive with the
    /// supplied detail. The detail accepts anything `Into<Cow<'static, str>>`
    /// so callers can pass string literals (zero-alloc) or owned `String`s.
    ///
    /// # Examples
    ///
    /// ```
    /// use hsh::error::{Error, HashingErrorKind};
    ///
    /// let err = Error::hashing(HashingErrorKind::Argon2, "memory cost too low");
    /// assert!(err.to_string().contains("argon2"));
    /// ```
    pub fn hashing(
        kind: HashingErrorKind,
        detail: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::Hashing(HashingError {
            kind,
            detail: detail.into(),
        })
    }
}

// Compile-time assertion: Error stays Send + Sync + Clone so it composes
// with tower-style middleware and fans an error to multiple sinks.
const _: fn() = || {
    fn assert<T: Send + Sync + Clone + 'static>() {}
    assert::<Error>();
    assert::<DecodeError>();
    assert::<HashingError>();
    assert::<HashingErrorKind>();
};
