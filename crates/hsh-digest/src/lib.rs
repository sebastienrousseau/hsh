#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `hsh-digest` — general-purpose hashing primitives
//!
//! **⚠️ This crate is NOT for password storage.** Hashing passwords
//! requires a memory-hard / iteration-hard KDF (Argon2id, scrypt,
//! bcrypt, PBKDF2). For that, use `hsh::api::hash` from the `hsh`
//! crate, not the primitives here.
//!
//! Use `hsh-digest` when you need a standard cryptographic digest for
//! things like:
//!
//! - Content addressing (Git-style, IPFS-style content hashes).
//! - Message authentication codes (with the `hmac` crate on top).
//! - Random-oracle / commitment schemes.
//! - PHC-string parsing for non-`hsh` hashes.
//! - Building blocks for higher-level protocols (e.g. Merkle trees).
//!
//! ## Algorithms
//!
//! | Family | Members | Feature flag |
//! | ------ | ------- | ------------ |
//! | SHA-2  | SHA-256, SHA-384, SHA-512 | `sha2` (default) |
//! | SHA-3  | SHA3-256, SHA3-384, SHA3-512 | `sha3` (default) |
//! | BLAKE3 | BLAKE3-256 | `blake3` (default) |
//! | K12    | KangarooTwelve, TurboSHAKE128/256 | `k12` (stub) |
//! | Ascon  | Ascon-Hash256, Ascon-XOF128 | `ascon` (stub) |
//!
//! ## Example
//!
//! ### One-shot
//!
//! ```
//! use hsh_digest::{Algorithm, hash};
//!
//! let digest = hash(Algorithm::Sha256, b"hello, world").unwrap();
//! assert_eq!(digest.len(), 32);
//! ```
//!
//! ### Streaming
//!
//! ```
//! use hsh_digest::{Algorithm, Hasher};
//!
//! let mut hasher = Hasher::new(Algorithm::Blake3).unwrap();
//! hasher.update(b"hello, ");
//! hasher.update(b"world");
//! let digest = hasher.finalize();
//! assert_eq!(digest.len(), 32);
//! ```

// At least one algorithm feature must be enabled — the `Algorithm`
// enum and `HasherInner` would otherwise be uninhabited, producing
// downstream `unreachable_code` errors.
#[cfg(not(any(
    feature = "sha2",
    feature = "sha3",
    feature = "blake3"
)))]
compile_error!(
    "hsh-digest requires at least one algorithm feature: `sha2`, `sha3`, or `blake3`."
);

pub mod error;

pub use error::DigestError;

// Bring the `digest::Digest` trait into scope at module level so
// `update` / `finalize` methods resolve on the sha2 / sha3 hashers.
// Hoisted out of each function body so static analysers don't trip
// on cfg-gated `use` statements interleaved with parameter usage
// (CodeQL Rust extractor false-positive on `rust/unused-variable`).
#[cfg(any(feature = "sha2", feature = "sha3"))]
use digest::Digest as _;

/// Supported general-purpose hash algorithms.
///
/// Variants are gated by feature flag — see crate-level docs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Algorithm {
    /// SHA-256 (FIPS 180-4). 32-byte output.
    #[cfg(feature = "sha2")]
    Sha256,
    /// SHA-384 (FIPS 180-4). 48-byte output.
    #[cfg(feature = "sha2")]
    Sha384,
    /// SHA-512 (FIPS 180-4). 64-byte output.
    #[cfg(feature = "sha2")]
    Sha512,
    /// SHA3-256 (FIPS 202). 32-byte output.
    #[cfg(feature = "sha3")]
    Sha3_256,
    /// SHA3-384 (FIPS 202). 48-byte output.
    #[cfg(feature = "sha3")]
    Sha3_384,
    /// SHA3-512 (FIPS 202). 64-byte output.
    #[cfg(feature = "sha3")]
    Sha3_512,
    /// BLAKE3, 32-byte output.
    #[cfg(feature = "blake3")]
    Blake3,
}

impl Algorithm {
    /// Returns the output length in bytes for this algorithm.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            #[cfg(feature = "sha2")]
            Self::Sha256 => 32,
            #[cfg(feature = "sha2")]
            Self::Sha384 => 48,
            #[cfg(feature = "sha2")]
            Self::Sha512 => 64,
            #[cfg(feature = "sha3")]
            Self::Sha3_256 => 32,
            #[cfg(feature = "sha3")]
            Self::Sha3_384 => 48,
            #[cfg(feature = "sha3")]
            Self::Sha3_512 => 64,
            #[cfg(feature = "blake3")]
            Self::Blake3 => 32,
        }
    }

    /// Returns the standard algorithm identifier (e.g. `"sha256"`).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            #[cfg(feature = "sha2")]
            Self::Sha256 => "sha256",
            #[cfg(feature = "sha2")]
            Self::Sha384 => "sha384",
            #[cfg(feature = "sha2")]
            Self::Sha512 => "sha512",
            #[cfg(feature = "sha3")]
            Self::Sha3_256 => "sha3-256",
            #[cfg(feature = "sha3")]
            Self::Sha3_384 => "sha3-384",
            #[cfg(feature = "sha3")]
            Self::Sha3_512 => "sha3-512",
            #[cfg(feature = "blake3")]
            Self::Blake3 => "blake3",
        }
    }
}

/// One-shot convenience: hashes `data` with `algorithm` and returns
/// the digest bytes.
///
/// # Errors
///
/// Returns [`DigestError::Unavailable`] if `algorithm` was compiled
/// out via Cargo features. This is unreachable when the corresponding
/// `Algorithm` variant exists — the function signature simply mirrors
/// `Hasher::new` for consistency.
pub fn hash(
    algorithm: Algorithm,
    data: &[u8],
) -> Result<Vec<u8>, DigestError> {
    let mut h = Hasher::new(algorithm)?;
    h.update(data);
    Ok(h.finalize())
}

/// Streaming hasher — call [`Hasher::update`] one or more times, then
/// [`Hasher::finalize`].
pub struct Hasher {
    inner: HasherInner,
}

impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hasher")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

// blake3::Hasher is ~1KB while sha2 state is ~96B; we deliberately
// accept the size delta because boxing every variant would force a
// heap allocation per hash, which dwarfs the cost of a few extra
// stack bytes in the streaming path.
#[allow(clippy::large_enum_variant)]
enum HasherInner {
    #[cfg(feature = "sha2")]
    Sha256(sha2::Sha256),
    #[cfg(feature = "sha2")]
    Sha384(sha2::Sha384),
    #[cfg(feature = "sha2")]
    Sha512(sha2::Sha512),
    #[cfg(feature = "sha3")]
    Sha3_256(sha3::Sha3_256),
    #[cfg(feature = "sha3")]
    Sha3_384(sha3::Sha3_384),
    #[cfg(feature = "sha3")]
    Sha3_512(sha3::Sha3_512),
    #[cfg(feature = "blake3")]
    Blake3(blake3::Hasher),
}

impl Hasher {
    /// Creates a new streaming hasher for the given algorithm.
    ///
    /// # Errors
    ///
    /// Currently infallible because `Algorithm` variants are themselves
    /// feature-gated; kept as `Result` for forward compatibility when
    /// runtime-selectable algorithms land.
    pub fn new(algorithm: Algorithm) -> Result<Self, DigestError> {
        let inner = match algorithm {
            #[cfg(feature = "sha2")]
            Algorithm::Sha256 => {
                HasherInner::Sha256(sha2::Sha256::new())
            }
            #[cfg(feature = "sha2")]
            Algorithm::Sha384 => {
                HasherInner::Sha384(sha2::Sha384::new())
            }
            #[cfg(feature = "sha2")]
            Algorithm::Sha512 => {
                HasherInner::Sha512(sha2::Sha512::new())
            }
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_256 => {
                HasherInner::Sha3_256(sha3::Sha3_256::new())
            }
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_384 => {
                HasherInner::Sha3_384(sha3::Sha3_384::new())
            }
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_512 => {
                HasherInner::Sha3_512(sha3::Sha3_512::new())
            }
            #[cfg(feature = "blake3")]
            Algorithm::Blake3 => {
                HasherInner::Blake3(blake3::Hasher::new())
            }
        };
        Ok(Self { inner })
    }

    /// Returns the algorithm this hasher was created with.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        match &self.inner {
            #[cfg(feature = "sha2")]
            HasherInner::Sha256(_) => Algorithm::Sha256,
            #[cfg(feature = "sha2")]
            HasherInner::Sha384(_) => Algorithm::Sha384,
            #[cfg(feature = "sha2")]
            HasherInner::Sha512(_) => Algorithm::Sha512,
            #[cfg(feature = "sha3")]
            HasherInner::Sha3_256(_) => Algorithm::Sha3_256,
            #[cfg(feature = "sha3")]
            HasherInner::Sha3_384(_) => Algorithm::Sha3_384,
            #[cfg(feature = "sha3")]
            HasherInner::Sha3_512(_) => Algorithm::Sha3_512,
            #[cfg(feature = "blake3")]
            HasherInner::Blake3(_) => Algorithm::Blake3,
        }
    }

    /// Feeds bytes into the hasher state.
    pub fn update(&mut self, bytes: &[u8]) {
        match &mut self.inner {
            #[cfg(feature = "sha2")]
            HasherInner::Sha256(h) => h.update(bytes),
            #[cfg(feature = "sha2")]
            HasherInner::Sha384(h) => h.update(bytes),
            #[cfg(feature = "sha2")]
            HasherInner::Sha512(h) => h.update(bytes),
            #[cfg(feature = "sha3")]
            HasherInner::Sha3_256(h) => h.update(bytes),
            #[cfg(feature = "sha3")]
            HasherInner::Sha3_384(h) => h.update(bytes),
            #[cfg(feature = "sha3")]
            HasherInner::Sha3_512(h) => h.update(bytes),
            #[cfg(feature = "blake3")]
            HasherInner::Blake3(h) => {
                let _ = h.update(bytes);
            }
        }
    }

    /// Consumes the hasher and returns the digest bytes.
    #[must_use]
    pub fn finalize(self) -> Vec<u8> {
        match self.inner {
            #[cfg(feature = "sha2")]
            HasherInner::Sha256(h) => h.finalize().to_vec(),
            #[cfg(feature = "sha2")]
            HasherInner::Sha384(h) => h.finalize().to_vec(),
            #[cfg(feature = "sha2")]
            HasherInner::Sha512(h) => h.finalize().to_vec(),
            #[cfg(feature = "sha3")]
            HasherInner::Sha3_256(h) => h.finalize().to_vec(),
            #[cfg(feature = "sha3")]
            HasherInner::Sha3_384(h) => h.finalize().to_vec(),
            #[cfg(feature = "sha3")]
            HasherInner::Sha3_512(h) => h.finalize().to_vec(),
            #[cfg(feature = "blake3")]
            HasherInner::Blake3(h) => h.finalize().as_bytes().to_vec(),
        }
    }
}

/// Constant-time comparison of two byte slices.
///
/// Useful for MAC verification, content-hash comparison, or any other
/// place where a timing side-channel on a non-secret-but-sensitive
/// comparison would help an attacker.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}
