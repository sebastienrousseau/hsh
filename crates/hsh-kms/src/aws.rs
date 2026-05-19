// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! AWS KMS pepper provider — **stub**.
//!
//! The real implementation calls `aws-sdk-kms`'s `Decrypt` operation
//! against a customer-managed CMK whose ciphertext blob is stored in
//! the application's config / secrets manager, returning a [`LocalPepper`]
//! snapshot. It is intentionally an out-of-band fetch so the hot
//! verify path stays sync and CPU-bound.
//!
//! ## Sketch of the intended API
//!
//! ```ignore
//! use aws_sdk_kms::Client;
//! use hsh_kms::aws::FetchOpts;
//!
//! let client = Client::new(&aws_config::load_from_env().await);
//! let pepper = hsh_kms::aws::fetch_pepper(&client, FetchOpts {
//!     key_id: "alias/hsh-pepper".into(),
//!     versions: vec![(KeyVersion::new(1), "<base64-ciphertext-v1>".into())],
//!     current: KeyVersion::new(1),
//! }).await?;
//!
//! let policy = Policy::owasp_minimum_2025().with_pepper(std::sync::Arc::new(pepper));
//! ```
//!
//! Tracked in [Phase 3 follow-up](https://github.com/sebastienrousseau/hsh/issues/142).

use crate::{KeyVersion, LocalPepper, PepperError};

/// Options for the (future) [`fetch_pepper`] call.
#[derive(Debug, Clone)]
pub struct FetchOpts {
    /// AWS KMS key ID or alias (e.g. `"alias/hsh-pepper"`).
    pub key_id: String,
    /// Each historical pepper version, encrypted with the CMK above.
    /// The fetcher decrypts each into the corresponding key version.
    pub versions: Vec<(KeyVersion, String)>,
    /// Which version to use for new hashes.
    pub current: KeyVersion,
}

/// Fetches pepper keys from AWS KMS and returns an in-memory snapshot.
///
/// **Stub.** Always returns [`PepperError::Backend`] today. Will be
/// wired up in a follow-up commit when the AWS integration tests can
/// run against a real account or `localstack`.
///
/// # Errors
///
/// Currently always returns an error.
#[cfg(feature = "aws-kms")]
#[allow(clippy::missing_panics_doc, clippy::unused_async)]
pub async fn fetch_pepper(
    _opts: FetchOpts,
) -> Result<LocalPepper, PepperError> {
    Err(PepperError::Backend(
        "aws-kms fetch_pepper is not yet wired up (Phase 3 follow-up)"
            .into(),
    ))
}
