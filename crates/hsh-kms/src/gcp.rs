// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Google Cloud KMS pepper provider — **stub**.
//!
//! Symmetric in shape to [`crate::aws`]; the real implementation uses
//! `gcloud-kms` (or `google-cloud-kms`) to decrypt versioned key
//! ciphertexts stored in app config.

use crate::{KeyVersion, LocalPepper, PepperError};

/// Options for the (future) GCP [`fetch_pepper`] call.
#[derive(Debug, Clone)]
pub struct FetchOpts {
    /// Fully-qualified GCP KMS resource name
    /// (`projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`).
    pub key_resource: String,
    /// Per-version encrypted blobs.
    pub versions: Vec<(KeyVersion, Vec<u8>)>,
    /// Which version to use for new hashes.
    pub current: KeyVersion,
}

/// Fetches pepper keys from GCP Cloud KMS. **Stub** — see
/// [`crate::aws::fetch_pepper`] for the rationale.
///
/// # Errors
///
/// Currently always returns an error.
#[cfg(feature = "gcp-kms")]
#[allow(clippy::missing_panics_doc, clippy::unused_async)]
pub async fn fetch_pepper(
    _opts: FetchOpts,
) -> Result<LocalPepper, PepperError> {
    Err(PepperError::Backend(
        "gcp-kms fetch_pepper is not yet wired up (Phase 3 follow-up)"
            .into(),
    ))
}
