// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! HashiCorp Vault pepper provider — **stub**.
//!
//! The real implementation uses the `vaultrs` crate's Transit
//! `decrypt` endpoint against a Vault Transit engine that holds the
//! pepper key material.

use crate::{KeyVersion, LocalPepper, PepperError};

/// Options for the (future) Vault [`fetch_pepper`] call.
#[derive(Debug, Clone)]
pub struct FetchOpts {
    /// Vault address (e.g. `https://vault.internal:8200`).
    pub address: String,
    /// Transit engine mount path.
    pub mount: String,
    /// Transit key name.
    pub key_name: String,
    /// Per-version encrypted blobs.
    pub versions: Vec<(KeyVersion, String)>,
    /// Which version to use for new hashes.
    pub current: KeyVersion,
}

/// Fetches pepper keys from HashiCorp Vault Transit. **Stub.**
///
/// # Errors
///
/// Currently always returns an error.
#[cfg(feature = "hashicorp-vault")]
#[allow(clippy::missing_panics_doc, clippy::unused_async)]
pub async fn fetch_pepper(
    _opts: FetchOpts,
) -> Result<LocalPepper, PepperError> {
    Err(PepperError::Backend(
        "hashicorp-vault fetch_pepper is not yet wired up (Phase 3 follow-up)".into(),
    ))
}
