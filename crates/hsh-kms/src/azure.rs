// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Azure Key Vault pepper provider — **stub**.
//!
//! Symmetric in shape to [`crate::aws`]; the real implementation uses
//! `azure_security_keyvault`'s secret-get or key-unwrap operation.

use crate::{KeyVersion, LocalPepper, PepperError};

/// Options for the (future) Azure [`fetch_pepper`] call.
#[derive(Debug, Clone)]
pub struct FetchOpts {
    /// Key Vault URL (e.g. `https://myvault.vault.azure.net/`).
    pub vault_url: String,
    /// Name of the key / secret holding the pepper material.
    pub secret_name: String,
    /// Per-version blob references.
    pub versions: Vec<(KeyVersion, Vec<u8>)>,
    /// Which version to use for new hashes.
    pub current: KeyVersion,
}

/// Fetches pepper keys from Azure Key Vault. **Stub.**
///
/// # Errors
///
/// Currently always returns an error.
#[cfg(feature = "azure-key-vault")]
#[allow(clippy::missing_panics_doc, clippy::unused_async)]
pub async fn fetch_pepper(
    _opts: FetchOpts,
) -> Result<LocalPepper, PepperError> {
    Err(PepperError::Backend(
        "azure-key-vault fetch_pepper is not yet wired up (Phase 3 follow-up)".into(),
    ))
}
