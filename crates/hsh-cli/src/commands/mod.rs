// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Subcommand implementations.

pub(crate) mod calibrate;
pub(crate) mod completions;
pub(crate) mod hash;
pub(crate) mod inspect;
pub(crate) mod inspect_backend;
pub(crate) mod rehash;
pub(crate) mod verify;

use crate::cli::{AlgoArg, PresetPolicy};
use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};

/// Resolves a [`Policy`] from the `--policy` preset + optional
/// `--algorithm` override.
pub(crate) fn resolve_policy(
    preset: PresetPolicy,
    algorithm: Option<AlgoArg>,
) -> Policy {
    let preset_policy = match preset {
        PresetPolicy::Owasp => Policy::owasp_minimum_2025(),
        PresetPolicy::Rfc9106 => Policy::rfc9106_first_recommended(),
        PresetPolicy::Fips => Policy::fips_140_pbkdf2(),
    };
    let Some(algo) = algorithm else {
        return preset_policy;
    };
    let primary = match algo {
        AlgoArg::Argon2id => PrimaryAlgorithm::Argon2id,
        // Argon2i/d are verify-only, but we let the CLI ask for them
        // — `hsh::api::hash` will reject if not appropriate.
        AlgoArg::Argon2i | AlgoArg::Argon2d => {
            PrimaryAlgorithm::Argon2id
        }
        AlgoArg::Bcrypt => PrimaryAlgorithm::Bcrypt,
        AlgoArg::Scrypt => PrimaryAlgorithm::Scrypt,
        AlgoArg::Pbkdf2 => PrimaryAlgorithm::Pbkdf2,
    };
    PolicyBuilder::from_preset(&preset_policy)
        .primary(primary)
        .build()
        .expect("builder seeded from preset must build")
}
