// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `hsh inspect-backend` — show the effective crypto route for a preset.
//!
//! This is the operator-facing self-check: given the preset a service is
//! about to deploy under, what does the binary actually do? Answers:
//!
//! - Which [`Backend`] does the preset declare? (`Native` / `Fips140Required`)
//! - Can this build satisfy the declared backend? (i.e. is the `fips`
//!   feature compiled in *and* a validated backend wired through?)
//! - Which primary algorithm will new hashes be minted under?
//! - Is the `pepper` feature compiled in for this binary?
//! - Build provenance: hsh crate version, rustc version, target triple,
//!   profile (debug/release).
//!
//! [`Backend`]: hsh::Backend

use anyhow::{Context, Result};

use crate::cli::{InspectBackendArgs, PresetPolicy};
use crate::io::print_kv;
use hsh::policy::Policy;

const HSH_VERSION: &str = env!("CARGO_PKG_VERSION");
const TARGET_TRIPLE: &str = env!("HSH_TARGET_TRIPLE");
const PROFILE: &str = env!("HSH_PROFILE");
const RUSTC_VERSION: &str = env!("HSH_RUSTC_VERSION");

pub(crate) fn run(args: InspectBackendArgs, json: bool) -> Result<()> {
    let preset_name = match args.policy {
        PresetPolicy::Owasp => "owasp_minimum_2025",
        PresetPolicy::Rfc9106 => "rfc9106_first_recommended",
        PresetPolicy::Fips => "fips_140_pbkdf2",
    };
    let policy = match args.policy {
        PresetPolicy::Owasp => Policy::owasp_minimum_2025(),
        PresetPolicy::Rfc9106 => Policy::rfc9106_first_recommended(),
        PresetPolicy::Fips => Policy::fips_140_pbkdf2(),
    };

    let backend_label = if policy.backend().is_fips() {
        "Fips140Required"
    } else {
        "Native"
    };
    let primary = format!("{:?}", policy.primary());
    let fips_available = hsh::Backend::fips_available_in_build();
    let pepper_feature = cfg!(feature = "pepper");

    let satisfies = if policy.backend().is_fips() {
        // FIPS policy is satisfied iff a FIPS-capable build is present.
        fips_available
    } else {
        // Native is always satisfiable.
        true
    };
    let satisfies_label = if satisfies {
        "satisfied"
    } else {
        "unsatisfied (build cannot provide a FIPS-validated route)"
    };

    let pairs: Vec<(String, serde_json::Value)> = vec![
        ("preset".into(), preset_name.into()),
        ("backend".into(), backend_label.into()),
        ("primary_algorithm".into(), primary.into()),
        (
            "fips_available_in_build".into(),
            serde_json::Value::Bool(fips_available),
        ),
        (
            "pepper_feature_compiled".into(),
            serde_json::Value::Bool(pepper_feature),
        ),
        ("readiness".into(), satisfies_label.into()),
        ("hsh_cli_version".into(), HSH_VERSION.into()),
        ("rustc".into(), RUSTC_VERSION.into()),
        ("target_triple".into(), TARGET_TRIPLE.into()),
        ("profile".into(), PROFILE.into()),
    ];

    emit(json, &pairs).context("emit inspect-backend output")
}

fn emit(
    json: bool,
    pairs: &[(String, serde_json::Value)],
) -> Result<()> {
    let kv: Vec<(&str, &serde_json::Value)> =
        pairs.iter().map(|(k, v)| (k.as_str(), v)).collect();
    print_kv(json, &kv)
}
