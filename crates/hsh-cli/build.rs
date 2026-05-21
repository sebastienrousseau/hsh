// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Captures build provenance for `hsh inspect-backend`.
//!
//! Cargo exposes `TARGET` and `PROFILE` only to build scripts, so we
//! re-export them as compile-time env vars consumable via `env!()`.
//! `HSH_RUSTC_VERSION` is sniffed from `rustc -vV`.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTC");

    let target =
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=HSH_TARGET_TRIPLE={target}");

    let profile =
        std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=HSH_PROFILE={profile}");

    let rustc =
        std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let rustc_version = Command::new(&rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=HSH_RUSTC_VERSION={rustc_version}");
}
