// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The main function of the build script.
//!
//! This function is executed when building the crate and performs certain tasks
//! necessary for the build process.
//!
//! It prints a "cargo:rerun-if-changed" directive to indicate that the build
//! should be re-run if the "build.rs" file is changed.
fn main() {
    // println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=build.rs");
}
