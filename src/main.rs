// Copyright © 2023-2024 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! This is the main entry point for the hsh application.
fn main() {
    // Call the `run()` function from the `Hash (HSH)` module.
    if let Err(err) = hsh::run() {
        eprintln!("Error running hsh: {}", err);
        std::process::exit(1);
    }
}
