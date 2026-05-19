// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Thin binary entry point that just delegates to [`hsh::run`].
//!
//! Phase 5 (#144) replaces this with a real `hsh-cli` crate exposing
//! `hash`, `verify`, `rehash`, `inspect`, and `calibrate` subcommands.

fn main() {
    if let Err(err) = hsh::run() {
        eprintln!("Error running hsh: {err}");
        std::process::exit(1);
    }
}
