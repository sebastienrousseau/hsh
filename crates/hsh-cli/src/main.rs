// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `hsh` — command-line companion for the `hsh` library.
//!
//! Subcommands:
//!
//! - `hsh hash`        — hash a password (PBKDF2 / Argon2id / scrypt / bcrypt).
//! - `hsh verify`      — verify a password against a stored hash.
//! - `hsh rehash`      — verify + emit a fresh hash under the current policy.
//! - `hsh inspect`     — show the algorithm + parameters of a stored hash.
//! - `hsh calibrate`   — measure parameters that hit a target wall-time.
//! - `hsh completions` — emit shell-completion scripts.
//!
//! Passwords are read from stdin (or `$HSH_PASSWORD` for non-interactive
//! invocations). Never put a password on the command line.

#![forbid(unsafe_code)]

mod cli;
mod commands;
mod io;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    cli.run()
}
