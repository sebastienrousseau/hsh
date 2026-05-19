// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Argument parsing for `hsh-cli`.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

/// `hsh` — password hashing on the command line.
#[derive(Debug, Parser)]
#[command(
    name = "hsh",
    version,
    about = "Enterprise password hashing for the command line.",
    long_about = None,
)]
pub(crate) struct Cli {
    /// Emit machine-readable JSON instead of plain text.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Hash a password and print the storable form to stdout.
    Hash(HashArgs),
    /// Verify a candidate password against a stored hash.
    Verify(VerifyArgs),
    /// Verify, then mint a fresh hash under the current policy.
    Rehash(RehashArgs),
    /// Pretty-print the algorithm + parameters of a stored hash.
    Inspect(InspectArgs),
    /// Calibrate KDF parameters to hit a wall-time target.
    Calibrate(CalibrateArgs),
    /// Emit shell-completion scripts for the named shell.
    Completions(CompletionsArgs),
}

/// Selectable preset policy.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub(crate) enum PresetPolicy {
    /// OWASP-2025 minimum (Argon2id, m=19456, t=2, p=1).
    #[default]
    Owasp,
    /// RFC 9106 §4 first-recommended (Argon2id, m=2^21, t=1, p=4).
    Rfc9106,
    /// Hardened FIPS profile (PBKDF2-HMAC-SHA-256, 600k iters,
    /// Backend::Fips140Required — requires a FIPS-capable build).
    Fips,
}

/// Algorithm tag accepted on the command line.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum AlgoArg {
    /// Argon2id — recommended default.
    Argon2id,
    /// Argon2i — verify-only for legacy hashes.
    Argon2i,
    /// Argon2d — exposed for completeness.
    Argon2d,
    /// Bcrypt — Blowfish-based KDF.
    Bcrypt,
    /// Scrypt — memory-hard KDF.
    Scrypt,
    /// PBKDF2-HMAC-SHA-256 — the only FIPS-validated path.
    Pbkdf2,
}

#[derive(Debug, Clone, clap::Args)]
pub(crate) struct HashArgs {
    /// Preset policy to apply. Defaults to OWASP-2025.
    #[arg(long, value_enum, default_value_t)]
    pub policy: PresetPolicy,
    /// Override the primary algorithm.
    #[arg(short, long, value_enum)]
    pub algorithm: Option<AlgoArg>,
    /// Password (insecure: leaves password in shell history).
    /// Omit and provide via stdin or `$HSH_PASSWORD` instead.
    #[arg(long, env = "HSH_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub(crate) struct VerifyArgs {
    /// Stored hash string (PHC / MCF / hsh-pepper:…).
    #[arg(short = 'H', long, env = "HSH_STORED")]
    pub stored: String,
    /// Preset policy to apply for rehash detection.
    #[arg(long, value_enum, default_value_t)]
    pub policy: PresetPolicy,
    /// Password (insecure: leaves password in shell history).
    #[arg(long, env = "HSH_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub(crate) struct RehashArgs {
    /// Stored hash string.
    #[arg(short = 'H', long, env = "HSH_STORED")]
    pub stored: String,
    /// Preset policy to mint the new hash under.
    #[arg(long, value_enum, default_value_t)]
    pub policy: PresetPolicy,
    /// Password (insecure).
    #[arg(long, env = "HSH_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub(crate) struct InspectArgs {
    /// Stored hash string to inspect.
    pub hash: String,
}

#[derive(Debug, Clone, clap::Args)]
pub(crate) struct CalibrateArgs {
    /// Algorithm to calibrate.
    #[arg(short, long, value_enum, default_value_t = AlgoArg::Argon2id)]
    pub algorithm: AlgoArg,
    /// Target wall-time per `hash` in milliseconds.
    #[arg(short = 't', long, default_value_t = 500)]
    pub target_ms: u32,
}

#[derive(Debug, Clone, clap::Args)]
pub(crate) struct CompletionsArgs {
    /// Shell to emit completions for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

impl Cli {
    /// Dispatches to the chosen subcommand.
    pub(crate) fn run(self) -> Result<()> {
        match self.command {
            Command::Hash(args) => {
                crate::commands::hash::run(args, self.json)
            }
            Command::Verify(args) => {
                crate::commands::verify::run(args, self.json)
            }
            Command::Rehash(args) => {
                crate::commands::rehash::run(args, self.json)
            }
            Command::Inspect(args) => {
                crate::commands::inspect::run(args, self.json)
            }
            Command::Calibrate(args) => {
                crate::commands::calibrate::run(args, self.json)
            }
            Command::Completions(args) => {
                crate::commands::completions::run(args)
            }
        }
    }
}
