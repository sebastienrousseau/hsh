// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `hsh verify` — verify a candidate password against a stored hash.
//!
//! Exit codes:
//! - `0` — valid match.
//! - `1` — invalid (wrong password).
//! - `2` — error (malformed input, policy mismatch).

use std::process::ExitCode;

use anyhow::{Context, Result};

use crate::cli::VerifyArgs;
use crate::commands::resolve_policy;
use crate::io::{print_kv, resolve_password};

pub(crate) fn run(args: VerifyArgs, json: bool) -> Result<()> {
    let password = resolve_password(args.password)
        .context("resolving password")?;
    let policy = resolve_policy(args.policy, None);

    let outcome =
        hsh::api::verify_and_upgrade(&policy, &password, &args.stored)
            .context("hsh::api::verify_and_upgrade")?;

    let valid = outcome.is_valid();
    let needs_rehash = outcome.needs_rehash();
    let rehashed = outcome.into_rehashed();

    if json {
        let mut pairs: Vec<(&str, serde_json::Value)> = vec![
            ("valid", serde_json::Value::Bool(valid)),
            ("needs_rehash", serde_json::Value::Bool(needs_rehash)),
        ];
        if let Some(new_phc) = rehashed {
            pairs
                .push(("rehashed", serde_json::Value::String(new_phc)));
        }
        let kv: Vec<(&str, &serde_json::Value)> =
            pairs.iter().map(|(k, v)| (*k, v)).collect();
        print_kv(true, &kv)?;
    } else if valid {
        println!("valid");
        if let Some(new_phc) = rehashed {
            println!("needs_rehash: true");
            println!("rehashed: {new_phc}");
        }
    } else {
        println!("invalid");
    }

    // Convert to the process exit code the user will key off in shells.
    if !valid {
        std::process::exit(1);
    }
    Ok(())
}

#[allow(dead_code)]
fn _exit_marker() -> ExitCode {
    ExitCode::SUCCESS
}
