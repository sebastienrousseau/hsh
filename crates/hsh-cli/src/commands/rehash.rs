// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `hsh rehash` — verify + mint a fresh hash under the current policy.

use anyhow::{Context, Result};

use crate::cli::RehashArgs;
use crate::commands::resolve_policy;
use crate::io::{print_kv, resolve_password};

pub(crate) fn run(args: RehashArgs, json: bool) -> Result<()> {
    let password = resolve_password(args.password)
        .context("resolving password")?;
    let policy = resolve_policy(args.policy, None);

    let outcome =
        hsh::api::verify_and_upgrade(&policy, &password, &args.stored)
            .context("hsh::api::verify_and_upgrade")?;

    let valid = outcome.is_valid();
    let rehashed = outcome.into_rehashed();

    if !valid {
        if json {
            print_kv(
                true,
                &[
                    ("valid", &serde_json::Value::Bool(false)),
                    ("rehashed", &serde_json::Value::Null),
                ],
            )?;
        } else {
            println!("invalid");
        }
        std::process::exit(1);
    }

    // Always mint a fresh hash, even if needs_rehash was false.
    let new_phc = rehashed
        .map(Ok)
        .unwrap_or_else(|| hsh::api::hash(&policy, &password))
        .context("hsh::api::hash")?;

    if json {
        print_kv(
            true,
            &[
                ("valid", &serde_json::Value::Bool(true)),
                (
                    "rehashed",
                    &serde_json::Value::String(new_phc.clone()),
                ),
            ],
        )?;
    } else {
        println!("{new_phc}");
    }
    Ok(())
}
