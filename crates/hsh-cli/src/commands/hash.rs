// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `hsh hash` — produce a storable hash from a password.

use anyhow::{Context, Result};

use crate::cli::HashArgs;
use crate::commands::resolve_policy;
use crate::io::{print_kv, resolve_password};

pub(crate) fn run(args: HashArgs, json: bool) -> Result<()> {
    let password = resolve_password(args.password)
        .context("resolving password")?;
    let policy = resolve_policy(args.policy, args.algorithm);

    let stored =
        hsh::api::hash(&policy, &password).context("hsh::api::hash")?;

    if json {
        print_kv(
            true,
            &[
                ("stored", &serde_json::Value::String(stored.clone())),
                (
                    "algorithm",
                    &serde_json::Value::String(format!(
                        "{:?}",
                        policy.primary
                    )),
                ),
            ],
        )?;
    } else {
        println!("{stored}");
    }
    Ok(())
}
