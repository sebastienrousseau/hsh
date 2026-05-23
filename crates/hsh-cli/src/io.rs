// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! I/O helpers — reading passwords safely and printing structured output.

use anyhow::{Context, Result};
use std::io::IsTerminal;

/// Resolves a password from (in order of preference):
///
/// 1. The `--password` flag / `$HSH_PASSWORD` env var, if supplied.
/// 2. A TTY prompt with no echo, if stdin is a terminal.
/// 3. The first line of stdin, if it isn't a terminal.
///
/// Trailing newlines are stripped.
pub(crate) fn resolve_password(
    supplied: Option<String>,
) -> Result<String> {
    if let Some(p) = supplied {
        return Ok(strip_trailing_newline(p));
    }
    if std::io::stdin().is_terminal() {
        let pw = rpassword::prompt_password("password: ")
            .context("reading password from terminal")?;
        return Ok(strip_trailing_newline(pw));
    }
    let mut buf = String::new();
    use std::io::BufRead;
    let _bytes_read = std::io::stdin()
        .lock()
        .read_line(&mut buf)
        .context("reading password from stdin")?;
    Ok(strip_trailing_newline(buf))
}

fn strip_trailing_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        let _ = s.pop();
        if s.ends_with('\r') {
            let _ = s.pop();
        }
    }
    s
}

/// Writes a structured result either as JSON or as a key-value plain
/// listing.
pub(crate) fn print_kv(
    json: bool,
    pairs: &[(&str, &serde_json::Value)],
) -> Result<()> {
    if json {
        let map: serde_json::Map<String, serde_json::Value> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).clone()))
            .collect();
        println!("{}", serde_json::to_string_pretty(&map)?);
    } else {
        for (k, v) in pairs {
            match v {
                serde_json::Value::String(s) => println!("{k}: {s}"),
                other => println!("{k}: {other}"),
            }
        }
    }
    Ok(())
}
