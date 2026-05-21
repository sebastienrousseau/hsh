// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `hsh inspect` — show the algorithm + parameters of a stored hash.

use anyhow::Result;

use crate::cli::InspectArgs;
use crate::io::print_kv;

pub(crate) fn run(args: InspectArgs, json: bool) -> Result<()> {
    let s = args.hash.trim();

    // hsh-pepper: prefix
    if let Some(rest) = s.strip_prefix("hsh-pepper:") {
        let (keyver, inner) =
            rest.split_once(':').ok_or_else(|| {
                anyhow::anyhow!("malformed pepper prefix")
            })?;
        let pairs: Vec<(String, serde_json::Value)> = vec![
            ("format".into(), "hsh-pepper".into()),
            ("keyver".into(), keyver.into()),
            ("inner".into(), inner.into()),
        ];
        emit(json, &pairs)?;
        return Ok(());
    }

    // hsh-bcrypt-sha256: envelope — bcrypt with HMAC-SHA-256 pre-hash.
    if let Some(rest) = s.strip_prefix("hsh-bcrypt-sha256:") {
        let mut pairs: Vec<(String, serde_json::Value)> = vec![
            ("format".into(), "hsh-bcrypt-sha256".into()),
            ("algorithm".into(), "bcrypt".into()),
            ("prehash".into(), "hmac-sha256".into()),
            ("inner".into(), rest.into()),
        ];
        if let Some(cost) = rest.split('$').nth(2) {
            pairs.push(("cost".into(), cost.into()));
        }
        emit(json, &pairs)?;
        return Ok(());
    }

    // Bcrypt MCF
    if s.starts_with("$2a$")
        || s.starts_with("$2b$")
        || s.starts_with("$2x$")
        || s.starts_with("$2y$")
    {
        let mut pairs: Vec<(String, serde_json::Value)> = vec![
            ("format".into(), "bcrypt-mcf".into()),
            ("algorithm".into(), "bcrypt".into()),
        ];
        if let Some(cost) = s.split('$').nth(2) {
            pairs.push(("cost".into(), cost.into()));
        }
        emit(json, &pairs)?;
        return Ok(());
    }

    // PHC string: $<algo>[$<k=v,k=v>...]
    if let Some(rest) = s.strip_prefix('$') {
        let segments: Vec<&str> = rest.split('$').collect();
        if let Some(algo) = segments.first() {
            let mut pairs: Vec<(String, serde_json::Value)> = vec![
                ("format".into(), "phc".into()),
                ("algorithm".into(), (*algo).into()),
            ];
            // Subsequent segments are either "k=v,k=v,..." params,
            // bare salt, or bare hash. We don't try to be exhaustive —
            // just surface the structural breakdown.
            for (idx, seg) in segments.iter().enumerate().skip(1) {
                if seg.contains('=') {
                    pairs.push((
                        format!("params[{idx}]"),
                        (*seg).into(),
                    ));
                } else if idx == segments.len() - 1 {
                    pairs.push(("hash_b64".into(), (*seg).into()));
                } else {
                    pairs.push((
                        format!("segment[{idx}]"),
                        (*seg).into(),
                    ));
                }
            }
            emit(json, &pairs)?;
            return Ok(());
        }
    }

    anyhow::bail!("unrecognised hash string format");
}

fn emit(
    json: bool,
    pairs: &[(String, serde_json::Value)],
) -> Result<()> {
    let kv: Vec<(&str, &serde_json::Value)> =
        pairs.iter().map(|(k, v)| (k.as_str(), v)).collect();
    print_kv(json, &kv)
}
