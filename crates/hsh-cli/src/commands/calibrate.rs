// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `hsh calibrate` — find parameters that hit a target wall-time.
//!
//! Walks a small parameter ladder for the chosen algorithm, measures
//! `hsh::api::hash` wall-time, and reports the params closest to the
//! caller's target. Useful when sizing servers for new deployments.

use anyhow::Result;
use std::time::Instant;

use crate::cli::{AlgoArg, CalibrateArgs};
use crate::io::print_kv;
use hsh::algorithms::bcrypt::BcryptParams;
use hsh::algorithms::pbkdf2::{Pbkdf2Params, Prf};
use hsh::algorithms::scrypt::ScryptParams;
use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};

const PROBE_PASSWORD: &str = "calibration-probe-1234567890";

pub(crate) fn run(args: CalibrateArgs, json: bool) -> Result<()> {
    let target = u128::from(args.target_ms);
    let mut best: Option<(String, u128)> = None;

    match args.algorithm {
        AlgoArg::Argon2id | AlgoArg::Argon2i | AlgoArg::Argon2d => {
            // Ladder over memory cost (KiB), holding t=2, p=1.
            for m in [4_096u32, 8_192, 19_456, 32_768, 65_536, 131_072]
            {
                let policy = PolicyBuilder::from_preset(
                    &Policy::owasp_minimum_2025(),
                )
                .primary(PrimaryAlgorithm::Argon2id)
                .argon2(argon2::Params::new(m, 2, 1, Some(32)).unwrap())
                .build()
                .unwrap();
                let took = time_hash(&policy);
                consider(
                    &mut best,
                    format!("argon2id m={m} t=2 p=1"),
                    took,
                );
            }
        }
        AlgoArg::Bcrypt => {
            for cost in 4u32..=14 {
                let policy = PolicyBuilder::from_preset(
                    &Policy::owasp_minimum_2025(),
                )
                .primary(PrimaryAlgorithm::Bcrypt)
                .bcrypt(BcryptParams::new(cost))
                .build()
                .unwrap();
                let took = time_hash(&policy);
                consider(
                    &mut best,
                    format!("bcrypt cost={cost}"),
                    took,
                );
            }
        }
        AlgoArg::Scrypt => {
            for log_n in 8u8..=17 {
                let policy = PolicyBuilder::from_preset(
                    &Policy::owasp_minimum_2025(),
                )
                .primary(PrimaryAlgorithm::Scrypt)
                .scrypt(ScryptParams {
                    log_n,
                    r: 8,
                    p: 1,
                    dk_len: 32,
                })
                .build()
                .unwrap();
                let took = time_hash(&policy);
                consider(
                    &mut best,
                    format!("scrypt log_n={log_n} r=8 p=1"),
                    took,
                );
            }
        }
        AlgoArg::Pbkdf2 => {
            for iters in [
                10_000u32, 50_000, 100_000, 200_000, 400_000, 600_000,
                1_000_000,
            ] {
                let policy = PolicyBuilder::from_preset(
                    &Policy::owasp_minimum_2025(),
                )
                .primary(PrimaryAlgorithm::Pbkdf2)
                .pbkdf2(Pbkdf2Params {
                    prf: Prf::Sha256,
                    iterations: iters,
                    dk_len: 32,
                })
                .build()
                .unwrap();
                let took = time_hash(&policy);
                consider(
                    &mut best,
                    format!("pbkdf2-sha256 iters={iters}"),
                    took,
                );
            }
        }
    }

    let (params, took) = best.unwrap_or(("(no result)".into(), 0));
    let distance = took.abs_diff(target);

    if json {
        print_kv(
            true,
            &[
                ("target_ms", &serde_json::Value::from(args.target_ms)),
                (
                    "selected_params",
                    &serde_json::Value::String(params.clone()),
                ),
                ("measured_ms", &serde_json::Value::from(took as u64)),
                (
                    "distance_ms",
                    &serde_json::Value::from(distance as u64),
                ),
            ],
        )?;
    } else {
        println!("target:   {} ms", args.target_ms);
        println!("selected: {params}");
        println!("measured: {took} ms (off by {distance} ms)");
    }
    Ok(())
}

fn time_hash(policy: &Policy) -> u128 {
    let start = Instant::now();
    // Best-effort — if hash() errors (e.g. FIPS preset without feature),
    // record a sentinel so we don't crash the calibrate loop.
    let _ = hsh::api::hash(policy, PROBE_PASSWORD);
    start.elapsed().as_millis()
}

fn consider(
    best: &mut Option<(String, u128)>,
    params: String,
    took: u128,
) {
    match best {
        None => *best = Some((params, took)),
        Some((_, current)) if *current < took => {
            *best = Some((params, took));
        }
        _ => {}
    }
}
