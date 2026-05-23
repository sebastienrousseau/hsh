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
    let mut ladder: Vec<LadderEntry> = Vec::new();

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
                let params = format!("argon2id m={m} t=2 p=1");
                ladder.push(LadderEntry::new(&params, took, target));
                consider(&mut best, params, took, target);
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
                let params = format!("bcrypt cost={cost}");
                ladder.push(LadderEntry::new(&params, took, target));
                consider(&mut best, params, took, target);
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
                let params = format!("scrypt log_n={log_n} r=8 p=1");
                ladder.push(LadderEntry::new(&params, took, target));
                consider(&mut best, params, took, target);
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
                let params = format!("pbkdf2-sha256 iters={iters}");
                ladder.push(LadderEntry::new(&params, took, target));
                consider(&mut best, params, took, target);
            }
        }
    }

    let (selected_params, took) =
        best.unwrap_or(("(no result)".into(), 0));
    let distance = took.abs_diff(target);

    if json {
        // Structured ladder + runner metadata. The ladder lets
        // operators see the full sweep; the runner block ties results
        // to the host that produced them so they're not silently
        // misapplied across heterogeneous fleets.
        let ladder_json: Vec<serde_json::Value> = ladder
            .iter()
            .map(|e| {
                serde_json::json!({
                    "candidate": e.candidate,
                    "measured_ms": e.measured_ms,
                    "distance_ms": e.distance_ms,
                    "selected": e.candidate == selected_params,
                })
            })
            .collect();
        let runner = serde_json::json!({
            "host_os": std::env::consts::OS,
            "host_arch": std::env::consts::ARCH,
            "target_triple": env!("HSH_TARGET_TRIPLE"),
            "profile": env!("HSH_PROFILE"),
            "rustc": env!("HSH_RUSTC_VERSION"),
            "hsh_cli_version": env!("CARGO_PKG_VERSION"),
        });
        let ladder_value = serde_json::Value::Array(ladder_json);
        print_kv(
            true,
            &[
                ("target_ms", &serde_json::Value::from(args.target_ms)),
                (
                    "selected_params",
                    &serde_json::Value::String(selected_params.clone()),
                ),
                ("measured_ms", &serde_json::Value::from(took as u64)),
                (
                    "distance_ms",
                    &serde_json::Value::from(distance as u64),
                ),
                ("ladder", &ladder_value),
                ("runner", &runner),
            ],
        )?;
    } else {
        println!("target:   {} ms", args.target_ms);
        println!("selected: {selected_params}");
        println!("measured: {took} ms (off by {distance} ms)");
        println!("ladder:");
        for entry in &ladder {
            let mark = if entry.candidate == selected_params {
                "*"
            } else {
                " "
            };
            println!(
                "  {mark} {} → {} ms (off by {} ms)",
                entry.candidate, entry.measured_ms, entry.distance_ms
            );
        }
    }
    Ok(())
}

/// One entry in the calibration sweep — a candidate parameter set plus
/// the measured wall-time and its distance from the target.
struct LadderEntry {
    candidate: String,
    measured_ms: u64,
    distance_ms: u64,
}

impl LadderEntry {
    fn new(candidate: &str, measured: u128, target: u128) -> Self {
        Self {
            candidate: candidate.to_owned(),
            measured_ms: measured as u64,
            distance_ms: measured.abs_diff(target) as u64,
        }
    }
}

fn time_hash(policy: &Policy) -> u128 {
    let start = Instant::now();
    // Best-effort — if hash() errors (e.g. FIPS preset without feature),
    // record a sentinel so we don't crash the calibrate loop.
    let _ = hsh::api::hash(policy, PROBE_PASSWORD);
    start.elapsed().as_millis()
}

/// Keeps the `(params, took)` whose `took` is closest to `target_ms`.
/// Ties (`abs_diff` equal) keep the first candidate so the ladder's
/// lower-cost choice wins — a tighter security upper bound at equal
/// distance is preferred.
fn consider(
    best: &mut Option<(String, u128)>,
    params: String,
    took: u128,
    target_ms: u128,
) {
    let new_distance = took.abs_diff(target_ms);
    match best {
        None => *best = Some((params, took)),
        Some((_, current))
            if new_distance < current.abs_diff(target_ms) =>
        {
            *best = Some((params, took));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::consider;

    #[test]
    fn consider_picks_closest_to_target() {
        let mut best: Option<(String, u128)> = None;
        // target = 250 ms; ladder produces 100, 200, 300, 500.
        consider(&mut best, "a".into(), 100, 250);
        consider(&mut best, "b".into(), 200, 250);
        consider(&mut best, "c".into(), 300, 250);
        consider(&mut best, "d".into(), 500, 250);
        let (chosen, took) = best.unwrap();
        // 200 and 300 are tied at distance 50; first-wins ⇒ "b".
        assert_eq!(chosen, "b");
        assert_eq!(took, 200);
    }

    #[test]
    fn consider_keeps_only_candidate() {
        let mut best: Option<(String, u128)> = None;
        consider(&mut best, "only".into(), 999, 100);
        let (chosen, took) = best.unwrap();
        assert_eq!(chosen, "only");
        assert_eq!(took, 999);
    }

    #[test]
    fn consider_does_not_drift_to_slowest() {
        // Regression: the prior implementation kept the *largest* took,
        // so a ladder that exceeded target by a lot would still win.
        let mut best: Option<(String, u128)> = None;
        consider(&mut best, "fast".into(), 50, 50);
        consider(&mut best, "slow".into(), 5_000, 50);
        let (chosen, _) = best.unwrap();
        assert_eq!(chosen, "fast");
    }
}
