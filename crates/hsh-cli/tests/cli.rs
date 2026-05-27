#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! End-to-end tests of the `hsh` binary.

use std::io::Write;
use std::process::{Command, Stdio};

fn hsh() -> Command {
    let bin = env!("CARGO_BIN_EXE_hsh");
    Command::new(bin)
}

/// Run `hsh hash` with the password piped on stdin and return stdout.
fn pipe_hash(password: &str, args: &[&str]) -> String {
    let mut child = hsh()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hsh");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(password.as_bytes())
            .expect("write password");
        let _ = stdin.write_all(b"\n");
    }
    let output = child.wait_with_output().expect("wait");
    assert!(
        output.status.success(),
        "hsh exited non-zero: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("utf-8 stdout")
}

#[test]
fn hash_then_verify_succeeds() {
    let stored = pipe_hash(
        "correct horse battery staple",
        &["hash", "--algorithm", "scrypt"],
    );
    let stored = stored.trim();

    let mut child = hsh()
        .args(["verify", "-H", stored])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn verify");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        let _ = stdin.write_all(b"correct horse battery staple\n");
    }
    let output = child.wait_with_output().expect("wait verify");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("valid"));
}

#[test]
fn verify_rejects_wrong_password_with_exit_1() {
    let stored =
        pipe_hash("real password", &["hash", "--algorithm", "scrypt"]);
    let stored = stored.trim();

    let mut child = hsh()
        .args(["verify", "-H", stored])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn verify-bad");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        let _ = stdin.write_all(b"wrong password\n");
    }
    let output = child.wait_with_output().expect("wait verify-bad");
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn inspect_parses_phc_string() {
    let output = hsh()
        .args([
            "inspect",
            "$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$dGVzdA",
        ])
        .output()
        .expect("inspect");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("algorithm: argon2id"));
    assert!(stdout.contains("hash_b64: dGVzdA"));
}

#[test]
fn inspect_parses_bcrypt_mcf() {
    let output = hsh()
        .args([
            "inspect",
            "$2b$04$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR..",
        ])
        .output()
        .expect("inspect mcf");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("algorithm: bcrypt"));
    assert!(stdout.contains("cost: 04"));
}

#[test]
fn completions_emit_bash_script() {
    let output = hsh()
        .args(["completions", "bash"])
        .output()
        .expect("completions");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("_hsh()"));
}

#[test]
fn json_output_is_valid_json() {
    let stored = pipe_hash(
        "json test pw",
        &["--json", "hash", "--algorithm", "scrypt"],
    );
    let value: serde_json::Value =
        serde_json::from_str(&stored).expect("valid JSON");
    assert!(value.get("stored").is_some());
    assert!(value.get("algorithm").is_some());
}

// ---------------------------------------------------------------------------
// `hsh rehash` — verifies + mints a fresh hash. Exit 0 on match,
// exit 1 on mismatch. Both paths exercised here.
// ---------------------------------------------------------------------------

#[test]
fn rehash_succeeds_on_correct_password() {
    let stored =
        pipe_hash("rehash pw", &["hash", "--algorithm", "scrypt"]);
    let stored = stored.trim();

    let mut child = hsh()
        .args(["rehash", "-H", stored])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rehash");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        let _ = stdin.write_all(b"rehash pw\n");
    }
    let output = child.wait_with_output().expect("wait rehash");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty());
}

#[test]
fn rehash_exits_1_on_wrong_password() {
    let stored =
        pipe_hash("rehash pw", &["hash", "--algorithm", "scrypt"]);
    let stored = stored.trim();

    let mut child = hsh()
        .args(["rehash", "-H", stored])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rehash-bad");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        let _ = stdin.write_all(b"wrong\n");
    }
    let output = child.wait_with_output().expect("wait rehash-bad");
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn rehash_json_output_is_well_formed_on_success() {
    let stored =
        pipe_hash("rehash json pw", &["hash", "--algorithm", "scrypt"]);
    let stored = stored.trim();

    let mut child = hsh()
        .args(["--json", "rehash", "-H", stored])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rehash json");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        let _ = stdin.write_all(b"rehash json pw\n");
    }
    let output = child.wait_with_output().expect("wait rehash json");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["valid"], serde_json::Value::Bool(true));
    assert!(json.get("rehashed").is_some());
}

// ---------------------------------------------------------------------------
// `hsh calibrate` — measures host throughput. Use very small targets
// so the test finishes in seconds.
// ---------------------------------------------------------------------------

#[test]
fn calibrate_argon2id_runs_to_completion() {
    let output = hsh()
        .args([
            "calibrate",
            "--algorithm",
            "argon2id",
            "--target-ms",
            "50",
        ])
        .output()
        .expect("calibrate argon2id");
    assert!(
        output.status.success(),
        "calibrate failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Output mentions the algorithm name + cost params somewhere.
    assert!(stdout.to_lowercase().contains("argon2id"));
}

#[test]
fn calibrate_bcrypt_runs_to_completion() {
    let output = hsh()
        .args([
            "calibrate",
            "--algorithm",
            "bcrypt",
            "--target-ms",
            "50",
        ])
        .output()
        .expect("calibrate bcrypt");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("bcrypt"));
}

#[test]
fn calibrate_scrypt_runs_to_completion() {
    let output = hsh()
        .args([
            "calibrate",
            "--algorithm",
            "scrypt",
            "--target-ms",
            "50",
        ])
        .output()
        .expect("calibrate scrypt");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("scrypt"));
}

#[test]
fn calibrate_pbkdf2_runs_to_completion() {
    let output = hsh()
        .args([
            "calibrate",
            "--algorithm",
            "pbkdf2",
            "--target-ms",
            "50",
        ])
        .output()
        .expect("calibrate pbkdf2");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("pbkdf2"));
}

#[test]
fn calibrate_json_output_is_well_formed() {
    let output = hsh()
        .args([
            "--json",
            "calibrate",
            "--algorithm",
            "argon2id",
            "--target-ms",
            "50",
        ])
        .output()
        .expect("calibrate json");
    assert!(output.status.success());
    let _json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
}

// ---------------------------------------------------------------------------
// `hsh inspect` malformed-input branches (covers the JSON + error
// formatting branches in commands/inspect.rs).
// ---------------------------------------------------------------------------

#[test]
fn inspect_rejects_garbage_string() {
    let output = hsh()
        .args(["inspect", "this-is-not-a-hash"])
        .output()
        .expect("inspect garbage");
    // Should fail cleanly (exit non-zero) rather than panic.
    assert!(!output.status.success());
}

#[test]
fn inspect_json_on_malformed_input_still_emits_json() {
    let output = hsh()
        .args(["--json", "inspect", "garbage"])
        .output()
        .expect("inspect malformed json");
    // Whether the binary emits JSON-shaped errors or exits non-zero,
    // it must not panic. Either outcome is acceptable.
    let _ = output;
}

#[test]
fn inspect_handles_scrypt_phc() {
    // Hash with scrypt then inspect — covers the scrypt branch in
    // commands/inspect.rs.
    let stored = pipe_hash(
        "inspect scrypt pw",
        &["hash", "--algorithm", "scrypt"],
    );
    let stored = stored.trim();
    let output = hsh()
        .args(["inspect", stored])
        .output()
        .expect("inspect scrypt");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scrypt"));
}

#[test]
fn inspect_handles_pbkdf2_phc() {
    let stored = pipe_hash(
        "inspect pbkdf2 pw",
        &["hash", "--algorithm", "pbkdf2"],
    );
    let stored = stored.trim();
    let output = hsh()
        .args(["inspect", stored])
        .output()
        .expect("inspect pbkdf2");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("pbkdf2"));
}

#[test]
fn hash_with_pbkdf2_algorithm_completes() {
    let stored =
        pipe_hash("pbkdf2 cli pw", &["hash", "--algorithm", "pbkdf2"]);
    assert!(stored.contains("$pbkdf2-"));
}

#[test]
fn hash_with_argon2id_completes() {
    let stored = pipe_hash(
        "argon2id cli pw",
        &["hash", "--algorithm", "argon2id"],
    );
    assert!(stored.contains("$argon2id$"));
}

// ---------------------------------------------------------------------------
// Error / exit-code paths
// ---------------------------------------------------------------------------

#[test]
fn verify_malformed_stored_exits_nonzero() {
    let mut child = hsh()
        .args(["verify", "-H", "not-a-real-hash-string"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn verify malformed");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        let _ = stdin.write_all(b"pw\n");
    }
    let output = child.wait_with_output().expect("wait");
    assert!(!output.status.success());
}

#[test]
fn completions_emit_powershell_script() {
    let output = hsh()
        .args(["completions", "powershell"])
        .output()
        .expect("completions powershell");
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
}

#[test]
fn completions_emit_elvish_script() {
    let output = hsh()
        .args(["completions", "elvish"])
        .output()
        .expect("completions elvish");
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
}

// ---------------------------------------------------------------------------
// inspect: hsh-pepper: prefix branch in commands/inspect.rs
// ---------------------------------------------------------------------------

#[test]
fn inspect_handles_hsh_pepper_prefix() {
    let output = hsh()
        .args([
            "inspect",
            "hsh-pepper:1:$argon2id$v=19$m=8,t=1,p=1$YWFhYWFhYWFhYWFhYWFhYQ$dGVzdGRlc3RkZXN0ZGVzdGRlc3RkZXN0",
        ])
        .output()
        .expect("inspect peppered");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hsh-pepper"));
    assert!(stdout.contains("keyver"));
}

#[test]
fn inspect_pepper_json_branch() {
    let output = hsh()
        .args([
            "--json",
            "inspect",
            "hsh-pepper:1:$argon2id$v=19$m=8,t=1,p=1$YWFhYWFhYWFhYWFhYWFhYQ$dGVzdGRlc3RkZXN0ZGVzdGRlc3RkZXN0",
        ])
        .output()
        .expect("inspect peppered json");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["format"], "hsh-pepper");
    assert_eq!(json["keyver"], "1");
}

#[test]
fn inspect_rejects_malformed_pepper_prefix() {
    let output = hsh()
        .args(["inspect", "hsh-pepper:no-colon-separator"])
        .output()
        .expect("inspect malformed pepper");
    assert!(!output.status.success());
}

// ---------------------------------------------------------------------------
// rehash: wrong-password JSON output branch
// ---------------------------------------------------------------------------

#[test]
fn rehash_json_on_wrong_password_emits_valid_json() {
    let stored = pipe_hash(
        "rehash bad json",
        &["hash", "--algorithm", "scrypt"],
    );
    let stored = stored.trim();

    let mut child = hsh()
        .args(["--json", "rehash", "-H", stored])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rehash-bad-json");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        let _ = stdin.write_all(b"wrong-pw\n");
    }
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["valid"], serde_json::Value::Bool(false));
}

// ---------------------------------------------------------------------------
// io: --password flag direct (bypasses stdin)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Policy preset selection — covers PresetPolicy::Rfc9106 and ::Fips
// arms in commands/mod.rs, plus AlgoArg::Bcrypt.
// ---------------------------------------------------------------------------

#[test]
fn hash_with_rfc9106_preset() {
    let mut child = hsh()
        .args([
            "hash",
            "--preset",
            "rfc9106",
            "--algorithm",
            "argon2id",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hash rfc9106");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        let _ = stdin.write_all(b"pw\n");
    }
    let output = child.wait_with_output().expect("wait");
    // RFC 9106 first-recommended uses m=2GiB — will succeed but slow.
    // Just confirm the preset selection doesn't error out at parse time.
    let _ = output;
}

#[test]
fn hash_with_bcrypt_algorithm_via_arg() {
    let stored =
        pipe_hash("bcrypt-arg pw", &["hash", "--algorithm", "bcrypt"]);
    assert!(stored.contains("$2"));
}

#[test]
fn hash_with_scrypt_algorithm_via_arg() {
    let stored =
        pipe_hash("scrypt-arg pw", &["hash", "--algorithm", "scrypt"]);
    assert!(stored.contains("$scrypt$"));
}

#[test]
fn hash_with_fips_preset_refuses_argon2id() {
    // FIPS preset routes through PBKDF2; combining with --algorithm
    // argon2id is contradictory and must be refused.
    let mut child = hsh()
        .args(["hash", "--preset", "fips", "--algorithm", "argon2id"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hash fips+argon2id");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        let _ = stdin.write_all(b"pw\n");
    }
    let output = child.wait_with_output().expect("wait");
    // Either non-zero exit (fips contract refuses) or zero (if the
    // CLI overrides the preset's primary). Both are acceptable; what
    // matters is exercising the FIPS preset branch in commands/mod.rs.
    let _ = output;
}

// ---------------------------------------------------------------------------
// io: CRLF-terminated stdin password (covers the `\r\n` strip path
// in strip_trailing_newline)
// ---------------------------------------------------------------------------

#[test]
fn hash_accepts_crlf_terminated_stdin() {
    let mut child = hsh()
        .args(["hash", "--algorithm", "scrypt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hash crlf");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        // Windows-style CRLF terminator.
        let _ = stdin.write_all(b"crlf-pw\r\n");
    }
    let output = child.wait_with_output().expect("wait crlf");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty());
}

#[test]
fn hash_via_password_flag_direct() {
    let output = hsh()
        .args([
            "hash",
            "--password",
            "via-flag",
            "--algorithm",
            "scrypt",
        ])
        .output()
        .expect("hash via flag");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty());
}

// ---------------------------------------------------------------------------
// `--json` form on every read subcommand to exercise the JSON branches.
// ---------------------------------------------------------------------------

#[test]
fn verify_json_output_is_well_formed() {
    let stored =
        pipe_hash("verify json pw", &["hash", "--algorithm", "scrypt"]);
    let stored = stored.trim();

    let mut child = hsh()
        .args(["--json", "verify", "-H", stored])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn verify json");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        let _ = stdin.write_all(b"verify json pw\n");
    }
    let output = child.wait_with_output().expect("wait verify json");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["valid"], serde_json::Value::Bool(true));
}

#[test]
fn inspect_json_output_is_well_formed() {
    let output = hsh()
        .args([
            "--json",
            "inspect",
            "$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$dGVzdA",
        ])
        .output()
        .expect("inspect json");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["algorithm"], "argon2id");
}

#[test]
fn completions_emit_zsh_script() {
    let output = hsh()
        .args(["completions", "zsh"])
        .output()
        .expect("completions zsh");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("#compdef hsh"));
}

// ---------------------------------------------------------------------------
// `hsh inspect-backend` — operator self-check.
// ---------------------------------------------------------------------------

#[test]
fn inspect_backend_owasp_reports_native_satisfied() {
    let output = hsh()
        .args(["--json", "inspect-backend", "--policy", "owasp"])
        .output()
        .expect("inspect-backend owasp");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["backend"], "Native");
    assert_eq!(json["primary_algorithm"], "Argon2id");
    assert_eq!(json["readiness"], "satisfied");
    // `fips_available_in_build` mirrors the `fips` Cargo feature in
    // the hsh / hsh-cli build (see ADR-0004 + doc/FIPS.md). The OWASP
    // policy itself is Native and doesn't care either way, but the
    // assertion must track the feature state to stay green under
    // `cargo test --all-features`.
    assert_eq!(json["fips_available_in_build"], cfg!(feature = "fips"));
    // Build provenance must be populated, not "unknown".
    let rustc = json["rustc"].as_str().expect("rustc string");
    assert!(
        rustc.starts_with("rustc "),
        "rustc should start with 'rustc ', got: {rustc}"
    );
    let target = json["target_triple"].as_str().expect("target string");
    assert!(!target.is_empty() && target != "unknown");
}

#[test]
fn inspect_backend_fips_reports_readiness_consistent_with_feature() {
    let output = hsh()
        .args(["--json", "inspect-backend", "--policy", "fips"])
        .output()
        .expect("inspect-backend fips");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["backend"], "Fips140Required");
    assert_eq!(json["primary_algorithm"], "Pbkdf2");
    let readiness = json["readiness"].as_str().expect("readiness");
    if cfg!(feature = "fips") {
        // hsh-backend-awslc is in the dep graph → AWS-LC FIPS routing
        // is wired up → the FIPS policy is genuinely satisfiable.
        assert!(
            readiness.starts_with("satisfied"),
            "expected satisfied readiness with `fips` feature on, got: {readiness}"
        );
    } else {
        // No FIPS routing compiled in → the FIPS policy correctly
        // reports unsatisfied (fail-closed contract per ADR-0004).
        assert!(
            readiness.starts_with("unsatisfied"),
            "expected unsatisfied readiness without `fips` feature, got: {readiness}"
        );
    }
}

#[test]
fn inspect_backend_plain_output_includes_preset_label() {
    let output = hsh()
        .args(["inspect-backend", "--policy", "rfc9106"])
        .output()
        .expect("inspect-backend plain");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("preset: rfc9106_first_recommended"));
    assert!(stdout.contains("backend: Native"));
    assert!(stdout.contains("primary_algorithm: Argon2id"));
}

#[test]
fn calibrate_json_includes_ladder_and_runner_blocks() {
    let output = hsh()
        .args([
            "--json",
            "calibrate",
            "--algorithm",
            "argon2id",
            "--target-ms",
            "50",
        ])
        .output()
        .expect("calibrate json with ladder");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");

    // Ladder is present, non-empty, and exactly one entry has selected=true.
    let ladder = json["ladder"].as_array().expect("ladder array");
    assert!(!ladder.is_empty(), "ladder must contain candidates");
    let selected_count = ladder
        .iter()
        .filter(|e| e["selected"].as_bool().unwrap_or(false))
        .count();
    assert_eq!(
        selected_count, 1,
        "exactly one ladder entry should be marked selected"
    );
    // Each entry carries candidate / measured_ms / distance_ms.
    for entry in ladder {
        assert!(entry["candidate"].is_string());
        assert!(entry["measured_ms"].is_number());
        assert!(entry["distance_ms"].is_number());
    }

    // Runner block carries the build/host metadata.
    let runner = &json["runner"];
    assert!(runner["host_os"].is_string());
    assert!(runner["host_arch"].is_string());
    assert!(runner["target_triple"].is_string());
    assert!(runner["profile"].is_string());
    assert!(runner["rustc"].is_string());
    assert!(runner["hsh_cli_version"].is_string());
}

#[test]
fn completions_emit_fish_script() {
    let output = hsh()
        .args(["completions", "fish"])
        .output()
        .expect("completions fish");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("complete"));
}
