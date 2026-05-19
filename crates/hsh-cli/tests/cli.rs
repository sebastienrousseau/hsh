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
    let stored = pipe_hash(
        "rehash pw",
        &["hash", "--algorithm", "scrypt"],
    );
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
    let stored = pipe_hash(
        "rehash pw",
        &["hash", "--algorithm", "scrypt"],
    );
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
    let stored = pipe_hash(
        "rehash json pw",
        &["hash", "--algorithm", "scrypt"],
    );
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

// ---------------------------------------------------------------------------
// `--json` form on every read subcommand to exercise the JSON branches.
// ---------------------------------------------------------------------------

#[test]
fn verify_json_output_is_well_formed() {
    let stored = pipe_hash(
        "verify json pw",
        &["hash", "--algorithm", "scrypt"],
    );
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
