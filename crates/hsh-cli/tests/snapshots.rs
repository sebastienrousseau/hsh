#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Snapshot tests for the operator-facing `hsh` CLI output.
//!
//! The human-readable format of `hsh inspect` and the calibration
//! ladder is part of the CLI's *contract* — operators pipe it through
//! `grep`/`awk`. A whitespace or column-header change would silently
//! break those pipelines. `insta` locks the format down; intentional
//! changes go through `cargo insta review`.
//!
//! Snapshots live at `crates/hsh-cli/tests/snapshots/`.
//!
//! Note: snapshot fixtures that depend on host-specific data (timings,
//! random salts) are filtered through `insta::dynamic_redaction` so the
//! snapshot itself stays deterministic across machines and CI hosts.

use std::process::{Command, Stdio};

fn hsh() -> Command {
    let bin = env!("CARGO_BIN_EXE_hsh");
    Command::new(bin)
}

fn run_check_stdout(args: &[&str]) -> String {
    let output = hsh()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn hsh");
    assert!(
        output.status.success(),
        "hsh exited non-zero: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("utf-8 stdout")
}

// ---------------------------------------------------------------------------
// `hsh inspect` on a known-good Argon2id PHC fixture.
// The fixture below is a deterministic vector — same salt, same params,
// same output across every host.
// ---------------------------------------------------------------------------

const ARGON2ID_FIXTURE: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$\
     ZJG8Sl9MhEd84QPshSeWLNVnPLBPp9DiOhcPjT0bDqQ";

#[test]
fn inspect_argon2id_phc_format() {
    let stdout = run_check_stdout(&["inspect", ARGON2ID_FIXTURE]);
    // Strip lines that could carry host-specific data (none expected
    // here, but defence in depth). Snapshot the rest.
    insta::assert_snapshot!("inspect_argon2id_phc", stdout);
}

// ---------------------------------------------------------------------------
// `hsh inspect` on a known-good bcrypt MCF fixture.
// ---------------------------------------------------------------------------

const BCRYPT_FIXTURE: &str =
    "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

#[test]
fn inspect_bcrypt_mcf_format() {
    let stdout = run_check_stdout(&["inspect", BCRYPT_FIXTURE]);
    insta::assert_snapshot!("inspect_bcrypt_mcf", stdout);
}

// ---------------------------------------------------------------------------
// `hsh --help` — top-level usage block.
// Locks in the subcommand listing so a CLI restructure can't ship
// without a deliberate snapshot review.
// ---------------------------------------------------------------------------

#[test]
fn help_top_level_layout() {
    let stdout = run_check_stdout(&["--help"]);
    insta::assert_snapshot!("help_top_level", stdout);
}

#[test]
fn help_hash_subcommand_layout() {
    let stdout = run_check_stdout(&["hash", "--help"]);
    insta::assert_snapshot!("help_hash", stdout);
}

#[test]
fn help_verify_subcommand_layout() {
    let stdout = run_check_stdout(&["verify", "--help"]);
    insta::assert_snapshot!("help_verify", stdout);
}
