#!/usr/bin/env sh
# scripts/parameter-calibration.sh — derive Argon2id params that hit a
# target wall-time (default 500 ms) on the current host.
#
# Implementation strategy:
#   1. Run a tiny calibration binary that hashes with a sweep of
#      memory-cost values at t=2,p=1.
#   2. Print the params that land closest to the target time.
#
# Phase 5 will turn this into a proper `hsh-cli calibrate` subcommand.
# For now it shells out to `cargo bench --bench benchmark -- --quick`
# and points the operator at the relevant lines.

set -eu

TARGET_MS="${TARGET_MS:-500}"

echo "[calibrate] target wall-time: ${TARGET_MS}ms"
echo "[calibrate] running quick bench against OWASP-2025 params..."
echo

cargo bench --bench benchmark \
    -- --quick \
    "hash_owasp_2025" \
    | tee /tmp/hsh-calibrate.log

echo
echo "[calibrate] full param sweep is not yet wired up — see"
echo "[calibrate] doc/PARAMETER-TUNING.md (Phase 5) for the manual ladder."
