#!/usr/bin/env sh
# scripts/miri.sh — Miri runner.
#
# Two modes:
#   focused   per-PR budget (fast — runs only the parser / verify paths)
#   full      weekly budget (every test that doesn't depend on getrandom)
#
# Miri needs nightly + the miri component:
#   rustup +nightly component add miri
#
# Exit codes:
#   0 — green
#   non-zero — Miri reported UB or the test failed

set -eu

MODE="${1:-focused}"

case "$MODE" in
focused)
    # test_properties uses proptest, which reads `current_dir()` for
    # the failure-persistence file path; that requires `-Zmiri-disable-isolation`
    # (set in the calling workflow / Makefile). Restrict the focused
    # suite to test_api, which is fast under Miri.
    cargo +nightly miri test \
        -p hsh \
        --test test_api \
        --test test_backend_policy
    ;;
full)
    # Full Miri sweep. Excludes tests that require getrandom or rely on
    # platform-specific syscalls Miri can't model.
    cargo +nightly miri test \
        -p hsh \
        --all-features \
        -- \
        --skip "test_main"
    ;;
*)
    echo "usage: $0 {focused|full}" >&2
    exit 2
    ;;
esac
