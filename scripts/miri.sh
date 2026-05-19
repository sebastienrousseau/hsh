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
    cargo +nightly miri test \
        -p hsh \
        --test test_properties \
        --test test_api \
        -- \
        --skip "scrypt_round_trip_holds" \
        --skip "bcrypt_round_trip_holds"
    ;;
full)
    # Full Miri sweep. Excludes tests that require getrandom or rely on
    # platform-specific syscalls Miri can't model.
    MIRIFLAGS="-Zmiri-strict-provenance" cargo +nightly miri test \
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
