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
    # the failure-persistence file path; that requires
    # `-Zmiri-disable-isolation` (set in the calling workflow /
    # Makefile). We restrict the focused suite to the surface that
    # exercises the largest fraction of dependency `unsafe` blocks:
    # `test_api` (argon2 / scrypt / bcrypt verify), `test_pepper`
    # (hmac + sha2 + subtle round-trip), and `test_backend_policy`
    # (PHC parser + FIPS dispatch).
    cargo +nightly miri test \
        -p hsh \
        --test test_api \
        --test test_backend_policy \
        --test test_pepper --features pepper
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
