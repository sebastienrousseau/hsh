#!/usr/bin/env sh
# scripts/pre-commit.sh — fast local mirror of the CI gates.
#
# Install:
#   ln -s ../../scripts/pre-commit.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Bypass for a WIP commit:
#   git commit --no-verify

set -eu

fail() {
    echo
    echo "pre-commit blocked: $1"
    echo
    exit 1
}

# 1. fmt
cargo fmt --all --check || fail "cargo fmt --check is dirty (run \`cargo fmt --all\`)"

# 2. clippy on the whole workspace — small enough that delta-detection
#    isn't worth the complexity yet.
cargo clippy --workspace --all-targets --all-features -- -D warnings \
    || fail "cargo clippy reported warnings"

# 3. unit tests only — integration + property suites are deferred to CI.
cargo test --workspace --lib \
    || fail "cargo test --lib failed"

echo "pre-commit: ok"
