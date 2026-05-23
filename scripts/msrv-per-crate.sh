#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# scripts/msrv-per-crate.sh — verify each workspace crate
# compiles cleanly against its declared `rust-version`.
#
# Workspace-wide `cargo +<msrv> check` only enforces the floor of
# the workspace root. With satellite crates that can declare higher
# floors (`hsh-cli` is 1.88 due to rpassword's let-chains; the
# libraries declare 1.75 for downstream consumability), the
# workspace check leaves drift undetected — a library adopting a
# 1.85-only feature wouldn't break the gate until a downstream user
# pinned to 1.75.
#
# This script walks each `crates/*/Cargo.toml`, reads its
# `rust-version` field, and runs `cargo +<msrv> check
# --manifest-path …` per crate. Fails on the first mismatch.
#
# Usage:
#   ./scripts/msrv-per-crate.sh             # check every crate
#   ./scripts/msrv-per-crate.sh hsh-cli     # check just one
#
# Run from the workspace root.

set -euo pipefail
IFS=$'\n\t'

ONLY="${1:-}"

mapfile -t MANIFESTS < <(
    for m in crates/*/Cargo.toml; do
        name=$(basename "$(dirname "$m")")
        if [[ -n "$ONLY" && "$name" != "$ONLY" ]]; then
            continue
        fi
        if grep -qE '^rust-version *=' "$m"; then
            echo "$m"
        fi
    done
)

if [[ ${#MANIFESTS[@]} -eq 0 ]]; then
    echo "no crates carry a rust-version field — nothing to check"
    exit 0
fi

declare -i FAILED=0

for m in "${MANIFESTS[@]}"; do
    name=$(basename "$(dirname "$m")")
    msrv=$(grep -E '^rust-version *=' "$m" | head -1 \
        | sed -E 's/rust-version *= *"([0-9.]+)".*/\1/')

    if [[ -z "$msrv" ]]; then
        echo "skip: $name — could not parse rust-version from $m"
        continue
    fi

    echo "==> $name @ Rust $msrv"

    # Install the toolchain if it isn't present. rustup is happy
    # to install profile=minimal in CI; locally we let the user
    # decide.
    if ! rustup toolchain list | grep -q "^${msrv}"; then
        echo "    installing toolchain ${msrv}…"
        rustup toolchain install "$msrv" --profile minimal
    fi

    # For library crates whose declared MSRV is below the workspace
    # effective floor (e.g. hsh / hsh-kms / hsh-digest declare 1.75
    # while hsh-cli forces the workspace to 1.88), we cannot load
    # the workspace at the lower toolchain. Check the crate in
    # isolation via --manifest-path.
    if ! cargo +"$msrv" check --locked --manifest-path "$m" \
        --no-default-features 2>&1 | tail -20
    then
        echo "FAIL: $name does not build under Rust $msrv (no-default-features)"
        FAILED+=1
    fi

    if ! cargo +"$msrv" check --locked --manifest-path "$m" \
        --all-features 2>&1 | tail -20
    then
        echo "FAIL: $name does not build under Rust $msrv (all-features)"
        FAILED+=1
    fi
done

if [[ $FAILED -gt 0 ]]; then
    echo
    echo "$FAILED crate(s) failed MSRV verification"
    exit 1
fi

echo
echo "✓ every crate builds at its declared rust-version"
