#!/usr/bin/env sh
# scripts/coverage-gap-report.sh — surface the lines in the codebase
# that no test currently touches.
#
# Requires:
#   cargo install cargo-llvm-cov
#   rustup +stable component add llvm-tools-preview
#
# Output:
#   - lcov.info               machine-readable
#   - target/llvm-cov/html/   browsable
#   - stdout                  human summary of files < 80% line coverage

set -eu

THRESHOLD="${THRESHOLD:-80}"

echo "[coverage] running cargo llvm-cov on workspace..."
cargo llvm-cov \
    --workspace \
    --all-features \
    --lcov --output-path lcov.info \
    --html

echo
echo "[coverage] files below ${THRESHOLD}% line coverage:"
echo

awk -v threshold="$THRESHOLD" '
/^SF:/ { file=$0; sub("SF:", "", file); covered=0; total=0; next }
/^DA:[0-9]+,[1-9]/ { covered++; total++; next }
/^DA:[0-9]+,0$/ { total++; next }
/^end_of_record/ {
    if (total > 0) {
        pct = (covered * 100) / total
        if (pct < threshold) {
            printf "  %6.2f%%  %s\n", pct, file
        }
    }
}
' lcov.info | sort -n

echo
echo "[coverage] full HTML report: target/llvm-cov/html/index.html"
