# Pre-commit hooks

`hsh` ships with a recommended git pre-commit hook that mirrors the
fastest CI checks, so you catch fmt / clippy / test failures **before**
they hit CI.

## Quick install

From the repository root:

```sh
ln -s ../../scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The hook lives in `scripts/pre-commit.sh` (added by Phase 2) and runs:

1. `cargo fmt --all --check` — formatting must be clean.
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   on **changed crates only** (delta-aware to keep the hook fast).
3. `cargo test --workspace --lib` — unit tests only; integration and
   property tests are deferred to CI because they're slow.

## What the hook will *not* do

- It will not run Miri (requires nightly + miri component).
- It will not run fuzz (requires `cargo +nightly fuzz`).
- It will not run the property suite (~3 min wall-time even at
  fast_test_policy() params).
- It will not run `cargo-deny` or `cargo-audit` (those run on CI from
  `supply-chain.yml`).

If you want a richer pre-push hook, mirror the `make ci` target.

## Bypassing

Skipping the hook (e.g. for a WIP commit) is fine:

```sh
git commit --no-verify -m "wip: temporary checkpoint"
```

We sign-off, but never bypass, in `feat/*` PR-ready branches. CI will
still gate the merge.

## What about pre-push?

A pre-push hook that runs `make ci` (fmt + clippy + test + doc) takes
~2 minutes locally and is recommended for branches you're about to
open a PR from:

```sh
cat > .git/hooks/pre-push <<'EOF'
#!/usr/bin/env sh
set -e
make ci
EOF
chmod +x .git/hooks/pre-push
```

## CI parity

Whatever your hook does is a best-effort local mirror of CI. The
authoritative gates live in `.github/workflows/`:

- `ci.yml` — fmt / clippy / test / doc on every PR
- `miri.yml` — per-PR (focused) + weekly (full)
- `supply-chain.yml` — cargo-deny + cargo-audit on every dep change
- `scorecard.yml` — OpenSSF rating weekly
- `fuzz.yml` — nightly 10-minute per-target cron
- `release.yml` — tag-driven release with SLSA L3 + sigstore

If CI catches something the hook didn't, fix the hook so it doesn't
recur.
