<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `hsh-cli` deep-dive documentation

Long-form documentation for the `hsh` command-line binary. The
two-line rule:

- **Inline `--help`** is the source of truth for flag-level
  reference — run `hsh <subcommand> --help` or see the rustdoc
  at <https://docs.rs/hsh-cli> for the same.
- **Everything else** — recipes, exit-code contract, deployment
  patterns — lives here.

## What's in this folder

| File | Audience | Covers |
|---|---|---|
| [`recipes.md`](./recipes.md) | Operators, CI authors | Shell pipeline patterns: hashing from stdin, exit-code contract under `&&` / `\|\|`, JSON output for `jq`, pre-commit hooks |
| [`internals.md`](./internals.md) | Contributors | Subcommand dispatch flow, password I/O contract, snapshot-test infrastructure |
| [`errors.md`](./errors.md) | Operators | Exit-code reference + common error symptoms with fixes |

## What's NOT in this folder

| Looking for… | Read this instead |
|---|---|
| `hsh --help` reference | `hsh --help` itself, or <https://docs.rs/hsh-cli> |
| Per-channel install instructions (Cargo / Homebrew / AUR / …) | [crate-level `README.md`](../README.md#install) |
| Library API (the underlying `hsh::api::hash` etc.) | [`crates/hsh/doc/`](../../hsh/doc/) |
| Architectural decisions | [`doc/adr/`](../../../doc/adr/) |
| Vulnerability reporting | [`SECURITY.md`](../../../SECURITY.md) |

## Contributor expectations

If you change a subcommand:

- **New flag?** Add `///` rustdoc on the clap derive struct + a
  matching `--help` snapshot fixture under `tests/snapshots/`. Run
  `cargo insta review` to accept the new snapshot.
- **Output format change?** Update the relevant snapshot fixture
  AND update [`recipes.md`](./recipes.md) if any documented
  pipeline pattern changes.
- **Exit code change?** Update [`errors.md`](./errors.md). Exit codes
  are tier-1 stable surface — operators rely on them.
- **New subcommand?** Update [`internals.md`](./internals.md)'s
  dispatch flow diagram + add a section to `recipes.md`.
