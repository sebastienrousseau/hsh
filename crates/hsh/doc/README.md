<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `hsh` deep-dive documentation

This directory holds long-form, contributor-facing documentation
for the `hsh` library crate. The two-line rule:

- **Reference / API docs** live inline in `src/` as `///` rustdoc
  and render at <https://docs.rs/hsh>. Don't duplicate them here.
- **Everything else** — architecture, mental model, recipes,
  error reference, migration playbooks — lives here.

For workspace-wide guidance (cross-crate architectural decisions,
release runbook, FIPS deployment, KMS integration), see the
top-level [`doc/`](../../../doc/) directory.

## What's in this folder

| File | Audience | Covers |
|---|---|---|
| [`architecture.md`](./architecture.md) | New contributors, advanced users | The mental model: how `Policy` drives dispatch, how `verify_and_upgrade` decides to rehash, how peppering wraps the inner PHC, what the `Backend` enum means |
| [`cookbook.md`](./cookbook.md) | Library users | Copy-paste recipes for common deployments — basic round-trip, legacy bcrypt migration, peppered + KMS, FIPS routing, custom parameters |
| [`internals.md`](./internals.md) | Library contributors | Module map, "where to make a change" matrix, dispatch flow, testing strategy |
| [`errors.md`](./errors.md) | Library users + contributors | Every `Error` variant with display prefix, when emitted, recovery guidance |

## What's NOT in this folder

| Looking for… | Read this instead |
|---|---|
| Quick-start tutorial | [`README.md`](../README.md) (crate-level) and [`GETTING_STARTED.md`](../../../GETTING_STARTED.md) (workspace) |
| API reference (every function, struct, enum) | <https://docs.rs/hsh> (auto-generated from `///` rustdoc) |
| Domain vocabulary (PHC / MCF / KDF / pepper / …) | [`GLOSSARY.md`](../../../GLOSSARY.md) |
| Architectural decisions across the workspace | [`doc/adr/`](../../../doc/adr/) |
| Per-symbol stability tier list | [`doc/API-STABILITY.md`](../../../doc/API-STABILITY.md) |
| FIPS 140-3 deployment playbook | [`doc/FIPS.md`](../../../doc/FIPS.md) |
| KMS-backed pepper deployment | [`doc/KMS-INTEGRATION.md`](../../../doc/KMS-INTEGRATION.md) |
| Migration from another password-hashing crate | [`doc/MIGRATION-from-*.md`](../../../doc/) |
| Comparison vs other crates | [`doc/COMPARISON.md`](../../../doc/COMPARISON.md) |
| Benchmark methodology / reproduction | [`doc/BENCHMARKS.md`](../../../doc/BENCHMARKS.md) |
| Vulnerability reporting | [`SECURITY.md`](../../../SECURITY.md) |
| Maintainer release runbook | [`doc/RELEASE.md`](../../../doc/RELEASE.md) |

## Contributor expectations

If you change a file in `src/`:

- **New public item?** Add `///` rustdoc with `# Errors` /
  `# Examples` sections. The `missing_docs = "deny"` workspace lint
  fails CI otherwise. If the change is non-obvious, also add a
  paragraph to `architecture.md` covering the *why*.
- **New error variant?** Update [`errors.md`](./errors.md) with the
  Display prefix, trigger conditions, and recovery guidance.
- **New algorithm wrapper?** Update [`internals.md`](./internals.md)'s
  module map and the dispatch flow diagram.
- **New recipe / common pattern?** Add it to [`cookbook.md`](./cookbook.md).

If you change a workspace-level invariant (FIPS contract, pepper
wire format, banned-crate list), you almost certainly want an ADR
under [`doc/adr/`](../../../doc/adr/) too — not a file here.
