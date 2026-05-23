# API stability contract

This document describes which `hsh` surfaces are committed to semver
and which are still evolving — read it before depending on anything
that isn't in the **stable** tier.

The v0.0.9 release is a **pre-1.0 stabilisation snapshot**. It
demonstrates the shape of the v1.0 surface; the actual stability
commitments below take effect when the v1.0.0 tag is pushed (target:
Phase 7 conclusion).

## Tiers

| Tier      | Meaning                                                     | Examples |
| --------- | ----------------------------------------------------------- | -------- |
| **Stable**    | Breaking changes require a major version bump.          | `hsh::api::hash`, `hsh::api::verify_and_upgrade`, `hsh::Policy::owasp_minimum_2025()` |
| **Unstable**  | May change in any minor release. Marked with `#[non_exhaustive]` or feature flag.       | Variant additions to `HashAlgorithm`, new presets, `crate::algorithms::*` low-level types |
| **Internal**  | Not part of the public API. `#[doc(hidden)]` or `pub(crate)`. | `verify_and_upgrade_inner`, `needs_rehash` |

## Per-crate commitments

### `hsh` (library)

| Surface | Tier |
| ------- | ---- |
| `hsh::api::hash` / `verify_and_upgrade` | **Stable** |
| `hsh::Policy` (preset constructors only) | **Stable** |
| `hsh::Outcome` | **Stable** |
| `hsh::Error` (top-level variants) | **Stable** |
| `hsh::Backend` | **Stable** |
| `hsh::PrimaryAlgorithm` | **Unstable** — `#[non_exhaustive]`. New variants may land in minor releases. |
| `hsh::policy::Policy` (struct literal) | **Unstable** — new fields may land. Use `Policy::owasp_minimum_2025()` / `..Default::default()` patterns. |
| `hsh::algorithms::*` low-level marker types | **Unstable** |
| `hsh::models::*` legacy v0.0.x API | **Deprecated** — slated for removal in v0.2.0 |

### `hsh-cli` (binary)

| Surface | Tier |
| ------- | ---- |
| Subcommand names + flags | **Stable** |
| Exit codes (0 / 1 / 2) | **Stable** |
| `--json` output schema | **Stable** |
| PHC / MCF / `hsh-pepper:` string formats | **Stable** |
| Plain-text output format | **Unstable** — may evolve for readability |

### `hsh-kms` (crate)

| Surface | Tier |
| ------- | ---- |
| `Pepper` trait | **Stable** |
| `LocalPepper` constructors | **Stable** |
| `KeyVersion` | **Stable** |
| `PepperError` (top-level variants) | **Stable** |
| Provider `FetchOpts` structs | **Unstable** — provider-specific options may grow |

### `hsh-digest` (crate)

| Surface | Tier |
| ------- | ---- |
| `Algorithm` enum (existing variants) | **Stable** |
| `Hasher` API | **Stable** |
| `hash()` / `constant_time_eq()` | **Stable** |
| Additional algorithm variants behind feature flags | **Unstable** — new variants may land |

## Feature flags

Feature additions are **never breaking**. Feature removals require a
major bump. Currently-declared marker features (`k12`, `ascon`,
`fips`) will keep their names; toggling them between "no-op" and
"functional" is **not** a breaking change.

## MSRV policy

- `hsh` (library): MSRV **1.75**. Bumps are minor-version events,
  announced one release in advance via a `Cargo.toml` warning.
- `hsh-cli` (binary): MSRV **1.85**. Bumps are minor-version events.
- `hsh-kms`, `hsh-digest`: track `hsh`'s MSRV.

## `#[non_exhaustive]` policy

Every public enum and most public structs in the workspace carry
`#[non_exhaustive]`. This means:

- Callers must not exhaustively match without a wildcard arm.
- Callers must not construct via struct literal without the
  `..Default::default()` spread (or equivalent).
- We can add variants / fields in **minor** releases without breaking
  the contract.

## Deprecation policy

Deprecated items carry `#[deprecated(since = "X.Y.Z", note = "…")]`
and remain functional for **at least one minor release** after
deprecation. Removal happens in the next major bump.

Current deprecations (as of v0.0.9):

- `hsh::models::hash::Hash::new_argon2i` — slated for removal in
  v0.2.0. Use `Hash::new_argon2id` or `hsh::api::hash` with
  `Policy::owasp_minimum_2025()`.

## Yanked-release policy

If a published version contains a vulnerability discovered
post-release, we `cargo yank` it within 24 hours of confirmation and
publish a patched version with the same minor (e.g. `0.1.7` is
patched by `0.1.8`, not `0.2.0`).

A `RUSTSEC-YYYY-NNNN` advisory is filed for any yanked release.

## Bumping semver

| Change | Bump |
| ------ | ---- |
| New `#[non_exhaustive]` variant | Minor |
| New `pub fn` / `pub struct` / `pub trait impl` | Minor |
| New feature flag | Minor |
| `#[deprecated]` annotation | Minor |
| Removing a `#[deprecated]` item | **Major** |
| Removing a public item that wasn't deprecated | **Major** (don't do this) |
| MSRV bump | Minor (with one-release warning) |
| Bug fix that changes observable behaviour | Patch + CHANGELOG note + explicit reasoning |
| Algorithm parameter default changes | **Major** (e.g. OWASP minimums shift) |

## How to track stability

- Every public item's rustdoc tags its tier ("Stable", "Unstable",
  "Internal") when the level differs from the page's surrounding
  context.
- The `#[non_exhaustive]` and `#[deprecated]` attributes are the
  machine-readable source of truth — `cargo public-api` is the
  recommended way to diff the public surface between releases.

## Questions

If a surface you depend on isn't tiered here, open a
[discussion](https://github.com/sebastienrousseau/hsh/discussions) so
we can clarify before you ship.
