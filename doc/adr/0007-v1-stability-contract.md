# ADR-0007 — v1.0 stability contract

- **Status:** Accepted
- **Date:** 2026-05-19
- **Deciders:** Sebastien Rousseau
- **Tracking issue:** [#146](https://github.com/sebastienrousseau/hsh/issues/146)

## Context

The v0.0.9 release closes the seven-phase enterprise-readiness
programme. The workspace is now four published crates (`hsh`,
`hsh-cli`, `hsh-kms`, `hsh-digest`) with ~165 tests, fuzz harnesses,
property tests, Miri coverage, SLSA L3 release signing, OpenSSF
Scorecard integration, and a dedicated security policy.

The question for Phase 7 is: **when do we cut v1.0.0, and what does
the v1.0 contract actually commit to?**

Pre-1.0 crates ship under the "anything can change in any release"
convention. That's appropriate for software still finding its shape.
The v0.0.9 work has explicitly *not* changed shape since Phase 1 —
the `Policy` / `Outcome` / `api::*` surface has been stable across
Phases 2 through 6. The remaining "this might still change" surfaces
are clearly tagged (low-level `algorithms::*`, provider-specific
`FetchOpts` structs, new `HashAlgorithm` variants under
`#[non_exhaustive]`).

A v1.0 commitment now is both **possible** (the API is stable in
practice) and **valuable** (downstream consumers — especially
enterprise ones — won't depend on a pre-1.0 crate).

## Decision

Cut **v1.0.0 immediately after a v0.0.9 release stabilisation
window** during which:

1. The published v0.0.9 crates absorb any post-merge bug reports.
2. The CI infrastructure (release.yml, scorecard.yml, fuzz.yml)
   runs at least one full week of nightly cycles against the v0.0.9
   tag, producing the first set of SLSA attestations / sigstore
   signatures / OpenSSF scores.
3. Any blockers surfaced are landed as v0.0.10 / v0.0.11.

When the window closes (target: **2026-07** — eight weeks after
v0.0.9 publish), the v1.0.0 release ships with the contract below.

### What v1.0 commits to

**Per crate, the surfaces tagged "Stable" in
[`doc/API-STABILITY.md`](../API-STABILITY.md) are frozen until v2.0.**
Specifically:

- `hsh::api::hash` and `hsh::api::verify_and_upgrade` signatures
  and return shapes.
- `Policy::owasp_minimum_2025`, `Policy::rfc9106_first_recommended`,
  `Policy::fips_140_pbkdf2` constructors and their parameter
  ladders.
- `Outcome` variants and helper methods.
- `Backend` enum variants.
- `hsh-cli` subcommand names, flag names, exit codes, and
  `--json` output schema.
- `hsh-kms::Pepper` trait shape and `LocalPepper` builder methods.
- `hsh-digest::Algorithm` (existing variants), `Hasher`, `hash()`,
  `constant_time_eq()`.
- PHC / MCF / `hsh-pepper:` storage formats.

### What v1.0 explicitly does NOT freeze

- `#[non_exhaustive]` enums and structs — new variants / fields land
  in minor releases.
- Internal items behind `#[doc(hidden)]` or `pub(crate)`.
- Plain-text CLI output format (the `--json` schema is stable; the
  human-readable text may improve).
- Provider-specific `FetchOpts` field layout (KMS provider APIs
  evolve).
- Feature-flag-gated experimental algorithms (`k12`, `ascon`).

### MSRV
- `hsh` library: 1.75 at v1.0; bumps are minor-version events,
  one-release warning window.
- `hsh-cli`: 1.85 at v1.0.

### Lockstep versioning

All four crates ship with the same version number. A v1.0.0 release
publishes `hsh@1.0.0` + `hsh-cli@1.0.0` + `hsh-kms@1.0.0` +
`hsh-digest@1.0.0` in a single coordinated push from `release.yml`.

This trades crate-by-crate independence for predictable
compatibility. Downstream consumers can pin a single version and
know all four crates work together.

### Yanked-release SLAs

- **Critical / High** vulnerability → patched release within
  72 hours; the bad version is `cargo yank`ed within 24 hours of
  confirmation.
- **Medium** → patched release within two weeks.
- **Low** → next scheduled release.

All yanks file a `RUSTSEC-YYYY-NNNN` advisory.

## Consequences

**Accepted trade-offs:**

- **Less flexibility post-1.0.** Once shipped, changes to the
  surfaces above require either a major bump (v2.0) or a careful
  `#[deprecated]` dance through a minor release. The v0.0.9
  shape isn't perfect, but it's been through enough phases to
  rule out the most obvious mis-designs.
- **Coordinated releases** make per-crate independent shipping
  impossible. We've traded that flexibility for predictability;
  consumers asked for it.
- **MSRV growth is gated by the slowest consumer** the maintainer
  is aware of. We poll bug reports for "I'm on Rust X" complaints
  before bumping.

**Benefits:**

- Enterprise consumers can pin `hsh = "1.x"` and be confident the
  shape won't change underneath them.
- Crates.io security audits (OSTIF etc.) are far more likely to
  accept a 1.0+ crate.
- We can advertise the OpenSSF Scorecard target (≥ 8.0) for the
  1.0 release.
- Downstream documentation (Stack Overflow, blog posts) becomes
  durable.

## Non-goals

- **Crate splits or merges** post-1.0. The four-crate shape is what
  ships in v1.0; reshuffling that requires a major bump.
- **A self-validating FIPS module.** The Phase 4 contract stays — we
  delegate to `aws-lc-rs` for actual validation.
- **Backwards compatibility with v0.0.x APIs that were never
  released to crates.io.** `hsh::models::hash::Hash::new_argon2i`
  and the legacy `Hash::from_string` 6-part format will be removed
  in v0.2.0 (pre-1.0); the v1.0 surface starts from `hsh::api::*`.

## Compliance

- Every `pub` item tagged in `doc/API-STABILITY.md` corresponds to
  what `cargo public-api` reports on the v1.0.0 tag. CI gates v1.x.y
  patch releases on no public-API diff (modulo additions and
  `#[deprecated]` annotations).
- The release pipeline (Phase 2's `release.yml`) emits SBOM + SLSA
  L3 attestation + sigstore signatures for every artefact.
- `RELEASE.md` documents the maintainer flow.

## References

- [`doc/API-STABILITY.md`](../API-STABILITY.md)
- [`doc/RELEASE.md`](../RELEASE.md)
- [Semantic Versioning 2.0.0](https://semver.org/)
- [`cargo public-api`](https://github.com/Enselic/cargo-public-api)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
