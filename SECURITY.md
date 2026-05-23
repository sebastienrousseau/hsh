# Security Policy

## Supported versions

`hsh` is on the road from `0.0.x` to `1.0.0` — see the
[v0.0.9 milestone][ms]. While the crate is pre-1.0, only the latest
minor release receives security fixes. Once v1.0.0 ships, the
support window will follow the policy in
[`doc/API-STABILITY.md`](doc/API-STABILITY.md).

| Version       | Status                                            |
| ------------- | ------------------------------------------------- |
| **`0.0.9`**   | Active — receives security patches                |
| `< 0.0.9`     | Unsupported — please upgrade                      |

[ms]: https://github.com/sebastienrousseau/hsh/milestone/1

## Reporting a vulnerability

**Please do not file public issues for security reports.**

- **Preferred channel:** [GitHub private security advisory](https://github.com/sebastienrousseau/hsh/security/advisories/new).
- **Email fallback:** <sebastian.rousseau@gmail.com>, subject prefix `[hsh-security]`.
- Please include: affected version(s), a minimal reproducer, the
  impact you see, and any suggested remediation.

You should expect:

- **Acknowledgement within 48 hours.**
- For confirmed issues, a triage outcome within **7 days** and a
  patched release per the SLA below:

  | Severity | Patched release | Yank window |
  | -------- | --------------- | ----------- |
  | Critical / High | 72 hours       | 24 h        |
  | Medium          | 14 days        | n/a         |
  | Low             | Next scheduled release | n/a |

- **Public disclosure window of 90 days** (or sooner once a patched
  release ships) coordinated with the reporter.
- A `RUSTSEC-YYYY-NNNN` advisory filed for any yanked release.

## Scope

In scope:

- The `hsh`, `hsh-cli`, `hsh-kms`, and `hsh-digest` crates.
- Helper code under `crates/`, `scripts/`, `fuzz/`.
- The GitHub Actions workflows under `.github/workflows/` and the
  release artefacts they produce.
- The packaging templates under `pkg/`.

Out of scope:

- Vulnerabilities in upstream dependencies — please report directly
  to the upstream project. We pin / patch promptly once a fix exists.
- Misuse of the crate (e.g. running `api::hash` with attacker-chosen
  parameters that are deliberately weak).
- DoS from caller-chosen prohibitively-expensive parameters
  (Argon2id at `m = 2^31` is a legitimate operator choice).

## Threat model

### Defended in v0.0.9

- **Timing side-channels on verification.** Hash byte comparison
  uses `subtle::ConstantTimeEq` in every code path. The bcrypt
  verifier delegates to the `bcrypt` crate, which also uses
  `subtle`.
- **Memory residue.** Secret material (`hash`, `salt`, derived
  buffers, pepper keys) is zeroed on drop via
  `zeroize::ZeroizeOnDrop`. Setters explicitly zero the previous
  buffer before reassignment.
- **Bcrypt 72-byte truncation (CVE-2025-22228 class).** The bcrypt
  wrapper rejects inputs `> 72` bytes by default; longer inputs
  require an explicit `BcryptParams::with_prehash(Sha256)`.
- **Weak default parameters.** Scrypt defaults to OWASP-2025
  (`N = 2^17`). Argon2id defaults to OWASP-2025 (`m = 19 456 KiB`,
  `t = 2`, `p = 1`). PBKDF2 defaults to OWASP-2025
  (`iters = 600 000` for SHA-256).
- **Algorithm-drift exposure.** `api::verify_and_upgrade` returns
  `Outcome::Valid { needs_rehash: true }` whenever the stored
  algorithm or its parameters fall below the current `Policy`,
  signalling the caller to persist a fresh hash.
- **Pepper key compromise window.** When using `hsh-kms`'s pepper
  support, `KeyVersion` allows non-destructive rotation;
  `verify_and_upgrade` migrates old-versioned hashes on next
  successful login.
- **FIPS fail-open.** When `Backend::Fips140Required` is set and
  the build can't satisfy it, `api::hash` returns a typed error
  rather than silently falling back to non-FIPS crypto.
- **`#![forbid(unsafe_code)]`** workspace-wide (ADR-0006). Every
  `unsafe` block reachable from `hsh` lives in an audited upstream
  crate.

### Tracked as follow-ups

- **Real FIPS routing through `aws-lc-rs`.** The `fips` Cargo
  feature is a forward-compat marker today; the
  `hsh-backend-awslc` workspace member that flips
  `Backend::fips_available_in_build()` to `true` is gated on a
  reliable build environment for AWS-LC FIPS
  (see [`doc/FIPS.md`](doc/FIPS.md)).
- **Real KMS provider implementations.** The AWS / GCP / Azure /
  HashiCorp Vault `fetch_pepper` functions in `hsh-kms` are stubs;
  the trait shape is stable but the network calls are tracked as
  Phase 3 follow-ups.

## Supply chain

- **`#![forbid(unsafe_code)]`** workspace-wide (ADR-0006).
- `Cargo.lock` is committed.
- `cargo-deny` + `cargo-audit` on every PR and weekly cron via
  `.github/workflows/supply-chain.yml`.
- **SLSA L3** build-provenance attestation on every release via
  `actions/attest-build-provenance`.
- **Sigstore keyless signing** of every release artefact via
  `cosign sign-blob`.
- **SBOM** generated per release via `cargo-about` (NOTICE.md
  attached to the GitHub release).
- **OpenSSF Scorecard** rated weekly via
  `.github/workflows/scorecard.yml`; SARIF uploaded to
  code-scanning.
- **5 libfuzzer harnesses** under `fuzz/` run nightly via
  `.github/workflows/fuzz.yml` (10-minute budget per target).
- **Miri** runs per-PR (focused, 60-minute budget) and weekly
  (full sweep, 90-minute budget) via `.github/workflows/miri.yml`.
- **Pinned GitHub Actions** by SHA where the action ecosystem
  supports it; Dependabot updates the pins weekly.

## Commit signing

All maintainer commits are signed. PRs that cannot be verified
will be re-signed or rebased before merge.

## Coordinated disclosure

For embargoed advisories that need cross-project coordination
(e.g. an issue affecting both `hsh` and `aws-lc-rs`):

1. Reporter contacts us via the preferred channel above.
2. We coordinate with the relevant upstream maintainers and the
   reporter to set a public disclosure date.
3. The pre-staged release PR is merged + tagged + published + the
   advisory is filed all within one hour of the agreed embargo
   end.
