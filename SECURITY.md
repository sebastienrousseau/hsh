# Security Policy

## Supported versions

`hsh` is on the road from `0.0.x` to `1.0.0` — see the [v0.0.9 milestone][ms].
While the crate is pre-1.0, only the latest release receives security fixes.

| Version  | Status                                               |
| -------- | ---------------------------------------------------- |
| `0.0.9`  | Active — receives security patches                   |
| `< 0.0.9`| Unsupported — please upgrade                         |

[ms]: https://github.com/sebastienrousseau/hsh/milestone/1

## Reporting a vulnerability

**Please do not file public issues for security reports.**

- **Preferred channel:** [GitHub private security advisory](https://github.com/sebastienrousseau/hsh/security/advisories/new).
- **Email fallback:** <sebastian.rousseau@gmail.com>, subject prefix `[hsh-security]`.
- Please include: affected version(s), a minimal reproducer, the impact you
  see, and any suggested remediation.

You should expect:

- An **acknowledgement within 48 hours**.
- A **fix or status update within 14 days** for confirmed issues; longer
  windows only for issues that require upstream coordination
  (e.g. RustCrypto, `bcrypt`, `aws-lc-rs`).
- A **public disclosure window of 90 days** (or sooner once a patched release
  ships) coordinated with the reporter.

## Scope

In scope:

- The `hsh` crate and its workspace members.
- Any helper code under `crates/`, `scripts/`, `fuzz/`.
- The GitHub Actions workflows and release artefacts.

Out of scope:

- Vulnerabilities in upstream dependencies — please report directly to
  the upstream project. We will pin or patch promptly once a fix exists.
- Misuse of the crate (e.g. running `Hash::new` on a 4-character password —
  the crate already returns `Error::InvalidPassword` here).
- DoS from arbitrarily expensive parameters chosen by the **caller**.

## Threat model summary

`hsh` defends against:

- **Timing side-channels on verification.** Hash byte comparison uses
  `subtle::ConstantTimeEq`. The bcrypt path delegates to the `bcrypt` crate
  which also uses `subtle`.
- **Memory residue.** Secret material (`hash`, `salt`, derived buffers) is
  zeroed on drop via `zeroize::ZeroizeOnDrop`. `set_hash` / `set_salt`
  zeroize the previous buffer before reassignment.
- **Mis-configured algorithms.** `Hash::new` rejects passwords shorter than
  8 characters and unknown algorithm strings.

`hsh` **does not yet** defend against — and these are tracked work items:

- **Bcrypt 72-byte input truncation.** Today the wrapper relies on the
  underlying `bcrypt` crate's silent truncation. Issue [#158][i158] adds an
  explicit reject-or-pre-hash policy in v0.1.0.
- **Weak scrypt params.** Today scrypt uses `N=2^14, r=8, p=1` — below the
  OWASP-2025 minimum of `N=2^17`. Issue [#157][i157] makes parameters
  configurable and updates the default.
- **Algorithm agility / auto-rehash.** PHC string format adoption and
  `verify_and_upgrade()` are tracked under issues [#159][i159] and
  [#160][i160].
- **FIPS compliance.** The crate is not FIPS-validated. Issue [#143][i143]
  adds an optional `aws-lc-rs` backend for SHA-2 / PBKDF2 paths.

[i157]: https://github.com/sebastienrousseau/hsh/issues/157
[i158]: https://github.com/sebastienrousseau/hsh/issues/158
[i159]: https://github.com/sebastienrousseau/hsh/issues/159
[i160]: https://github.com/sebastienrousseau/hsh/issues/160
[i143]: https://github.com/sebastienrousseau/hsh/issues/143

## Supply chain

- Workspace-wide `#![forbid(unsafe_code)]` (see ADR-0006).
- `Cargo.lock` is committed.
- Phase 2 (issue [#141][i141]) adds `cargo-deny`, `cargo-audit`,
  `cargo-about` SBOM, OpenSSF Scorecard, and SLSA L3 build provenance with
  keyless sigstore signing on every tagged release.

[i141]: https://github.com/sebastienrousseau/hsh/issues/141

## Commit signing

All maintainer commits are signed. PRs that cannot be verified will be
re-signed or rebased before merge.
