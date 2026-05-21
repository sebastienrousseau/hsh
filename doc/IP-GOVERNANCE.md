<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# IP, research, and standards governance

`hsh` implements widely-used cryptographic constructions
(salt + iterated KDFs, HMAC-based peppers, key versioning) under
open standards (RFC 9106, RFC 7914, RFC 8018). This document
captures the process this project uses to **stay aligned with open
standards** and **avoid drifting into vendor-specific patented
flows** as the standards and case-law landscape evolves.

It is *not* legal advice. Maintainers are not lawyers. The
checklist below exists so that, when a downstream consumer's
counsel asks "what is your IP-hygiene process?", the answer is
something concrete they can audit rather than "we hope it's fine."

## Governing principles

1. **Implement open standards verbatim.** Argon2 follows
   [RFC 9106][rfc9106]; scrypt follows [RFC 7914][rfc7914];
   PBKDF2 follows [RFC 8018 §5.2][rfc8018]; HMAC follows
   [RFC 2104][rfc2104]; key-versioning conventions follow
   [NIST SP 800-57 Part 1 Rev 5][sp800-57]. Don't invent novel
   constructions whose patentability is unclear; if a standard
   exists, ship the standard.
2. **Prefer RustCrypto upstreams over vendor SDKs.** The
   RustCrypto project's `argon2`, `scrypt`, `bcrypt`,
   `pbkdf2`, `hmac`, and `sha2` crates have a multi-year review
   history under the same open licences `hsh` uses, and inherit
   the standards-tracking discipline of the parent project. Vendor
   SDKs (cloud-KMS clients) are wrapped via thin traits
   (`hsh_kms::Pepper`) so the vendor surface is contained and
   replaceable.
3. **Document deviations.** Anywhere `hsh` does something the
   standards don't prescribe — the `hsh-pepper:<keyver>:<inner>`
   wrapper format, the `hsh-bcrypt-sha256:<mcf>` envelope from
   P0-2, the bespoke PBKDF2 PHC string format documented in
   [ADR-0004](adr/0004-fips-strategy.md) — the rationale and a
   pointer to the closest equivalent open prior art is recorded
   in an ADR.

[rfc9106]: https://www.rfc-editor.org/rfc/rfc9106
[rfc7914]: https://www.rfc-editor.org/rfc/rfc7914
[rfc8018]: https://www.rfc-editor.org/rfc/rfc8018
[rfc2104]: https://www.rfc-editor.org/rfc/rfc2104
[sp800-57]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf

## Patent watchlist (informational, **not** a clearance opinion)

The patents below have claims that *touch* the same problem space
as `hsh` (salt+pepper architectures, key-versioned credential
hardening, multi-KDF orchestration). They are listed here so that
release-time reviews can confirm `hsh`'s current implementation
continues to track open standards rather than the proprietary
flows these claims describe.

> **Important.** None of these entries asserts infringement and
> none assert non-infringement. Inclusion on this list is a
> *prompt to look*, not a conclusion. A downstream consumer
> commercialising `hsh` as part of a product MUST run their own
> freedom-to-operate analysis with counsel for their jurisdiction
> and product context.

| Patent / Application | Holder (assignee at publication) | Subject area | Why it's on the watchlist |
| --- | --- | --- | --- |
| **US 11,641,281 B2** ([Google Patents][p1641281]) | (see filing) | Credential validation / pepper-style secret layered with password hashing | Touches the salt+pepper composition pattern; verify open prior art (RFC 2104 HMAC + standard salting) covers `hsh`'s implementation. |
| **US 11,741,218 B2** ([Google Patents][p1741218]) | (see filing) | Key-versioning / rotation flows for credential systems | Touches the same problem the `KeyVersion` + `hsh-pepper:<keyver>:<inner>` wrapper solves; confirm NIST SP 800-57 Part 1 (and prior published implementations) cover the construction. |
| **US 9,454,661 B2** / **US 20150379270 A1** family ([Google Patents][p9454661]) | (see filing) | Multi-algorithm credential-store / migration | Touches the verify-then-auto-rehash pattern in `verify_and_upgrade`; confirm RFC 8018 + the publicly-documented Django / Devise / `password-auth` ecosystem cover the construction. |

[p1641281]: https://patents.google.com/patent/US11641281B2/en
[p1741218]: https://patents.google.com/patent/US11741218B2/en
[p9454661]: https://patents.google.com/patent/US20150379270A1/en

### How a maintainer uses this list

1. **At every major / minor release** (see [`RELEASE.md`](RELEASE.md)),
   re-check each row: has the patent's status changed (expired,
   reissued, litigated)? Is `hsh`'s implementation still
   demonstrably tracking the open standard rather than the
   proprietary flow? Record the finding in the release PR as a
   one-line note ("watchlist reviewed; no changes" is acceptable).
2. **When adding a substantively new construction** (a new wrapper
   format, a new pepper trait method, a new migration path),
   scan the watchlist before merging — does any claim
   *prima facie* read on the new behaviour? If yes, draft an ADR
   that pinpoints the open-standard equivalent, or pause and
   consult counsel before shipping.
3. **When a third party flags a claim** against `hsh` in an issue
   or downstream channel, add it to the watchlist and open an ADR
   to capture the analysis even if the claim is dismissed; the
   record matters for future reviewers.

## Annual standards review

`hsh`'s defaults and parameter ladders track external standards.
Those standards change. Once per calendar year, the maintainer
runs the following review and amends the affected crates / docs:

| Source | Cadence | What to check | Where it lands in `hsh` |
| --- | --- | --- | --- |
| **OWASP Password Storage Cheat Sheet** ([cheatsheetseries.owasp.org][owasp]) | annual | Minimum recommended Argon2id / scrypt / bcrypt / PBKDF2 parameters | `Policy::owasp_minimum_2025()` — rename + bump the preset when the year changes (keep the old preset as `#[deprecated]` for one release cycle) |
| **NIST SP 800-63** ([pages.nist.gov/800-63-4][nist63]) | major-rev cycle (≈ every 4–5 yrs) | Identity assurance levels, syncable-authenticator policy, AAL/IAL impact on password retention | README + `doc/PASSKEY-ERA.md` positioning |
| **NIST SP 800-132 / FIPS 140-3** ([nvlpubs.nist.gov][nist132], [csrc.nist.gov/projects/cmvp][cmvp]) | continuous | PBKDF2 validated modules; CMVP cert list for `aws-lc-rs` / OpenSSL FIPS / BoringSSL FIPS | [`FIPS.md`](FIPS.md) + the eventual `hsh-backend-awslc` crate |
| **FIDO Alliance Passkey Index** ([fidoalliance.org][fido-idx]) | annual (Q4) | Passkey eligibility / adoption trends informing the password-fallback positioning | `doc/PASSKEY-ERA.md` "2026 baseline" section — update the year + sources |
| **IETF CFRG / RustCrypto deprecations** ([github.com/RustCrypto][rc]) | continuous | Deprecation notices on upstream `argon2` / `scrypt` / `bcrypt` / `pbkdf2` crates; new CVE advisories on FFI-based competitors | `clippy.toml` `disallowed-methods` list + `deny.toml` `bans.deny` list |
| **RFC editor — KDF / hashing track** ([rfc-editor.org][rfc-ed]) | quarterly skim | New RFCs covering hashing primitives (e.g. RFC 9861 KangarooTwelve, NIST SP 800-232 Ascon) | `hsh-digest` roadmap |

[owasp]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[nist63]: https://pages.nist.gov/800-63-4/
[nist132]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-132.pdf
[cmvp]: https://csrc.nist.gov/projects/cryptographic-module-validation-program
[fido-idx]: https://fidoalliance.org/passkeys/
[rc]: https://github.com/RustCrypto/password-hashes
[rfc-ed]: https://www.rfc-editor.org/

### Annual review process

The review is a calendar event on the maintainer's January
schedule. The deliverables are:

1. **A single review-summary issue** opened against this repo with
   the label `governance/annual-review` and a body listing each
   row of the table above plus a "no change" or "change" verdict.
2. **An ADR per change** — if e.g. OWASP raises the Argon2id
   minimum from `m=19456, t=2, p=1` to a higher target, the
   resulting preset bump gets its own ADR alongside the
   `Policy` change.
3. **A README + COMPARISON refresh** so external readers see the
   review happened. The "Capabilities in v0.0.9" table in the
   top-level README should carry the date of the most recent
   review in a footer.

## Pre-commercialisation legal review checklist

For downstream consumers (and for the project itself, if it ever
takes commercial money) before releasing a product that embeds or
extends `hsh`:

- [ ] **License compatibility check.** `hsh` ships under
      MIT *or* Apache-2.0 at the consumer's choice. Confirm the
      consumer's product licence is compatible with both.
- [ ] **SBOM cross-reference.** `cargo about generate` produces
      `NOTICE.md` listing every transitive licence. Counsel
      verifies no incompatible licences leaked in (e.g.
      copyleft via a `[build-dependencies]` toolchain).
- [ ] **FTO (freedom-to-operate) analysis.** Run the patent
      watchlist above against the consumer's specific product
      claims and jurisdiction. `hsh` maintainers' "looks like the
      open standard" is a starting point, not a clearance.
- [ ] **Export-control review.** The product as a whole may carry
      export-control obligations (EAR / Wassenaar) that the
      `hsh` library on its own does not trigger. Confirm with
      trade counsel.
- [ ] **FIPS claim review.** If the product advertises FIPS
      compliance, confirm `Backend::Fips140Required` is wired
      *and* a validated runtime is present (the in-development
      `hsh-backend-awslc` crate, or an equivalent vendor module
      with a current CMVP certificate).
- [ ] **Vulnerability-disclosure clause.** The product's security
      contact must coordinate with `hsh`'s
      [`SECURITY.md`](../SECURITY.md) policy for upstream-bound
      reports.

## Ownership and audit trail

- **Watchlist owner**: the maintainer publishing the release.
- **Annual review owner**: the project lead listed in
  [`SUPPORT.md`](SUPPORT.md). Calendar entry: January of each
  year, with a one-month deadline.
- **Audit trail**: every change recorded as an ADR under
  [`doc/adr/`](adr/) and referenced from `CHANGELOG.md`.

See also the release-time wiring in
[`RELEASE.md`](RELEASE.md#governance-gate) — a release tag is not
pushed without the watchlist review one-liner recorded on the
release PR.
