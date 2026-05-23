# Getting help with `hsh`

## Where to ask

| Channel                                                                                   | Use for                                                                |
| ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| [GitHub Discussions](https://github.com/sebastienrousseau/hsh/discussions)                | Open-ended questions, design feedback, "how do I…" requests            |
| [GitHub Issues](https://github.com/sebastienrousseau/hsh/issues)                          | Confirmed bugs, missing features, documentation defects                |
| [GitHub Security Advisories](https://github.com/sebastienrousseau/hsh/security/advisories) | **Vulnerability reports — private channel.** See [`SECURITY.md`](../SECURITY.md). |
| [docs.rs/hsh](https://docs.rs/hsh)                                                        | Rendered rustdoc for the latest release                                |
| [crates.io/crates/hsh](https://crates.io/crates/hsh)                                      | Version index, download stats                                          |

## Response windows

These are best-effort commitments from a small maintainer team —
they're not contractual SLAs, but they're what we aim for.

| Issue type                         | First response | Resolution target |
| ---------------------------------- | -------------- | ----------------- |
| Security vulnerability             | 48 hours       | 14 days for confirmed issues |
| Critical bug (data loss / panic)   | 72 hours       | Next patch release |
| Standard bug                       | 1 week         | Next minor release |
| Feature request                    | 1 week         | Triaged into a phase / roadmap milestone |
| Documentation defect               | 1 week         | Next minor release |
| Discussion / question              | Best-effort    | n/a |

If a confirmed security issue stalls (e.g. needs upstream
coordination with RustCrypto or `aws-lc-rs`), the
[`SECURITY.md`](../SECURITY.md) disclosure timer pauses with explicit
ack to the reporter.

## What to include in a bug report

Cuts the resolution time in half. A good report has:

1. **Version** — `cargo tree | grep hsh` output. We don't support
   versions older than the most recent minor release.
2. **Minimal reproducer** — a code snippet that triggers the issue.
3. **Expected vs actual behaviour**.
4. **Platform** — `rustc --version`, `uname -a` on Linux/macOS,
   Windows version + arch.
5. **Cargo features enabled** — `pepper`, `fips`, etc.

For panics, include the full backtrace
(`RUST_BACKTRACE=1 cargo test ...`).

## What we can't help with

- **General Rust / cargo questions.** Use
  [users.rust-lang.org](https://users.rust-lang.org) or
  [r/rust](https://reddit.com/r/rust).
- **Cryptographic design review of your application.** `hsh`
  provides primitives + safe defaults; the threat model of *your*
  app is outside our scope. Engage a crypto auditor if the stakes
  are high.
- **Free integration consulting for closed-source enterprise
  deployments.** Open an issue if you need a feature; we'll triage
  it. We don't currently offer paid support contracts.

## Useful starting points

- **"How do I store user passwords?"** →
  [`README.md#usage`](../README.md#usage), then
  [`doc/KMS-INTEGRATION.md`](KMS-INTEGRATION.md) for peppered
  storage.
- **"How do I migrate from bcrypt / argonautica / rust-argon2 / etc.?"**
  → The `doc/MIGRATION-from-*.md` family.
- **"Can I use this for FIPS?"** →
  [`doc/FIPS.md`](FIPS.md) explains what's wired today.
- **"Is parameter X tuneable?"** → Yes — every Argon2 / bcrypt /
  scrypt / PBKDF2 parameter is exposed via `PolicyBuilder`. For
  sizing on real hardware, use `hsh calibrate --algorithm <algo>
  --target-ms <budget>` and persist the selected params via the
  builder. See the runbook in [`OPERATIONS.md`](OPERATIONS.md).

## Stable contact

For anything that doesn't fit the channels above:

- **Email**: <sebastian.rousseau@gmail.com>
- **Subject prefix** for routing: `[hsh]`, `[hsh-security]`,
  `[hsh-cli]`, `[hsh-kms]`, `[hsh-digest]`.
