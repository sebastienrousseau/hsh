# Contributing to `hsh`

Thanks for your interest in `hsh`. This document covers everything
you need to file a useful bug report, propose a change, or land a pull
request.

## Reporting bugs and proposing features

- **Bug reports and feature requests** live on the
  [issue tracker][issues]. Search existing issues first.
- **Security reports** are out of scope for the public tracker. See
  [`SECURITY.md`](SECURITY.md) for the coordinated disclosure
  process.
- A useful issue includes: what you were doing, what you expected to
  happen, what actually happened, the output of `hsh --version` (or
  the version pinned in your `Cargo.toml`), and the smallest input
  that reproduces it.

## Sending pull requests

```sh
git clone https://github.com/sebastienrousseau/hsh.git
cd hsh
make ci                    # fmt + clippy + test + doc (what CI runs on every PR)
```

- Source lives in the Cargo **workspace** under [`crates/`](crates/):
  - [`crates/hsh/`](crates/hsh/) — core library
  - [`crates/hsh-cli/`](crates/hsh-cli/) — `hsh` binary
  - [`crates/hsh-kms/`](crates/hsh-kms/) — pepper / KMS providers
  - [`crates/hsh-digest/`](crates/hsh-digest/) — general digests
- Match the existing **commit style** (Conventional Commits, e.g.
  `fix(api): …`, `feat(cli): …`, `docs: …`).
- Keep PRs focused. If your change touches the public API surface,
  read [`doc/API-STABILITY.md`](doc/API-STABILITY.md) first to
  understand which surfaces are stability tier 1 and require a
  semver bump.
- New behaviour wants a regression test next to it — see the
  existing layout in `crates/*/tests/`.
- Don't skip pre-commit hooks (`--no-verify`) and don't bypass CI
  (`[skip ci]` / `if: false`). If a hook fails, fix the underlying
  issue.

## Style and lints

- `rustfmt` is non-negotiable; `make fmt-check` is the gate.
- `clippy` runs with `-D warnings` and the workspace lint groups
  configured in the root `Cargo.toml` (`[workspace.lints.rust]` +
  `[workspace.lints.clippy]`). Don't add `#[allow(...)]` to silence
  a lint without a justification comment.
- `#![forbid(unsafe_code)]` is the workspace-wide rule
  ([ADR-0006](doc/adr/0006-zero-unsafe-policy.md)).
- The disallowed-methods list in [`clippy.toml`](clippy.toml) bans
  non-OS-CSPRNG random sources and crates we've explicitly chosen
  not to depend on. Don't try to work around them.

## Larger conversations

- For design questions that don't fit in an issue, open a
  Discussion on the repo or start a draft PR with a single
  `doc/` change explaining what you're proposing.
- For positioning / architecture conversations, the existing
  long-form artefacts ([`doc/PASSKEY-ERA.md`](doc/PASSKEY-ERA.md),
  [`doc/COMPARISON.md`](doc/COMPARISON.md),
  [`doc/FIPS.md`](doc/FIPS.md), the ADRs under
  [`doc/adr/`](doc/adr/)) are good seeds.

Thanks again — every well-shaped issue, well-scoped PR, and
well-reasoned design comment makes the project better.

[issues]: https://github.com/sebastienrousseau/hsh/issues
