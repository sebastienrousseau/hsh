<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# hsh-cli error reference

`hsh-cli` is a binary, so it uses `anyhow::Error` internally to chain
contexts and surfaces all errors via `main`'s `Result<()>` return.
Exit codes are the contract; the message text on stderr is
informational.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. For `verify` / `rehash`, also means the password matched |
| `1` | Authentication failure (`verify` / `rehash` only) — `Outcome::Invalid` from the library |
| `2`+ | Error (`anyhow::Error` surfaced via `main`) — malformed input, FIPS misconfiguration, KMS outage, I/O failure, etc. |

The exit-1-on-mismatch contract for `verify` is part of the CLI's
stability surface — shell pipelines using `&&` / `||` rely on it.

## Common error sources

| Symptom | Likely cause | Fix |
|---|---|---|
| `Error: bcrypt input exceeds 72 bytes` | Hashing a > 72-byte password with `--algorithm bcrypt` without a pre-hash | Add `--prehash sha256` or use `--algorithm argon2id` |
| `Error: Backend::Fips140Required cannot mint hashes with Argon2id` | `--preset fips` combined with `--algorithm argon2id` | Drop one of the flags, or use `--algorithm pbkdf2` |
| `Error: Backend::Fips140Required policy supplied but the 'fips' Cargo feature is not enabled` | Built without `--features fips` | Rebuild `hsh-cli` with `--features fips`, or use `--preset owasp` |
| `Error: invalid hash string: not a recognised PHC or MCF string` | `verify` / `inspect` got a non-PHC string | Inspect the stored value; typically corruption |
| `Error: reading password from terminal: …` | TTY available but `rpassword` failed (e.g. `/dev/tty` missing in a container) | Pipe the password via stdin instead |
| `invalid` printed, exit 1 | `verify` ran successfully but the password didn't match | Expected for wrong-password attempts; no action needed |

## JSON output on error paths

When `--json` is passed, the success path emits structured JSON.
On error paths, `anyhow::Error` is still rendered as a plain-text
chain on stderr — JSON-shaping error output is a v0.0.10+ follow-up
tracked separately. For now, scripts should match on exit codes,
not stderr text.

## When to file an issue vs read the docs

| Behaviour | Action |
|---|---|
| Exit code or success/failure semantics changes between versions | File an issue — this is a regression |
| Stderr message text changes between minor versions | Acceptable per stability tier — text is informational |
| `--help` output reformats between minor versions | Update your scripts (snapshot tests in `tests/snapshots/` give you the diff) |
| Exit code is unexpected | Check this file + run `hsh --help` for the subcommand |
