<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# hsh-cli internals

Contributor-facing map of the `hsh` CLI binary. The CLI is a thin
wrapper over [`hsh`](../../hsh/) — its job is argument parsing,
password I/O, and human / JSON output formatting. All cryptographic
behaviour lives in the library.

## Module map

```text
crates/hsh-cli/src/
├── main.rs             # entry point; clap parse + dispatch
├── cli.rs              # `Cli` struct, subcommand args, ValueEnum impls
├── io.rs               # password input (stdin / --password / TTY no-echo)
│                       # + structured output (key-value plain / JSON)
└── commands/
    ├── mod.rs          # subcommand dispatch + policy resolution
    ├── hash.rs         # `hsh hash`
    ├── verify.rs       # `hsh verify`
    ├── rehash.rs       # `hsh rehash`
    ├── inspect.rs      # `hsh inspect`
    ├── calibrate.rs    # `hsh calibrate`
    └── completions.rs  # `hsh completions {bash|zsh|fish|powershell|elvish}`
```

## Subcommand dispatch

```text
clap Cli::parse()
  └─ match cli.command:
       Command::Hash(args)        → commands::hash::run
       Command::Verify(args)      → commands::verify::run
       Command::Rehash(args)      → commands::rehash::run
       Command::Inspect(args)     → commands::inspect::run
       Command::Calibrate(args)   → commands::calibrate::run
       Command::Completions(arg)  → commands::completions::run
```

Each `run()` function:

1. Reads the password via `io::resolve_password` if applicable.
2. Builds a `hsh::Policy` via `commands::mod::resolve_policy` from
   the `--preset` / `--algorithm` / `--backend` flags.
3. Calls into the `hsh` library.
4. Emits via `io::print_kv` (JSON or plain key-value) based on the
   top-level `--json` flag.

## Password I/O contract (`io.rs`)

```text
resolve_password(args.password) →
  ├─ args.password is Some(s) → strip trailing newline → return
  ├─ stdin is a TTY            → rpassword::prompt_password (no-echo)
  └─ stdin is piped            → read to String → strip trailing newline
```

Trailing-newline stripping handles both `\n` (POSIX) and `\r\n`
(Windows / piped from `cmd.exe`). This is what lets
`echo -n hunter2 | hsh hash` work consistently across OSes.

## Exit-code contract

| Subcommand | Exit code | When |
|---|---|---|
| `hash` / `inspect` / `calibrate` / `completions` | 0 | success |
| `verify` | 0 | password matches |
| `verify` | 1 | password mismatch (`Outcome::Invalid`) |
| `rehash` | 0 | password matches; fresh PHC printed |
| `rehash` | 1 | password mismatch |
| any | 2+ | error (malformed input, FIPS misconfig, …) — `anyhow::Error` exit via `main` |

Operators piping `verify` through shell `&&` / `||` rely on the
exit-1-on-mismatch contract; it's part of the CLI's stability surface
(tier 1 per [`doc/API-STABILITY.md`](../../../doc/API-STABILITY.md)).

## Snapshot testing

`crates/hsh-cli/tests/snapshots.rs` uses `insta` to lock down
`hsh inspect <fixture>` and `hsh <subcommand> --help` output. The
fixtures live in `tests/snapshots/`. Intentional format changes go
through `cargo insta review`.

`--help` snapshots are `#[cfg(unix)]`-gated because clap emits
program path differences on Windows (e.g. `hsh.exe` vs `hsh`) that
would diverge from a POSIX baseline.

## Why bool flags aren't used past 3 args

`clippy.toml` enforces `max-fn-params-bools = 3`. The CLI follows
the same rule — anything more nuanced than three boolean flags
becomes a `clap::ValueEnum`. Example: `--algorithm` is an enum, not
six `--algo-{argon2id,bcrypt,scrypt,pbkdf2,...}` bools.
