<p align="center">
  <img src="https://cloudcdn.pro/hsh/v1/logos/hsh.svg" alt="hsh-cli logo" width="128" />
</p>

<h1 align="center">hsh-cli</h1>

<p align="center">
  <strong>Command-line companion for <a href="../hsh/"><code>hsh</code></a> — hash, verify, rehash, inspect, calibrate.</strong>
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/hsh/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/hsh/ci.yml?style=for-the-badge&logo=github" alt="Build" /></a>
  <a href="https://crates.io/crates/hsh-cli"><img src="https://img.shields.io/crates/v/hsh-cli.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Crates.io" /></a>
  <a href="https://docs.rs/hsh-cli"><img src="https://img.shields.io/badge/docs.rs-hsh--cli-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs.rs" /></a>
</p>

---

## Contents

[Install](#install) · [Quick Start](#quick-start) · [Subcommands](#subcommands) · [Password resolution](#password-resolution) · [Exit codes](#exit-codes) · [JSON output](#json-output) · [Shell completions](#shell-completions) · [Examples](#examples) · [Security](#security)

---

## Install

```bash
cargo install hsh-cli
```

MSRV **1.85** stable. Edition 2024. Provides the `hsh` binary.

Packaging for Docker / Homebrew / Debian / Arch / Scoop is shipped under [`pkg/`](../../pkg/); each tagged release materialises ready-to-publish artefacts via [`release.yml`](../../.github/workflows/release.yml).

---

## Quick Start

```bash
# Hash a password (read from stdin)
echo -n "correct horse battery staple" | hsh hash
# → $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>

# Verify
echo -n "correct horse battery staple" | hsh verify \
    -H '$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>'
# → valid
# exit code 0
```

---

## Subcommands

| Command          | Purpose                                                                  |
| ---------------- | ------------------------------------------------------------------------ |
| `hsh hash`       | Hash a password → emit the storable PHC / MCF string                     |
| `hsh verify`     | Verify a candidate password against a stored hash                        |
| `hsh rehash`     | Verify + mint a fresh hash under the current policy (combined op)         |
| `hsh inspect`    | Pretty-print the algorithm + parameters of any stored hash                |
| `hsh calibrate`  | Walk a parameter ladder; report the params closest to a wall-time target  |
| `hsh completions`| Emit bash / zsh / fish / powershell / elvish completion scripts           |

Every subcommand accepts `--json` for machine-readable output and `--policy {owasp,rfc9106,fips}` to switch the parameter ladder.

### `hsh hash`

```bash
hsh hash --algorithm argon2id --policy owasp
hsh hash --algorithm bcrypt   --policy owasp --json
hsh hash --algorithm pbkdf2   --policy fips         # errors: FIPS feature not built in
```

### `hsh verify`

```bash
hsh verify -H "$STORED"
# Reads password from stdin / $HSH_PASSWORD env / TTY prompt.
# Plain output:
#   valid                          (exit 0)
#   needs_rehash: true             (when policy drifted)
#   rehashed: $argon2id$...        (the fresh hash to persist)
# Or:
#   invalid                        (exit 1)
```

### `hsh rehash`

```bash
hsh rehash -H "$STORED" --policy rfc9106
# Verifies, then unconditionally mints a fresh hash under the
# current policy. Useful for batch migration scripts.
```

### `hsh inspect`

```bash
hsh inspect '$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$dGVzdA'
# → format:    phc
#   algorithm: argon2id
#   params[1]: v=19
#   params[2]: m=19456,t=2,p=1
#   segment[3]: YWJjZGVmZ2hpamtsbW5vcA
#   hash_b64:  dGVzdA
```

### `hsh calibrate`

```bash
hsh calibrate --algorithm argon2id --target-ms 500
# Walks m_cost ∈ {4096, 8192, 19456, 32768, 65536, 131072},
# reports the params that hit closest to 500 ms.
```

### `hsh completions`

```bash
hsh completions bash > /etc/bash_completion.d/hsh
hsh completions zsh  > ~/.zsh/functions/_hsh
hsh completions fish > ~/.config/fish/completions/hsh.fish
```

---

## Password resolution

`hsh-cli` resolves the password in this order (and **never** accepts it on the command line):

1. **`--password <value>` flag** — discouraged; documented as insecure (leaves password in shell history).
2. **`$HSH_PASSWORD` env var** — for batch scripts.
3. **TTY prompt with no echo** — when stdin is a terminal.
4. **First line of stdin** — for pipelines.

The same priority applies to `--stored` / `$HSH_STORED` for hash inputs.

---

## Exit codes

| Code | Meaning                                                            |
| ---- | ------------------------------------------------------------------ |
| `0`  | Success (verify match, hash produced, completions emitted, etc.)   |
| `1`  | Verify mismatch (wrong password) — only `verify` and `rehash`      |
| `2`  | Error (malformed input, missing flag, policy contradiction)        |

These are stable per [`doc/API-STABILITY.md`](../../doc/API-STABILITY.md).

---

## JSON output

Every subcommand accepts `--json`:

```bash
echo -n "secret" | hsh hash --algorithm scrypt --json
# {
#   "stored": "$scrypt$ln=17,r=8,p=1$<salt>$<hash>",
#   "algorithm": "Scrypt"
# }
```

The JSON schema is stable per the stability contract — additive changes only.

---

## Shell completions

`hsh-cli` ships completions for **bash, zsh, fish, powershell, elvish** via the `completions` subcommand. The Arch (`PKGBUILD`) and Homebrew templates wire these into standard locations automatically — see [`pkg/`](../../pkg/).

---

## Examples

See [`crates/hsh-cli/examples/`](examples/) for runnable demos:

- `quickstart.rs` — hash + verify in 10 LOC.
- `pipeline.rs` — shell-pipeline patterns.

Run with `cargo run --example quickstart`.

---

## Security

- **Passwords are never on argv.** The `--password` flag exists but is documented insecure.
- **Verify exits 1 on mismatch**, 2 on error — no ambiguity for shell-script callers.
- **TTY prompts use `rpassword`** (no echo).
- **No telemetry**, no network calls, no log files.

See [`SECURITY.md`](../../SECURITY.md) for the vulnerability reporting policy.

---

## License

Dual-licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/licenses/MIT), at your option.

<p align="right"><a href="#hsh-cli">Back to top</a></p>
