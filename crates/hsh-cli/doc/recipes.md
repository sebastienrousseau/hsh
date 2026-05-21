<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `hsh-cli` recipes

Shell-pipeline patterns operators reach for most often. Every
recipe assumes the `hsh` binary is on `PATH`.

For an overview of all subcommands, see `hsh --help`. For the
exit-code contract, see [`errors.md`](./errors.md).

## Hash a password from stdin

```sh
echo -n 'hunter2' | hsh hash --algorithm argon2id
# $argon2id$v=19$m=19456,t=2,p=1$…
```

Notes:
- `-n` matters — without it, `echo` appends `\n` which becomes part
  of the password. `hsh` strips trailing `\n` and `\r\n` from stdin
  to make the common case correct, but explicit `-n` is clearer.
- Use `printf '%s' 'hunter2'` if your shell's `echo` doesn't take
  `-n` (POSIX `echo` doesn't).

## Verify under shell `&&` / `||`

`hsh verify` exits 0 on match, 1 on mismatch. Pipelines work out
of the box:

```sh
if echo -n "$pw" | hsh verify -H "$stored"; then
    echo "logged in"
else
    echo "wrong password"
fi
```

The exit-code contract is part of the CLI's tier-1 stability
surface — see [`errors.md`](./errors.md).

## Pipe JSON output through `jq`

Every subcommand accepts a top-level `--json` flag:

```sh
$ echo -n hunter2 | hsh --json hash --algorithm scrypt | jq .
{
  "stored": "$scrypt$ln=17,r=8,p=1$…",
  "algorithm": "scrypt"
}

$ echo -n hunter2 | hsh --json verify -H "$stored" | jq '.valid'
true

$ hsh --json inspect "$argon2id_phc" | jq '{algo: .algorithm, m: .m_cost}'
{
  "algo": "argon2id",
  "m": "19456"
}
```

`--json` placement: it's a global flag, before the subcommand.

## Migrate a legacy column in bulk (DON'T)

There is no `hsh migrate` subcommand by design. The recommended
migration pattern is *transparent upgrade on next login* via
`api::verify_and_upgrade` — see the library [cookbook](../../hsh/doc/cookbook.md#migrating-from-a-legacy-bcrypt-database).

If you absolutely must rotate stored values without a successful
verify (e.g. user is dormant), the only correct path is to force a
password reset — you do not have the cleartext, so you cannot
remint under a new algorithm.

## Pre-deploy: verify the binary's effective crypto route

`hsh inspect-backend --policy <preset>` is the operator self-check.
It resolves the preset, asks `hsh::Backend` what it demands, and
reports whether this build can satisfy that demand. Use it as a
deploy gate so the binary going to production actually delivers the
contract its policy claims.

```sh
$ hsh --json inspect-backend --policy fips | jq -e '.readiness == "satisfied"'
# exit 0 → deploy; exit 1 → block until hsh-backend-awslc lands
```

Plain output for human eyes:

```sh
$ hsh inspect-backend --policy owasp
preset: owasp_minimum_2025
backend: Native
primary_algorithm: Argon2id
fips_available_in_build: false
pepper_feature_compiled: true
readiness: satisfied
hsh_cli_version: 0.0.9
rustc: rustc 1.95.0 (…)
target_triple: x86_64-unknown-linux-gnu
profile: release
```

## Calibrate parameters for your host

```sh
$ hsh calibrate --algorithm argon2id --target-ms 500
target:   500 ms
selected: argon2id m=65536 t=2 p=1
measured: 503 ms (off by 3 ms)
ladder:
  * argon2id m=65536 t=2 p=1 → 503 ms (off by 3 ms)
    …more rungs of the ladder, the selected one is prefixed with *…
```

JSON mode also emits a `ladder` array (every candidate the sweep
tried, with `measured_ms`, `distance_ms`, `selected`) plus a
`runner` block carrying `host_os`, `host_arch`, `target_triple`,
`profile`, `rustc`, `hsh_cli_version` so sizing decisions are tied
to the host that produced them.

Re-run calibration after a CPU upgrade — the optimal cost ladder
shifts.

## Inspect a stored value without verifying

```sh
$ hsh inspect '$argon2id$v=19$m=19456,t=2,p=1$WX0$dGVzdA'
format: phc
algorithm: argon2id
params[1]: v=19
params[2]: m=19456,t=2,p=1
segment[3]: WX0
hash_b64: dGVzdA

$ hsh inspect '$2b$10$saltsaltsaltsaltsalth8shorhashbcryptmcfgoeshere'
format: bcrypt-mcf
algorithm: bcrypt
cost: 10

$ hsh inspect 'hsh-bcrypt-sha256:$2b$10$…'
format: hsh-bcrypt-sha256
algorithm: bcrypt
prehash: hmac-sha256
inner: $2b$10$…
cost: 10

$ hsh inspect 'hsh-pepper:1:$argon2id$…'
format: hsh-pepper
keyver: 1
inner: $argon2id$…
```

Useful for triaging DB corruption / unexpected stored values.

## Shell completions

```sh
# Bash — add to ~/.bashrc
echo 'source <(hsh completions bash)' >> ~/.bashrc

# Zsh — drop into fpath
hsh completions zsh > ~/.zsh/functions/_hsh

# Fish — drop into completions
hsh completions fish > ~/.config/fish/completions/hsh.fish

# PowerShell — append to profile
hsh completions powershell >> $PROFILE
```

## Pre-commit hook: reject committed plaintext passwords

```sh
#!/bin/sh
# .git/hooks/pre-commit (chmod +x)
#
# Refuse a commit that touches the literal "$argon2id$v=" prefix
# without going through the `hsh` library — the only sane way to
# emit one is via api::hash.

if git diff --cached | grep -qE '^\+.*\$argon2(i?d?)\$v='; then
    echo "WARNING: a committed file appears to contain a literal PHC hash."
    echo "Verify it's a TEST FIXTURE, not real credential material."
    echo "If intentional, commit with --no-verify."
    exit 1
fi
```

## CI: enforce that all stored hashes meet current policy

```yaml
# .github/workflows/audit-password-storage.yml
- name: Audit DB password column against current policy
  run: |
    DB=/path/to/dump.sql
    grep -oE '\$[a-z0-9-]+\$[^"]+' "$DB" | while read -r stored; do
      # If `inspect --json` parses cleanly AND the algo matches our
      # current primary, the row is up-to-date. Anything else is a
      # rotation candidate.
      hsh --json inspect "$stored" \
        | jq -e 'select(.algorithm == "argon2id")' >/dev/null \
        || echo "OUTDATED: $stored"
    done
```

This is read-only — actual rotation still happens transparently
on next login via `api::verify_and_upgrade`.

## Containerised one-shot hash

```sh
echo -n 'hunter2' \
    | docker run --rm -i ghcr.io/sebastienrousseau/hsh:0.0.9 \
        hash --algorithm argon2id
```

The `ghcr.io/sebastienrousseau/hsh` image is a `distroless`
container with just the `hsh` binary — no shell, no libc, no
package manager. ~3 MB total.

## Generate a NOTICE.md for your distribution

```sh
cargo install cargo-about
cargo about generate -c about.toml about.hbs > NOTICE.md
```

Lists every third-party crate `hsh` redistributes, grouped by
license. Required for some redistributable bundles (Debian
`copyright`, Homebrew formula `License`, etc.).

## Force a rehash to current policy without a verify

The library's `api::hash(&policy, password)` mints a fresh hash;
the CLI mirror is:

```sh
echo -n "$password" | hsh rehash -H "$stored"
```

`rehash` does verify first — if the password matches, it prints a
fresh PHC under the current policy (regardless of whether the
stored hash was already at policy). If verify fails, exit code 1.

This is the explicit form of what `verify_and_upgrade` does
automatically; useful for ops who want to bulk-rotate after a
policy change.
