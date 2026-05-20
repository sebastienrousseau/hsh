<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Getting started with hsh

A focused walkthrough for someone who just landed on the repo and
wants to *use* the library. The full reference is the
[root README](./README.md); this page is the on-ramp.

## Install

### As a Rust library

```toml
[dependencies]
hsh = "0.0.9"
```

For peppered / KMS-backed deployments, enable the optional feature:

```toml
[dependencies]
hsh = { version = "0.0.9", features = ["pepper"] }
```

### As a CLI tool

The `hsh` binary ships through every mainstream package channel:

```sh
cargo install hsh-cli --locked                     # crates.io
brew tap sebastienrousseau/tap && brew install hsh # macOS
yay -S hsh-bin                                      # Arch / AUR
```

The library crate is `hsh`; the binary crate that produces the
`hsh` executable is `hsh-cli`. See the
[Install](./README.md#install) section of the root README for the
full per-channel matrix (Cargo, Homebrew, AUR, Scoop, Debian,
Docker / GHCR, shell installer).

## First hash + verify

```rust
use hsh::{api, Outcome, Policy};

fn main() -> Result<(), hsh::Error> {
    // 1. Pick a policy. OWASP Password Storage Cheat Sheet 2025 is
    //    the right default; it uses Argon2id with m=19 456 KiB,
    //    t=2, p=1.
    let policy = Policy::owasp_minimum_2025();

    // 2. Hash the password. `api::hash` returns a PHC-format string
    //    you store in your database as-is.
    let stored = api::hash(&policy, "correct horse battery staple")?;
    println!("stored: {stored}");

    // 3. Verify on next login. `verify_and_upgrade` does both the
    //    match check AND tells you whether the stored hash is below
    //    current policy — if so, it hands you a freshly-hashed PHC
    //    string to persist alongside the user row.
    let outcome = api::verify_and_upgrade(
        &policy,
        "correct horse battery staple",
        &stored,
    )?;

    match outcome {
        Outcome::Valid { rehashed: Some(new_phc) } => {
            // Policy drifted — persist `new_phc` against the user
            // row. The next login reads the upgraded hash directly.
            let _ = new_phc;
        }
        Outcome::Valid { rehashed: None } => {
            // Match, no rehash needed. Common case.
        }
        Outcome::Invalid => {
            // Wrong password — return a generic auth-error to the
            // caller. Do NOT distinguish "wrong password" from
            // "user not found" in the response.
        }
    }
    Ok(())
}
```

This is the **only** API pair you need for 95 % of password-storage
deployments. Everything else (FIPS contract, pepper / KMS, custom
parameters, legacy migration) is built on top of these two calls.

## First CLI invocation

```sh
# Hash a password from stdin
$ echo -n "hunter2" | hsh hash --algorithm argon2id
$argon2id$v=19$m=19456,t=2,p=1$…

# Verify against a stored PHC string
$ echo -n "hunter2" | hsh verify -H '$argon2id$v=19$m=19456,t=2,p=1$…'
valid

# Measure host-specific parameter cost
$ hsh calibrate --algorithm argon2id --target-ms 500
argon2id m=131072 t=2 p=1   ≈ 503 ms

# Generate shell completions
$ hsh completions zsh > ~/.zsh/functions/_hsh
```

The `hsh inspect <phc>` and `hsh rehash <phc>` subcommands round
out the surface — see `hsh --help` for the full menu.

## Common paths from here

| If you need… | Read |
|---|---|
| **Migrating from another crate** (`argonautica`, `rust-argon2`, `bcrypt`, `password-auth`, `djangohashers`) | [`doc/MIGRATION-from-*.md`](./doc/) |
| **FIPS 140-3 deployment** (PBKDF2 fail-closed routing) | [`doc/FIPS.md`](./doc/FIPS.md) |
| **AWS / GCP / Azure / HashiCorp Vault peppering** | [`doc/KMS-INTEGRATION.md`](./doc/KMS-INTEGRATION.md) |
| **Per-host benchmark calibration** | [`doc/BENCHMARKS.md`](./doc/BENCHMARKS.md) + `hsh calibrate` |
| **Comparing `hsh` to other Rust password-hashing crates** | [`doc/COMPARISON.md`](./doc/COMPARISON.md) |
| **Vocabulary** (PHC, MCF, OWASP, KDF, …) | [`GLOSSARY.md`](./GLOSSARY.md) |
| **Architectural decisions** | [`doc/adr/`](./doc/adr/) |
| **Stability tier per public symbol** | [`doc/API-STABILITY.md`](./doc/API-STABILITY.md) |
| **Vulnerability reporting** | [`SECURITY.md`](./SECURITY.md) |

## What `hsh` is *not*

- **Not post-quantum cryptography.** Argon2id raises the cost of
  offline brute-force on classical and quantum hardware alike (Grover
  yields only a √-speedup), but it is not a PQ primitive. For ML-KEM
  / ML-DSA / SLH-DSA, use [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs).
- **Not a self-validating FIPS 140-3 module.** The
  `Backend::Fips140Required` *contract* is enforced — `api::hash`
  refuses to mint non-FIPS-routed hashes — but the underlying crypto
  today is the pure-Rust RustCrypto stack. The `aws-lc-rs` validated
  backend is a follow-up.
- **Not a general-purpose digest library.** For SHA-2 / SHA-3 /
  BLAKE3 content addressing, use the companion
  [`hsh-digest`](https://crates.io/crates/hsh-digest) crate.

If something on this page is unclear, please open an issue — every
question becomes a future paragraph.
