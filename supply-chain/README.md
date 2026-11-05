<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Supply-chain audits

`cargo vet` records who has reviewed each dependency. This directory
holds its store; `cargo vet --locked` runs in CI (the `cargo-vet` job in
`.github/workflows/ci.yml`).

| File | Purpose |
|------|---------|
| `config.toml` | The audit sets imported from Bytecode Alliance, Embark, Google and Mozilla, plus policy and exemptions (none). |
| `audits.toml` | Audits and trust entries this project's maintainers record themselves, and the `crypto-reviewed` criteria. |
| `imports.lock` | The imported audits and crates.io publisher records, pinned so CI checks against what the maintainers approved. |
| `exemptions-baseline.txt` | The ceiling CI holds the exemption count to: it may go down, never up. |

`cargo vet` owns the layout of these files (`cargo vet fmt` rewrites
them) and drops comments, so the notes that used to sit in them live
here:

- `crypto-reviewed` means a maintainer familiar with the primitive
  (Argon2, bcrypt, scrypt, SHA-2) read the crate's cryptographic code
  end to end and confirmed, for the API `hsh` uses, constant-time
  comparison wherever a secret is involved, zeroing of secret material
  on drop where applicable, and no silent truncation of inputs. It
  implies `safe-to-deploy`.
- `hsh`, `hsh-cli`, `hsh-digest`, `hsh-kms` and `hsh-backend-awslc` are
  this repository's own crates. Their policy sets
  `audit-as-crates-io = false`, so cargo-vet treats them as first-party
  code reviewed through pull requests, not as crates.io dependencies;
  cargo-vet requires one answer or the other once they are published.
- Record a first-party audit with `cargo vet certify`, for example
  `cargo vet certify argon2 0.5.3 --criteria crypto-reviewed` after
  reading the verify path.
- The Mozilla import points at `mozilla-firefox/firefox` on GitHub, where
  Firefox's source now lives; the `hg.mozilla.org` copy it used to name
  serves the same file (byte-identical when this was changed), but
  cargo-vet could not reach it.
