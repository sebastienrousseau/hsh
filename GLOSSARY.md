<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Glossary

Domain vocabulary used across `hsh`'s documentation, code, and commit
messages. When a term has both a cryptographic-spec meaning and an
`hsh`-specific meaning, both are listed.

## Password hashing & key derivation

**KDF (Key Derivation Function).** A function that turns a password
into a fixed-length tag using deliberate computational cost. The four
KDFs `hsh` ships with are Argon2id, bcrypt, scrypt, and PBKDF2.

**Argon2.** A memory-hard KDF — RFC 9106 — with three variants:
*Argon2id* (hybrid, recommended for password storage),
*Argon2i* (resistant to side-channel leakage; legacy),
*Argon2d* (resistant to GPU cracking; legacy). `hsh` mints new
hashes under Argon2id by default; the other two are accepted on the
verify path so legacy stored hashes round-trip.

**Bcrypt.** A 1999-era KDF based on the Blowfish key schedule.
Truncates input to 72 bytes silently — `hsh` enforces a hard 72-byte
*safety rail* (CVE-2025-22228 class). Use `BcryptParams::with_prehash`
to opt into an HMAC-SHA-256 pre-hash adapter for longer inputs.

**Scrypt.** A memory-hard KDF — RFC 7914 — tunable via `N` (work
factor), `r` (block size), `p` (parallelism). OWASP-2025 minimum is
`N = 2^17`, `r = 8`, `p = 1`.

**PBKDF2.** Iteration-hard KDF — RFC 8018 — with HMAC-SHA-256 or
HMAC-SHA-512 as the PRF. OWASP-2025 minimums: 600 000 iterations for
SHA-256, 210 000 for SHA-512. The only KDF with a FIPS 140-3
validated implementation path today (via `aws-lc-rs`).

**Salt.** A per-password random value mixed into the KDF input to
defeat rainbow-table precomputation. `hsh` draws every salt from the
OS CSPRNG (`getrandom::OsRng`); `vrd` / `rand::thread_rng` /
`fastrand::Rng::new` are explicitly banned via `clippy.toml`.

**Pepper.** A *server-side* secret applied to every password before
the KDF, typically via HMAC-SHA-256. Unlike a salt (per-password,
stored alongside the hash), the pepper is the same for every password
and lives in a separate trust boundary — usually a KMS or HSM that
the password database cannot read. See [`doc/KMS-INTEGRATION.md`](./doc/KMS-INTEGRATION.md).

**Pre-hash.** Hashing the password with a cheap fast hash (e.g.
HMAC-SHA-256) before passing the digest to a length-bounded KDF
like bcrypt. Lets you accept arbitrarily long inputs without silent
truncation.

## Storage formats

**PHC string format.** Modular Crypt Format successor —
`$<algo>$v=<ver>$<params>$<salt>$<hash>` — standardised at
<https://github.com/P-H-C/phc-string-format>. `hsh` emits PHC for
Argon2id, scrypt, and PBKDF2. Interoperable with Django, Devise,
libsodium, the Argon2 reference CLI, and most other ecosystems.

**MCF (Modular Crypt Format).** The pre-PHC predecessor —
`$<algo>$<rest>` — with per-algorithm bespoke `<rest>` encoding.
`hsh` emits MCF for bcrypt (`$2b$<cost>$<salt-and-hash>`) because
the `bcrypt` crate has no PHC encoder.

**`hsh-pepper:` wrapper.** Bespoke `hsh`-specific format
(`hsh-pepper:<keyver>:<inner-phc-or-mcf>`) used when a `Policy`
attaches a pepper provider. The key-version field lets the verifier
locate the right HMAC key and triggers transparent rotation on next
verify under a newer current key.

## Policy & verification

**Policy.** A versioned snapshot of the primary algorithm + per-
algorithm parameters used by `api::hash`. Construct via the
[`Policy::owasp_minimum_2025`](./doc/API-STABILITY.md) /
`rfc9106_first_recommended` / `fips_140_pbkdf2` presets, or via
`PolicyBuilder`.

**Auto-rehash on policy drift.** `api::verify_and_upgrade` returns
`Outcome::Valid { rehashed: Some(_) }` whenever the stored hash
falls below current policy — algorithm drift, parameter drift, PBKDF2
PRF drift, or pepper-version drift. The caller persists the new PHC
string on next successful login.

**Backend.** A *requirement* the caller declares on a `Policy`.
`Backend::Native` accepts any KDF; `Backend::Fips140Required`
restricts new-hash minting to PBKDF2 and refuses Argon2 / bcrypt /
scrypt — see [`doc/FIPS.md`](./doc/FIPS.md). The actual FIPS-validated
crypto routes through `aws-lc-rs` (Phase 4 follow-up).

## Security primitives

**Constant-time comparison.** Byte comparison that takes the same
wall-clock time regardless of where the inputs differ. Defeats
timing side-channel attacks on the verify path. `hsh` uses
`subtle::ConstantTimeEq` everywhere a hash is compared.

**Zeroize.** Erasing a secret from memory on drop, defeating heap-
residue forensic recovery. `hsh` uses `zeroize::ZeroizeOnDrop` for
password / hash / salt / pepper-key buffers.

**OS CSPRNG.** Cryptographically-secure pseudorandom number
generator provided by the operating system —
`getrandom(2)` / `/dev/urandom` on Linux, `BCryptGenRandom` on
Windows, `getentropy(2)` on macOS / BSD. The only acceptable salt
source for password hashing.

## Standards & compliance

**OWASP-2025.** The OWASP Password Storage Cheat Sheet
recommendations valid at the start of 2025 — Argon2id
`m=19 456 KiB t=2 p=1`, bcrypt `cost=10`, scrypt
`N=2^17 r=8 p=1`, PBKDF2 600 000 iters (SHA-256).

**FIPS 140-3.** US federal standard for cryptographic module
validation — <https://csrc.nist.gov/projects/cryptographic-module-validation-program/standards>.
`hsh` itself isn't validated; the `Backend::Fips140Required`
contract delegates the primitive to a FIPS-validated module via
`aws-lc-rs` (Phase 4 follow-up). See ADR-0004.

**RFC 9106.** Argon2 specification — <https://datatracker.ietf.org/doc/html/rfc9106>.
§4 names the "first recommended" parameter set
(`m=2^21`, `t=1`, `p=4`) and the "second recommended" set
(`m=2^16`, `t=3`, `p=4`).

**RFC 7914.** Scrypt specification.

**RFC 8018.** PKCS #5 — PBKDF2 specification.

**SLSA L3.** Supply-chain Levels for Software Artifacts level 3 —
<https://slsa.dev/spec/v1.0/levels>. `hsh` release artefacts ship
with SLSA L3 build provenance attestations via
`actions/attest-build-provenance`.

**Sigstore / cosign.** Keyless signing infrastructure —
<https://www.sigstore.dev/>. Every `hsh` release artefact is signed
via `cosign sign-blob` and verifiable via the Sigstore Rekor
transparency log.

## Project-specific

**Phase N.** A discrete unit of work tracked in the v0.0.9
milestone — see [`PLAN.md`](./PLAN.md). Phases 0-7 cover Foundation
→ Core refactor → Operational hardening → Pepper/KMS → FIPS contract
→ CLI → General hashing → v1.0 stabilisation.

**ADR.** Architecture Decision Record — short markdown documents
under [`doc/adr/`](./doc/adr/) capturing irreversible design choices
(scope, FIPS strategy, pepper-key versioning, zero-unsafe policy,
v1.0 stability contract).

**Compat shim.** The `compat-v0_0_x` feature flag re-exposes the
pre-0.0.9 stringly-typed API for one release cycle so existing
callers can upgrade gradually. Slated for removal in v0.2.0 per
[`doc/API-STABILITY.md`](./doc/API-STABILITY.md).

**Calibrate.** The `hsh calibrate <algorithm> --target-ms <N>`
subcommand measures the host's KDF throughput and suggests a
parameter set that lands within ±10 % of the target wall time.
