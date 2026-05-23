# Benchmarks

`hsh` ships Criterion benchmarks for the public hash / verify surface
across every supported algorithm. This document covers methodology,
reproduction, and a placeholder for the published numbers (filled in
by [`release.yml`](../.github/workflows/release.yml)'s CodSpeed step
on each tagged release).

## Methodology

Benchmarks live in [`crates/hsh/benches/criterion.rs`](../crates/hsh/benches/criterion.rs)
and are organised into three groups:

### `hash_owasp_2025`

Measures `hsh::api::hash` wall-time at the OWASP-2025 minimum
parameters per algorithm. **These are the numbers a production
operator will pay** — they reflect what the library mints on each
new password hash.

| Variant                  | Parameters                                            |
| ------------------------ | ----------------------------------------------------- |
| `argon2id_m19456_t2_p1`  | OWASP-2025 minimum: `m = 19 456 KiB, t = 2, p = 1`    |
| `bcrypt_cost_10`         | OWASP-2025 minimum: `cost = 10`                       |
| `scrypt_N_2_17`          | OWASP-2025 minimum: `N = 2^17, r = 8, p = 1`          |

### `verify_owasp_2025`

Symmetric to `hash_owasp_2025` but for `hsh::api::verify_and_upgrade`
against a pre-computed stored hash. Verify cost should be ~identical
to hash cost for memory-hard KDFs (Argon2id / scrypt); slightly
faster for PBKDF2 / bcrypt.

### `fast_params`

The same shape with **non-production** parameters used by the
proptest / fuzz / unit-test suites so CI doesn't burn budget on
real cost factors. **Not for production sizing.**

| Variant                | Parameters                                          |
| ---------------------- | --------------------------------------------------- |
| `argon2id_m8_t1_p1`    | `m = 8 KiB, t = 1, p = 1`                           |
| `bcrypt_cost_4`        | `cost = 4`                                          |
| `scrypt_N_2_8`         | `N = 2^8, r = 8, p = 1`                             |

## Reproduce

```bash
cargo bench --bench benchmark                          # full Criterion run (~5–10 min on Apple Silicon)
cargo bench --bench benchmark -- --quick               # smoke (~30 s total)
cargo bench --bench benchmark "hash_owasp_2025"        # specific group
cargo bench --bench benchmark -- --save-baseline main  # save baseline for diffing
cargo bench --bench benchmark -- --baseline main       # compare against saved baseline
```

For continuous-integration baselines, the [`release.yml`](../.github/workflows/release.yml)
workflow runs Criterion under [CodSpeed](https://codspeed.io/) which
posts per-commit comparisons to PRs.

## Published numbers

> The numbers below are **placeholders**. Each tagged release runs
> the full Criterion suite on the GitHub Actions `ubuntu-latest`
> runner (x86_64, ~2-core), and the numbers are pasted into this
> table by the release pipeline. For your own deployment, run
> `cargo bench` on a representative host or use `hsh-cli calibrate`
> (see `doc/PARAMETER-TUNING.md` once the latter ships).

### `ubuntu-latest` (x86_64, 2-core)

| Group                   | Variant                       | Median  | Std. dev. |
| ----------------------- | ----------------------------- | ------- | --------- |
| `hash_owasp_2025`       | `argon2id_m19456_t2_p1`       | _TBD_   | _TBD_     |
| `hash_owasp_2025`       | `bcrypt_cost_10`              | _TBD_   | _TBD_     |
| `hash_owasp_2025`       | `scrypt_N_2_17`               | _TBD_   | _TBD_     |
| `verify_owasp_2025`     | `argon2id_m19456_t2_p1`       | _TBD_   | _TBD_     |
| `verify_owasp_2025`     | `bcrypt_cost_10`              | _TBD_   | _TBD_     |
| `verify_owasp_2025`     | `scrypt_N_2_17`               | _TBD_   | _TBD_     |
| `fast_params`           | `argon2id_m8_t1_p1`           | _TBD_   | _TBD_     |
| `fast_params`           | `bcrypt_cost_4`               | _TBD_   | _TBD_     |
| `fast_params`           | `scrypt_N_2_8`                | _TBD_   | _TBD_     |

### Apple Silicon (`aarch64-apple-darwin`, M-series)

| Group                   | Variant                       | Median  | Std. dev. |
| ----------------------- | ----------------------------- | ------- | --------- |
| `hash_owasp_2025`       | `argon2id_m19456_t2_p1`       | _TBD_   | _TBD_     |
| `hash_owasp_2025`       | `bcrypt_cost_10`              | _TBD_   | _TBD_     |
| `hash_owasp_2025`       | `scrypt_N_2_17`               | _TBD_   | _TBD_     |

## Calibrating for your host

Production sizing should target ~**500 ms** per `hash` on the actual
serving hardware. Use `hsh-cli calibrate`:

```bash
hsh calibrate --algorithm argon2id --target-ms 500
# → target:   500 ms
#   selected: argon2id m=65536 t=2 p=1
#   measured: 487 ms (off by 13 ms)
```

Or run the bench harness directly:

```bash
cargo bench --bench benchmark "hash_owasp_2025/argon2id"
```

Then map the measured wall-time into a `PolicyBuilder::argon2(...)`
override for your deployment.

## Threats covered by these benchmarks

- **Operator capacity planning** — what's the headroom on this
  server for 100 logins/sec?
- **Regression detection** — CI's CodSpeed step fails if a PR
  regresses any benchmark by >5 %.
- **Algorithm comparison** — which KDF should we mint new hashes
  with given our latency budget?

## Threats *not* covered

- **Side-channel timing analysis.** Constant-time verify is
  asserted via `subtle::ConstantTimeEq` use; the Criterion harness
  doesn't measure that.
- **Memory bandwidth contention** with co-tenant workloads —
  benchmarks run alone; production servers don't.
- **AVX2 / AVX-512 / NEON hardware acceleration** — exposed by the
  upstream `argon2` / `sha2` / `blake3` crates; we don't override.

## References

- [Argon2 RFC 9106](https://datatracker.ietf.org/doc/rfc9106/)
- [OWASP Password Storage Cheat Sheet (2025)](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Criterion.rs](https://bheisler.github.io/criterion.rs/book/)
- [CodSpeed](https://codspeed.io/) — CI-integrated continuous benchmarking
