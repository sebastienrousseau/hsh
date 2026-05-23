# Operations runbook

Day-2 procedures for the `hsh` binary. Each section pairs a goal with
the exact CLI invocations and the expected output shape so a runbook
step can be turned into a deploy gate or paged-on-call workflow.

## Pre-deployment self-check

**Goal:** confirm the binary that's about to take traffic actually
delivers the contract the policy declares.

```bash
hsh --json inspect-backend --policy fips > /tmp/hsh-backend.json
cat /tmp/hsh-backend.json
```

Expected fields (every value is stable across runs on the same host):

| Field                       | Meaning                                                                                          |
| --------------------------- | ------------------------------------------------------------------------------------------------ |
| `preset`                    | One of `owasp_minimum_2025`, `rfc9106_first_recommended`, `fips_140_pbkdf2`.                     |
| `backend`                   | `Native` or `Fips140Required` — what the policy *demands*.                                       |
| `primary_algorithm`         | `Argon2id` / `Bcrypt` / `Scrypt` / `Pbkdf2` — what new hashes are minted under.                  |
| `fips_available_in_build`   | `true` only when a FIPS-validated runtime is wired (e.g. `hsh-backend-awslc`). `false` in v0.0.9.|
| `pepper_feature_compiled`   | `true` when the binary was built with `--features pepper`.                                       |
| `readiness`                 | `"satisfied"` or `"unsatisfied …"` — the actionable summary.                                     |
| `hsh_cli_version` / `rustc` / `target_triple` / `profile` | Build provenance, attached for fleet audits. |

**Gate logic:**

- For a Native preset: `readiness == "satisfied"` is sufficient.
- For a FIPS preset: `readiness == "satisfied"` requires
  `fips_available_in_build == true`. In v0.0.9 this is always `false`,
  so a FIPS preset's readiness will be `"unsatisfied …"` — that means
  the *contract* (mint-time fail-closed) is wired but the *validated
  runtime* is not. Block the deploy until `hsh-backend-awslc` ships in
  0.1.x, or accept that hashing will fail closed at every call.

Use this in CI / pre-rollout:

```bash
hsh --json inspect-backend --policy "$DESIRED_PRESET" \
  | jq -e '.readiness == "satisfied"' >/dev/null \
  || { echo "hsh backend not ready for $DESIRED_PRESET" >&2; exit 1; }
```

## Sizing a new fleet

**Goal:** pick parameters that hit a per-request wall-time target on
the hardware the service will actually run on.

```bash
hsh --json calibrate --algorithm argon2id --target-ms 250 \
  > /tmp/calibrate.json
```

Output carries two operator-facing blocks:

- **`ladder`** — every candidate the sweep tried, in order, with
  `candidate`, `measured_ms`, `distance_ms`, and `selected: true|false`.
  Exactly one entry is marked selected (the one with the smallest
  `distance_ms`; ties keep the lower-cost candidate).
- **`runner`** — `host_os`, `host_arch`, `target_triple`, `profile`,
  `rustc`, `hsh_cli_version`. Pin this to your sizing decision so you
  don't accidentally apply Apple-Silicon-debug-build numbers to a
  Linux-x86_64-release fleet.

Operator workflow:

1. Run on the actual deployment hardware in `release` profile. The
   `runner.profile` field will say `release`; `debug` measurements are
   typically 10–40× slower and will mislead.
2. Inspect the ladder. The selected entry is the closest fit to your
   target, but the next-larger row is often a better choice when the
   distance is comparable and you can afford the latency. The full
   ladder lets you see that tradeoff explicitly.
3. Persist the chosen params in your config management alongside the
   `runner` block. If you change hardware, re-run.

## Pepper key rotation

See [`KMS-INTEGRATION.md`](KMS-INTEGRATION.md) for the full
end-to-end procedure. The TL;DR:

1. Add `KeyVersion::new(N+1)` to the keyset; do not drop old versions.
2. Bump `current` to `N+1` and redeploy.
3. As users log in, `verify_and_upgrade` returns
   `Outcome::Valid { rehashed: Some(new_phc) }` carrying `keyver=N+1`;
   persist `new_phc`.
4. After a chosen window, audit for rows still on old keyvers and
   force-rotate inactive users via fresh sign-in.
5. Drop the old version from the keyset on the next deploy.

## Inspecting a stored hash

When investigating a credential incident or a migration discrepancy:

```bash
hsh --json inspect "$STORED_HASH"
```

Recognises:

- **PHC** (`$argon2id$…`, `$scrypt$…`, `$pbkdf2-sha256$…`) — exposes
  `algorithm` plus per-segment params.
- **MCF** (`$2a$…` / `$2b$…` / `$2x$…` / `$2y$…`) — exposes `cost`.
- **`hsh-bcrypt-sha256:<mcf>`** — bcrypt with HMAC-SHA-256 pre-hash;
  surfaces `prehash`, the inner MCF, and the inner cost.
- **`hsh-pepper:<keyver>:<inner>`** — peppered wrapper; surfaces the
  key version and the inner format for further inspection.

## Migration playbooks

- [`MIGRATION-from-rust-argon2.md`](MIGRATION-from-rust-argon2.md)
- [`MIGRATION-from-bcrypt.md`](MIGRATION-from-bcrypt.md)
- [`MIGRATION-from-argonautica.md`](MIGRATION-from-argonautica.md)
- [`MIGRATION-from-djangohashers.md`](MIGRATION-from-djangohashers.md)
- [`MIGRATION-from-password-hash.md`](MIGRATION-from-password-hash.md)
