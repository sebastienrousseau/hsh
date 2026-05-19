# Release runbook (maintainers)

Step-by-step process for cutting an `hsh` release. The release
pipeline (Phase 2's `.github/workflows/release.yml`) does most of
the heavy lifting on a tag push; this runbook documents the prep,
verification, and post-release follow-up that lives outside CI.

## Pre-release (T-7 days)

1. **Land all merging PRs.** No new feature branches merged between
   T-7 and the tag push.
2. **Run the full Miri sweep** (`make miri-full`) and the **weekly
   fuzz cron** ad-hoc (`gh workflow run fuzz.yml`). Confirm both are
   green for the candidate.
3. **Check OpenSSF Scorecard**:
   `gh workflow run scorecard.yml && gh run watch`. Target ≥ 8.0
   for v1.x releases; ≥ 6.5 for v0.x.
4. **Run `cargo public-api diff`** between the last tag and `HEAD`.
   Any change to a surface marked **Stable** in
   `doc/API-STABILITY.md` must be intentional and reflected in the
   semver bump.
5. **Update `CHANGELOG.md`** — move items from `[Unreleased]` into
   a new `[X.Y.Z] — YYYY-MM-DD` section. Group by Added / Changed /
   Fixed / Deprecated / Removed / **Security**.
6. **Bump versions** in all four `Cargo.toml` files. They must
   match exactly. The release pipeline's `verify-version` job
   refuses to publish on any mismatch.

   ```sh
   for f in Cargo.toml crates/hsh/Cargo.toml crates/hsh-cli/Cargo.toml \
            crates/hsh-kms/Cargo.toml crates/hsh-digest/Cargo.toml; do
       sed -i.bak -E 's/^version = "[^"]+"/version = "X.Y.Z"/' "$f"
   done
   rm -f Cargo.toml.bak crates/*/Cargo.toml.bak
   ```

7. **Open a release PR** titled `release: vX.Y.Z` with the
   `CHANGELOG.md` diff. Sit on it for the standard review window
   (48h for patches, 72h for minor/major).

## Tag push (T-0)

Once the release PR is merged on `main`:

```sh
git checkout main && git pull
git tag -s vX.Y.Z -m "vX.Y.Z"   # signed tag, picks up the maintainer's SSH/GPG key
git push origin vX.Y.Z
```

The tag push triggers `release.yml`, which:

1. Re-runs the full quality gate (`fmt + clippy + test + doc`).
2. Verifies tag ↔ Cargo.toml agreement on all four crates.
3. Generates the SBOM via `cargo about`.
4. Builds release artefacts for the platform matrix.
5. Generates SLSA L3 build provenance via
   `actions/attest-build-provenance`.
6. Keyless-signs every artefact via `cosign sign-blob`.
7. Publishes the four crates to crates.io in **dependency order**:
   `hsh-kms` → `hsh-digest` → `hsh` → `hsh-cli`. The pipeline waits
   for each to be visible before starting the next.

## Post-release (T+1h)

1. **Confirm the GitHub release page** has every signed artefact
   plus `SHA256SUMS`, the SBOM, and the SLSA attestation.
2. **Smoke-test crates.io** from a clean working directory:

   ```sh
   cargo new /tmp/hsh-smoke && cd /tmp/hsh-smoke
   cargo add hsh@X.Y.Z
   cat > src/main.rs <<'EOF'
   fn main() {
       let p = hsh::Policy::owasp_minimum_2025();
       let s = hsh::api::hash(&p, "smoke-test-pw").unwrap();
       let (o, _) = hsh::api::verify_and_upgrade(&p, "smoke-test-pw", &s).unwrap();
       assert!(o.is_valid());
       println!("ok");
   }
   EOF
   cargo run --release
   ```

3. **Update the packaging templates** (`pkg/`): the release pipeline
   has already materialised them, but eyeball the Homebrew tap PR
   and AUR push to confirm the SHAs landed correctly.
4. **Verify docs.rs** built every crate
   (`https://docs.rs/hsh/X.Y.Z`). If a build failed, push a
   `package.metadata.docs.rs` fix and yank-then-re-release if the
   docs are load-bearing.
5. **Close the milestone** on GitHub.

## If the release goes wrong

### Quality-gate failed in CI

The `release.yml` quality gate runs *before* the publish step. If it
fails, the crates are **not** published — fix the issue on `main`,
delete and re-create the tag.

```sh
git tag -d vX.Y.Z
git push origin :vX.Y.Z
# fix on main, then re-tag
```

### Bad artefact published

Within 24 hours of a confirmed defect:

```sh
cargo yank --version X.Y.Z hsh
cargo yank --version X.Y.Z hsh-cli
cargo yank --version X.Y.Z hsh-kms
cargo yank --version X.Y.Z hsh-digest
```

Then file a `RUSTSEC-YYYY-NNNN` advisory and ship the patched
release with the *next* patch version (don't re-use X.Y.Z).

### Coordinated security release

For embargoed advisories:

1. Land the fix on a private branch.
2. Pre-stage the release PR but don't merge.
3. Coordinate the disclosure window with the reporter.
4. On the agreed date, merge + tag + publish + advisory all
   within one hour.

## Version-bump cheat sheet

See [`doc/API-STABILITY.md`](API-STABILITY.md) for the full table.
Common cases:

- Added a new algorithm variant under `#[non_exhaustive]` → **minor**
- New `pub fn` or convenience constructor → **minor**
- Added a feature flag → **minor**
- Bumped a parameter default (e.g. OWASP recommendations shift) →
  **major** (callers' stored hashes drift below policy)
- Bug fix that changes observable behaviour → **patch** with explicit
  CHANGELOG note
- MSRV bump → **minor** with a one-release warning window

## Tooling

```sh
make ci              # what CI runs on every PR
make release         # everything in `make ci` + bench + miri
make sbom            # cargo-about NOTICE.md
make deny            # cargo-deny all sections
make audit-strict    # cargo-audit --deny warnings
make miri-full       # full Miri sweep
make fuzz-smoke      # 30s per fuzz target
```
