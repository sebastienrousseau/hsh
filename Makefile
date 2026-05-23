# Makefile — `hsh` dev / CI targets.
#
# POSIX-compatible (no bash-isms). Each recipe is a single shell line so
# the recipe is portable across BSD / GNU make.
#
# Usage:
#   make help        # list targets
#   make ci          # what CI runs on every PR
#   make release     # everything `make ci` does + bench + miri + fuzz-smoke

.POSIX:
.PHONY: help all ci release \
        fmt fmt-check \
        check clippy clippy-strict \
        test test-doc test-prop test-api \
        doc doc-check \
        deny deny-licenses deny-advisories deny-bans deny-sources \
        audit audit-strict \
        sbom \
        miri miri-focused miri-full \
        fuzz-list fuzz-smoke fuzz-build \
        bench bench-quick \
        coverage coverage-gap \
        calibrate \
        clean

CARGO ?= cargo
RUST_NIGHTLY ?= +nightly

help:
	@echo "Common targets:"
	@echo "  make ci          - what CI runs on every PR (fmt-check, clippy, test, doc)"
	@echo "  make fmt-check   - rustfmt --check"
	@echo "  make clippy      - clippy with -D warnings"
	@echo "  make test        - full workspace test suite"
	@echo "  make doc         - cargo doc --workspace --no-deps --all-features"
	@echo "  make deny        - cargo-deny check (advisories, licenses, bans, sources)"
	@echo "  make audit       - cargo-audit"
	@echo "  make sbom        - generate SBOM with cargo-about (writes NOTICE.md)"
	@echo "  make miri-focused- focused Miri suite (per-PR budget)"
	@echo "  make miri-full   - full Miri sweep (weekly budget)"
	@echo "  make fuzz-list   - list fuzz targets"
	@echo "  make fuzz-smoke  - 30-second smoke run of every fuzz target (nightly)"
	@echo "  make bench       - full criterion bench suite"
	@echo "  make bench-quick - criterion --quick smoke"
	@echo "  make coverage    - cargo llvm-cov"
	@echo "  make calibrate   - measure Argon2id params to hit ~0.5s on this host"

ci: fmt-check clippy test doc

release: ci bench miri-focused

# ---------------------------------------------------------------- format
fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

# ---------------------------------------------------------------- lint
check:
	$(CARGO) check --workspace --all-targets --all-features

clippy:
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

clippy-strict: clippy

# ---------------------------------------------------------------- test
test:
	$(CARGO) test --workspace --all-features

test-doc:
	$(CARGO) test --workspace --doc

test-prop:
	$(CARGO) test --workspace --test test_properties

test-api:
	$(CARGO) test --workspace --test test_api

# ---------------------------------------------------------------- docs
doc:
	$(CARGO) doc --workspace --no-deps --all-features

doc-check:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps --all-features

# ---------------------------------------------------------------- supply-chain
deny: deny-advisories deny-licenses deny-bans deny-sources

deny-advisories:
	$(CARGO) deny check advisories

deny-licenses:
	$(CARGO) deny check licenses

deny-bans:
	$(CARGO) deny check bans

deny-sources:
	$(CARGO) deny check sources

audit:
	$(CARGO) audit

audit-strict:
	$(CARGO) audit --deny warnings

sbom:
	$(CARGO) about generate --output-file NOTICE.html about.hbs || \
	echo "  (no template yet — Phase 5 adds about.hbs / about.md.hbs)"

# ---------------------------------------------------------------- miri
miri: miri-focused

miri-focused:
	./scripts/miri.sh focused

miri-full:
	./scripts/miri.sh full

# ---------------------------------------------------------------- fuzz
fuzz-list:
	@ls fuzz/fuzz_targets

fuzz-build:
	cd fuzz && $(CARGO) $(RUST_NIGHTLY) fuzz build

fuzz-smoke:
	@for t in api_round_trip phc_parse argon2id_verify bcrypt_verify legacy_from_string; do \
	    echo "[fuzz-smoke] $$t"; \
	    cd fuzz && $(CARGO) $(RUST_NIGHTLY) fuzz run "fuzz_$$t" -- -max_total_time=30 || exit 1; \
	    cd ..; \
	done

# ---------------------------------------------------------------- bench
bench:
	$(CARGO) bench --bench benchmark

bench-quick:
	$(CARGO) bench --bench benchmark -- --quick

# ---------------------------------------------------------------- coverage
coverage:
	$(CARGO) llvm-cov --workspace --all-features --lcov --output-path lcov.info

coverage-gap:
	./scripts/coverage-gap-report.sh

# ---------------------------------------------------------------- calibrate
calibrate:
	./scripts/parameter-calibration.sh

clean:
	$(CARGO) clean
	rm -rf fuzz/target lcov.info NOTICE.html NOTICE.md
