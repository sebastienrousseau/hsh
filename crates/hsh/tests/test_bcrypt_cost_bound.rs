//! Behavioural tests for the bcrypt verification cost bound.
//!
//! These live here rather than beside the code because they pass
//! passwords to `Bcrypt::verify`. `crates/*/src/` is analysed by CodeQL
//! as production code, where a hard-coded password is a critical
//! finding; `crates/*/tests/**` is excluded precisely because fixtures
//! there are expected to carry them. See
//! `.github/codeql/codeql-config.yml`.
//!
//! The parsing half of the guard is unit-tested in
//! `src/algorithms/bcrypt.rs`.

use hsh::algorithms::bcrypt::{
    Bcrypt, PrehashAlgorithm, MAX_VERIFY_COST,
};
use hsh::error::Error;

/// The exact input libFuzzer found stalling `fuzz_phc_parse` for over
/// 29 minutes: a bcrypt string advertising cost 29.
const FUZZ_TIMEOUT_INPUT: &str =
    "$2x$29$rrjrrdrjrrdrh..jrrdrh..n.................jrrdrh......";

/// A throwaway candidate password. Its value is irrelevant: every case
/// below is decided before any hashing happens.
const CANDIDATE: &str = "candidate-password-123";

#[test]
fn the_fuzz_input_is_rejected_rather_than_computed() {
    let err = Bcrypt::verify(
        CANDIDATE,
        FUZZ_TIMEOUT_INPUT,
        PrehashAlgorithm::None,
    )
    .expect_err("a cost-29 hash must be refused");
    assert!(
        matches!(err, Error::InvalidHashString(_)),
        "expected InvalidHashString, got {err:?}"
    );
}

#[test]
fn rejection_is_immediate() {
    // At cost 31 the work would be astronomical, so returning at all is
    // proof the digest was never computed.
    let stored =
        "$2b$31$rrjrrdrjrrdrh..jrrdrh..n.................jrrdrh......";
    assert!(matches!(
        Bcrypt::verify(CANDIDATE, stored, PrehashAlgorithm::None),
        Err(Error::InvalidHashString(_))
    ));
}

#[test]
fn the_comparison_is_strictly_greater_than() {
    // A cheap explicit bound shows equal passes the guard and one more
    // does not, without paying for a verification at the real ceiling.
    let at_bound = "$2b$04$abcdefghijklmnopqrstuv";
    let over_bound = "$2b$05$abcdefghijklmnopqrstuv";

    assert!(
        !matches!(
            Bcrypt::verify_with_max_cost(
                CANDIDATE,
                at_bound,
                PrehashAlgorithm::None,
                4
            ),
            Err(Error::InvalidHashString(_))
        ),
        "a cost equal to the bound must pass the guard"
    );
    assert!(matches!(
        Bcrypt::verify_with_max_cost(
            CANDIDATE,
            over_bound,
            PrehashAlgorithm::None,
            4
        ),
        Err(Error::InvalidHashString(_))
    ));
}

#[test]
fn raising_the_bound_stops_the_guard_firing() {
    // Deliberately never calls the real ceiling: an earlier draft proved
    // this by running a cost-29 verification and hung the suite.
    let stored =
        format!("$2b${}$abcdefghijklmnopqrstuv", MAX_VERIFY_COST + 1);
    assert!(matches!(
        Bcrypt::verify(CANDIDATE, &stored, PrehashAlgorithm::None),
        Err(Error::InvalidHashString(_))
    ));
    assert!(
        !matches!(
            Bcrypt::verify_with_max_cost(
                CANDIDATE,
                &stored,
                PrehashAlgorithm::None,
                31
            ),
            Err(Error::InvalidHashString(_))
        ),
        "the guard must not fire once the bound permits this cost"
    );
}
