//! Expiry, clock skew, and millisecond-precision timing.

//! Tests for the proof-of-work core. Time/entropy are injected data, so
//! generation is deterministic apart from proptest's own seeded RNG.

use crate::MAX_CLOCK_SKEW_SECS;
use crate::challenge::Solution;
use crate::clock::UnixMillis;
use crate::error::PowError;
use crate::ops::{hmac_tag_hex, tag_message};
use crate::{
    MAX_FUTURE_SKEW_SECS, mint_challenge, verify_solution, verify_solution_with_clock_skew,
};

use super::test_support::*;

// --- Expiry ---------------------------------------------------------

#[test]
fn stale_tim_rejected() {
    let sol = solved_solution(1);
    assert_eq!(
        verify_solution(&secret(), &sol, at(TIM_UNIX + MAX_AGE + 1), MAX_AGE, 1),
        Err(PowError::Expired)
    );
}

#[test]
fn expiry_boundary_accepted() {
    let sol = solved_solution(1);
    // age == max_age exactly: still valid.
    verify_solution(&secret(), &sol, at(TIM_UNIX + MAX_AGE), MAX_AGE, 1).unwrap();
}

#[test]
fn future_tim_rejected() {
    let sol = solved_solution(1);
    // now is MAX_FUTURE_SKEW_SECS + 1 before tim => beyond allowed skew.
    assert_eq!(
        verify_solution(
            &secret(),
            &sol,
            at(TIM_UNIX - MAX_FUTURE_SKEW_SECS - 1),
            MAX_AGE,
            1
        ),
        Err(PowError::FutureTimestamp)
    );
}

#[test]
fn future_tim_within_skew_accepted() {
    let sol = solved_solution(1);
    verify_solution(
        &secret(),
        &sol,
        at(TIM_UNIX - MAX_FUTURE_SKEW_SECS),
        MAX_AGE,
        1,
    )
    .unwrap();
}

#[test]
fn configured_thirty_second_skew_has_a_millisecond_boundary() {
    let sol = solved_solution(1);
    let boundary_ms = TIM_UNIX * 1000 - 30_000;
    let verified = verify_solution_with_clock_skew(
        &secret(),
        &sol,
        UnixMillis::from_millis(boundary_ms),
        MAX_AGE,
        1,
        30,
    )
    .expect("exactly thirty seconds ahead is accepted");
    assert_eq!(verified.mint_to_verify_ms, None);
    assert_eq!(
        verify_solution_with_clock_skew(
            &secret(),
            &sol,
            UnixMillis::from_millis(boundary_ms - 1),
            MAX_AGE,
            1,
            30,
        ),
        Err(PowError::FutureTimestamp)
    );
}

#[test]
fn default_sixty_second_skew_is_preserved() {
    let sol = solved_solution(1);
    assert_eq!(MAX_FUTURE_SKEW_SECS, 60);
    for offset_ms in [0, 30_001, 60_000, 60_001] {
        let now = UnixMillis::from_millis(TIM_UNIX * 1000 - offset_ms);
        assert_eq!(
            verify_solution(&secret(), &sol, now, MAX_AGE, 1),
            verify_solution_with_clock_skew(&secret(), &sol, now, MAX_AGE, 1, 60)
        );
    }
    assert_eq!(
        verify_solution(
            &secret(),
            &sol,
            UnixMillis::from_millis(TIM_UNIX * 1000 - 60_001),
            MAX_AGE,
            1,
        ),
        Err(PowError::FutureTimestamp)
    );
}

#[test]
fn zero_skew_rejects_a_timestamp_one_millisecond_ahead() {
    let sol = solved_solution(1);
    assert!(verify_solution_with_clock_skew(&secret(), &sol, at(TIM_UNIX), MAX_AGE, 1, 0).is_ok());
    assert_eq!(
        verify_solution_with_clock_skew(
            &secret(),
            &sol,
            UnixMillis::from_millis(TIM_UNIX * 1000 - 1),
            MAX_AGE,
            1,
            0,
        ),
        Err(PowError::FutureTimestamp)
    );
}

#[test]
fn configured_skew_preserves_expiry_and_is_capped() {
    let sol = solved_solution(1);
    for clock_skew_secs in [0, 30, 60, MAX_CLOCK_SKEW_SECS] {
        assert!(
            verify_solution_with_clock_skew(
                &secret(),
                &sol,
                at(TIM_UNIX + MAX_AGE),
                MAX_AGE,
                1,
                clock_skew_secs,
            )
            .is_ok()
        );
        assert_eq!(
            verify_solution_with_clock_skew(
                &secret(),
                &sol,
                UnixMillis::from_millis((TIM_UNIX + MAX_AGE) * 1000 + 1),
                MAX_AGE,
                1,
                clock_skew_secs,
            ),
            Err(PowError::Expired)
        );
    }
    // Above the cap is a configuration error, whatever the clock says.
    for clock_skew_secs in [MAX_CLOCK_SKEW_SECS + 1, u64::MAX] {
        assert_eq!(
            verify_solution_with_clock_skew(
                &secret(),
                &sol,
                at(TIM_UNIX),
                MAX_AGE,
                1,
                clock_skew_secs
            ),
            Err(PowError::ClockSkewTooLarge)
        );
    }
    // At the cap the arithmetic stays overflow safe at both clock extremes.
    assert_eq!(
        verify_solution_with_clock_skew(
            &secret(),
            &sol,
            UnixMillis::from_millis(0),
            MAX_AGE,
            1,
            MAX_CLOCK_SKEW_SECS,
        ),
        Err(PowError::FutureTimestamp)
    );
    assert_eq!(
        verify_solution_with_clock_skew(
            &secret(),
            &sol,
            UnixMillis::from_millis(u64::MAX),
            MAX_AGE,
            1,
            MAX_CLOCK_SKEW_SECS,
        ),
        Err(PowError::Expired)
    );
}

// --- Millisecond resolution -------------------------------------------

/// A sub-second mint instant lands in `tim` as a millisecond fraction, the
/// solve round-trips, and the mint→verify delta is millisecond-exact. (The
/// fraction-free whole-second format is pinned by
/// `mint_is_deterministic_golden`.)
#[test]
fn millisecond_tim_round_trips_with_exact_delta() {
    let mint_ms = TIM_UNIX * 1000 + 123;
    let challenge =
        mint_challenge(&secret(), 1, UnixMillis::from_millis(mint_ms), entropy()).expect("mint");
    assert_eq!(challenge.tim, "2026-07-09T12:00:00.123Z");
    let (nonce, hash) = solve_like_worker(&challenge.chg, 1);
    let sol = Solution {
        chg: challenge.chg,
        sol: hash,
        non: nonce.to_string(),
        dif: 1,
        tim: challenge.tim,
        tag: challenge.tag,
    };
    let verified = verify_solution(
        &secret(),
        &sol,
        UnixMillis::from_millis(mint_ms + 250),
        MAX_AGE,
        1,
    )
    .unwrap();
    assert_eq!(verified.mint_to_verify_ms, Some(250));
}

/// Expiry is millisecond-precise: exactly `max_age` is accepted, one
/// millisecond past it is rejected.
#[test]
fn expiry_boundary_is_millisecond_precise() {
    let sol = solved_solution(1);
    let mint_ms = TIM_UNIX * 1000;
    verify_solution(
        &secret(),
        &sol,
        UnixMillis::from_millis(mint_ms + MAX_AGE * 1000),
        MAX_AGE,
        1,
    )
    .unwrap();
    assert_eq!(
        verify_solution(
            &secret(),
            &sol,
            UnixMillis::from_millis(mint_ms + MAX_AGE * 1000 + 1),
            MAX_AGE,
            1,
        ),
        Err(PowError::Expired)
    );
}

/// Within the allowed future-skew window the delta is negative and carries
/// no timing information: it must be `None`, never a clamped zero (which
/// would read as the fastest possible solve) and never a wrapped value.
#[test]
fn delta_is_unknown_within_future_skew() {
    let sol = solved_solution(1);
    let verified = verify_solution(
        &secret(),
        &sol,
        UnixMillis::from_millis(TIM_UNIX * 1000 - 5_000),
        MAX_AGE,
        1,
    )
    .unwrap();
    assert_eq!(verified.mint_to_verify_ms, None);
}

/// Boundary: verifying at exactly the mint instant is a known zero delta;
/// one millisecond before it is unknown.
#[test]
fn delta_boundary_at_mint_instant() {
    let sol = solved_solution(1);
    let mint_ms = TIM_UNIX * 1000;
    let at_mint = verify_solution(
        &secret(),
        &sol,
        UnixMillis::from_millis(mint_ms),
        MAX_AGE,
        1,
    )
    .unwrap();
    assert_eq!(at_mint.mint_to_verify_ms, Some(0));
    let before_mint = verify_solution(
        &secret(),
        &sol,
        UnixMillis::from_millis(mint_ms - 1),
        MAX_AGE,
        1,
    )
    .unwrap();
    assert_eq!(before_mint.mint_to_verify_ms, None);
}

#[test]
fn garbage_tim_needs_valid_tag_first() {
    // A non-RFC3339 tim with a correctly minted tag reaches the timestamp
    // check and fails there (proves order: authenticity before parsing).
    let s = secret();
    let chg = "c92da1677dc682632c77af723ed48d6ccd288ac1d99f68fcef2ff430433fd6f8";
    let sol = Solution {
        chg: chg.to_string(),
        sol: "0".repeat(64),
        non: "0".to_string(),
        dif: 1,
        tim: "not-a-timestamp".to_string(),
        tag: hmac_tag_hex(&s, &tag_message(chg, 1, "not-a-timestamp")),
    };
    assert_eq!(
        verify_solution(&s, &sol, at(TIM_UNIX), MAX_AGE, 1),
        Err(PowError::InvalidTimestamp)
    );
}
