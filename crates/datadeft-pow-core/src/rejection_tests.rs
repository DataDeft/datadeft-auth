//! Tamper, difficulty, oversized, non-canonical, and out-of-range rejections.

//! Tests for the proof-of-work core. Time/entropy are injected data, so
//! generation is deterministic apart from proptest's own seeded RNG.

use crate::MAX_CHALLENGE_MAX_AGE_SECS;
use crate::challenge::Solution;
use crate::error::PowError;
use crate::ops::{hmac_tag_hex, tag_message};
use crate::secret::PowSecret;
use crate::{MAX_DIFFICULTY, mint_challenge, verify_solution};
use sha2::{Digest, Sha256};

use super::test_support::*;

// --- Tamper (examples the property does not construct) ----------------

#[test]
fn wrong_secret_rejected() {
    let sol = solved_solution(1);
    let other = PowSecret::new([0x42; 32]);
    assert_eq!(
        verify_solution(&other, &sol, at(TIM_UNIX + 1), MAX_AGE, 1),
        Err(PowError::InvalidTag)
    );
}

#[test]
fn solution_for_different_challenge_rejected() {
    // Valid tag/chg from challenge A, but sol/non solve challenge B.
    let a = mint_challenge(&secret(), 1, at(TIM_UNIX), entropy()).expect("mint a");
    let b = mint_challenge(&secret(), 1, at(TIM_UNIX), [0xFF; 16]).expect("mint b");
    assert_ne!(a.chg, b.chg);
    let (nonce, hash) = solve_like_worker(&b.chg, 1);
    let sol = Solution {
        chg: a.chg,
        sol: hash,
        non: nonce.to_string(),
        dif: 1,
        tim: a.tim,
        tag: a.tag,
    };
    assert_eq!(
        verify_solution(&secret(), &sol, at(TIM_UNIX + 1), MAX_AGE, 1),
        Err(PowError::InvalidSolution)
    );
}

#[test]
fn missing_leading_zeros_rejected() {
    // Honest hash of chg+non, but the nonce does no work (no zeros).
    let challenge = mint_challenge(&secret(), 1, at(TIM_UNIX), entropy()).expect("mint");
    let mut nonce: u64 = 0;
    let hash = loop {
        let digest = Sha256::digest(format!("{}{nonce}", challenge.chg).as_bytes());
        let hash = hex::encode(digest);
        if !hash.starts_with('0') {
            break hash;
        }
        nonce += 1;
    };
    let sol = Solution {
        chg: challenge.chg,
        sol: hash,
        non: nonce.to_string(),
        dif: 1,
        tim: challenge.tim,
        tag: challenge.tag,
    };
    assert_eq!(
        verify_solution(&secret(), &sol, at(TIM_UNIX + 1), MAX_AGE, 1),
        Err(PowError::InvalidSolution)
    );
}

// --- Difficulty downgrade ---------------------------------------------

#[test]
fn difficulty_downgrade_rejected() {
    // Legitimately minted+solved at dif=1, replayed after the server
    // raised min_difficulty to 2: must be rejected.
    let sol = solved_solution(1);
    assert_eq!(
        verify_solution(&secret(), &sol, at(TIM_UNIX + 1), MAX_AGE, 2),
        Err(PowError::DifficultyTooLow)
    );
}

#[test]
fn higher_difficulty_than_min_accepted() {
    let sol = solved_solution(2);
    verify_solution(&secret(), &sol, at(TIM_UNIX + 1), MAX_AGE, 1).unwrap();
}

#[test]
fn zero_difficulty_rejected() {
    // Zero-work backstop: dif=0 must never validate, even if a caller mis-sets
    // min_difficulty=0. `has_leading_zero_prefix(.., 0)` is trivially true, so
    // the floor's `max(1)` is the only thing preventing any nonce from passing
    // as zero work. The tag is minted honestly over dif=0, so it clears
    // authenticity and freshness and reaches the floor check.
    let s = secret();
    let chg = "c92da1677dc682632c77af723ed48d6ccd288ac1d99f68fcef2ff430433fd6f8";
    let sol = Solution {
        chg: chg.to_string(),
        sol: "0".repeat(64),
        non: "0".to_string(),
        dif: 0,
        tim: TIM.to_string(),
        tag: hmac_tag_hex(&s, &tag_message(chg, 0, TIM)),
    };
    assert_eq!(
        verify_solution(&s, &sol, at(TIM_UNIX + 1), MAX_AGE, 0),
        Err(PowError::DifficultyTooLow)
    );
}

#[test]
fn difficulty_above_digest_width_is_rejected() {
    assert_eq!(
        mint_challenge(&secret(), MAX_DIFFICULTY + 1, at(TIM_UNIX), entropy()).unwrap_err(),
        PowError::DifficultyTooHigh
    );

    let mut sol = solved_solution(1);
    sol.dif = MAX_DIFFICULTY + 1;
    assert_eq!(
        verify_solution(&secret(), &sol, at(TIM_UNIX + 1), MAX_AGE, 1).unwrap_err(),
        PowError::DifficultyTooHigh
    );
    assert_eq!(
        verify_solution(
            &secret(),
            &solved_solution(1),
            at(TIM_UNIX + 1),
            MAX_AGE,
            MAX_DIFFICULTY + 1
        )
        .unwrap_err(),
        PowError::DifficultyTooHigh
    );
}

#[test]
fn oversized_fields_are_rejected_before_hmac_work() {
    let huge = "a".repeat(10 * 1024 * 1024);
    let mut sol = solved_solution(1);
    sol.chg = huge;
    assert_eq!(
        verify_solution(&secret(), &sol, at(TIM_UNIX + 1), MAX_AGE, 1).unwrap_err(),
        PowError::InvalidTag
    );

    let mut sol = solved_solution(1);
    sol.non = "1".repeat(21);
    assert_eq!(
        verify_solution(&secret(), &sol, at(TIM_UNIX + 1), MAX_AGE, 1).unwrap_err(),
        PowError::InvalidSolution
    );

    let mut sol = solved_solution(1);
    sol.tim = "2".repeat(33);
    assert_eq!(
        verify_solution(&secret(), &sol, at(TIM_UNIX + 1), MAX_AGE, 1).unwrap_err(),
        PowError::InvalidTimestamp
    );
}

#[test]
fn oversized_max_age_is_rejected_explicitly() {
    let sol = solved_solution(1);
    assert_eq!(
        verify_solution(&secret(), &sol, at(TIM_UNIX + 1), u64::MAX, 1).unwrap_err(),
        PowError::InvalidMaxAge
    );
}

/// Non-canonical hex: uppercase spellings of otherwise valid `chg`, `tag`,
/// and `sol` are rejected rather than normalized.
#[test]
fn uppercase_hex_fields_are_rejected() {
    let valid = solved_solution(1);
    verify_solution(&secret(), &valid, at(TIM_UNIX), MAX_AGE, 1).expect("valid solution");

    let mut chg = valid.clone();
    chg.chg = chg.chg.to_ascii_uppercase();
    let mut tag = valid.clone();
    tag.tag = tag.tag.to_ascii_uppercase();
    let mut sol = valid.clone();
    sol.sol = sol.sol.to_ascii_uppercase();
    for solution in [chg, tag, sol] {
        assert!(
            verify_solution(&secret(), &solution, at(TIM_UNIX), MAX_AGE, 1).is_err(),
            "uppercase hex must not verify"
        );
    }
}

/// Fresh entropy always yields a fresh challenge id; the mint is otherwise
/// deterministic.
#[test]
fn distinct_entropy_mints_distinct_challenges() {
    let first = mint_challenge(&secret(), 1, at(TIM_UNIX), [0x01; 16]).expect("mint");
    let second = mint_challenge(&secret(), 1, at(TIM_UNIX), [0x02; 16]).expect("mint");
    let repeat = mint_challenge(&secret(), 1, at(TIM_UNIX), [0x01; 16]).expect("mint");
    assert_ne!(first.chg, second.chg);
    assert_ne!(first.tag, second.tag);
    assert_eq!(first, repeat);
}

/// A challenge lifetime above the ceiling is rejected before any work, so a
/// misconfigured max age cannot let solutions be stockpiled.
#[test]
fn challenge_max_age_above_the_ceiling_is_rejected() {
    let sol = solved_solution(1);
    assert!(verify_solution(&secret(), &sol, at(TIM_UNIX), MAX_CHALLENGE_MAX_AGE_SECS, 1).is_ok());
    for max_age in [0, MAX_CHALLENGE_MAX_AGE_SECS + 1, u64::MAX] {
        assert_eq!(
            verify_solution(&secret(), &sol, at(TIM_UNIX), max_age, 1),
            Err(PowError::InvalidMaxAge)
        );
    }
}
