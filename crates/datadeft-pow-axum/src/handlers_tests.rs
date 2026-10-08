//! Admission-flow glue tests.

use datadeft_auth_token_core::keyring::KeyRing;
use datadeft_auth_token_core::test_support::{PerCallRng, test_keyring};
use datadeft_pow_core::{
    MAX_CHALLENGE_MAX_AGE_SECS, MAX_CLOCK_SKEW_SECS, PowProofCookie, PowSecret, UnixMillis,
    verify_pow_proof_cookie,
};
use sha2::{Digest, Sha256};

use super::*;
use crate::cookie::PowProofCookieConfig;

/// Unix timestamp of the fixture mint instant (2026-07-09T12:00:00Z).
const TIM_UNIX: u64 = 1_783_598_400;
const DIFFICULTY: u8 = 1;

/// Millisecond clock at a whole-second unix instant.
fn at(unix_secs: u64) -> UnixMillis {
    UnixMillis::from_millis(unix_secs * 1000)
}

fn secret() -> PowSecret {
    PowSecret::new([0x11; 32])
}

fn keyring() -> KeyRing<PowProofCookie> {
    test_keyring::<PowProofCookie>(0x22, "test-active")
}

fn policy() -> PowPolicy {
    PowPolicy::new(DIFFICULTY, DEFAULT_POW_CHALLENGE_MAX_AGE_SECS).expect("policy is valid")
}

/// Mirrors the browser worker: SHA-256 over `chg + nonce`, `dif` leading zero
/// hex chars, posting `{chg, sol, non, tim, tag}` (no `dif`).
fn solve(challenge: &PowChallengeResponse) -> PowSolutionRequest {
    let mut nonce: u64 = 0;
    let sol = loop {
        let hash = hex::encode(Sha256::digest(
            format!("{}{nonce}", challenge.chg).as_bytes(),
        ));
        if hash.starts_with(&"0".repeat(usize::from(challenge.dif))) {
            break hash;
        }
        nonce += 1;
    };
    PowSolutionRequest {
        chg: challenge.chg.clone(),
        sol,
        non: nonce.to_string(),
        tim: challenge.tim.clone(),
        tag: challenge.tag.clone(),
    }
}

#[test]
fn policy_rejects_out_of_range_inputs() {
    assert_eq!(
        PowPolicy::new(0, 120).err(),
        Some(PowPolicyError::InvalidDifficulty)
    );
    assert_eq!(
        PowPolicy::new(DIFFICULTY, 0).err(),
        Some(PowPolicyError::InvalidChallengeMaxAge)
    );
}

#[test]
fn admission_applies_configured_clock_skew() {
    let secret = secret();
    let keyring = keyring();
    let config = PowProofCookieConfig::production_defaults();
    let challenge =
        mint_pow_challenge(&secret, policy(), at(TIM_UNIX), [7; 16]).expect("challenge mints");
    let solution = solve(&challenge);
    assert_eq!(policy().clock_skew_secs(), 60);

    for (skew, future_ms, accepted) in [
        (30, 30_000, true),
        (30, 30_001, false),
        (0, 0, true),
        (0, 1, false),
        (60, 60_000, true),
        (60, 60_001, false),
    ] {
        let configured = policy().with_clock_skew_secs(skew).expect("skew in range");
        let mut rng = PerCallRng::starting_at(0xa0);
        let result = verify_pow_solution(
            &secret,
            configured,
            &solution,
            &keyring,
            &config,
            &mut rng,
            UnixMillis::from_millis(TIM_UNIX * 1000 - future_ms),
            |_| None,
        );
        assert_eq!(
            result.is_ok(),
            accepted,
            "skew={skew}, future_ms={future_ms}"
        );
        if !accepted {
            assert_eq!(result.err(), Some(PowFlowError::Rejected));
        }
    }
}

#[test]
fn create_then_validate_round_trips_into_a_parseable_proof_cookie() {
    let secret = secret();
    let keyring = keyring();
    let config = PowProofCookieConfig::production_defaults();
    let mut rng = PerCallRng::starting_at(0xa0);

    let challenge =
        mint_pow_challenge(&secret, policy(), at(TIM_UNIX), [7; 16]).expect("challenge mints");
    assert_eq!(challenge.dif, DIFFICULTY);

    let solution = solve(&challenge);
    // App-side classifier: quantize the delta into an opaque class byte that
    // is stamped into the proof cookie.
    let admission = verify_pow_solution(
        &secret,
        policy(),
        &solution,
        &keyring,
        &config,
        &mut rng,
        at(TIM_UNIX + 1),
        |ms| ms.map(|ms| u8::from(ms >= 300)),
    )
    .expect("solution accepted");

    // Server-derived solve timing: verified one second after mint.
    assert_eq!(admission.mint_to_verify_ms, Some(1000));

    let header = admission.set_cookie.to_str().expect("ascii");
    assert!(header.starts_with("dd_pow=v1."));
    assert!(header.contains("Max-Age=10800"));

    let cookie_value = header
        .strip_prefix("dd_pow=")
        .and_then(|rest| rest.split_once(';').map(|(token, _)| token))
        .expect("cookie value present");
    let verified = verify_pow_proof_cookie(cookie_value, &keyring, TIM_UNIX + 1, config.ttl_secs())
        .expect("proof cookie parses");
    // tid is the stable hex BLAKE3 of the solved challenge.
    assert_eq!(
        verified.tid(),
        blake3::hash(challenge.chg.as_bytes()).to_string()
    );
    // The classifier's byte (1000 ms >= 300) survives the stateless round
    // trip through the encrypted v2 body.
    assert_eq!(verified.solve_class(), Some(1));
}

#[test]
fn tampered_solution_is_rejected_generically() {
    let secret = secret();
    let keyring = keyring();
    let config = PowProofCookieConfig::production_defaults();
    let mut rng = PerCallRng::starting_at(0xa0);

    let challenge =
        mint_pow_challenge(&secret, policy(), at(TIM_UNIX), [7; 16]).expect("challenge mints");
    let mut solution = solve(&challenge);
    solution.tag = "00".repeat(32);

    assert_eq!(
        verify_pow_solution(
            &secret,
            policy(),
            &solution,
            &keyring,
            &config,
            &mut rng,
            at(TIM_UNIX + 1),
            |_| None,
        )
        .err(),
        Some(PowFlowError::Rejected)
    );
}

#[test]
fn expired_challenge_is_rejected() {
    let secret = secret();
    let keyring = keyring();
    let config = PowProofCookieConfig::production_defaults();
    let mut rng = PerCallRng::starting_at(0xa0);

    let challenge =
        mint_pow_challenge(&secret, policy(), at(TIM_UNIX), [7; 16]).expect("challenge mints");
    let solution = solve(&challenge);

    // One second past the challenge max age.
    let now = at(TIM_UNIX + DEFAULT_POW_CHALLENGE_MAX_AGE_SECS + 1);
    assert_eq!(
        verify_pow_solution(
            &secret,
            policy(),
            &solution,
            &keyring,
            &config,
            &mut rng,
            now,
            |_| None,
        )
        .err(),
        Some(PowFlowError::Rejected)
    );
}

#[test]
fn solution_request_rejects_unknown_fields() {
    let json = r#"{"chg":"a","sol":"b","non":"0","tim":"t","tag":"g","extra":"x"}"#;
    assert!(serde_json::from_str::<PowSolutionRequest>(json).is_err());
}

#[test]
fn policy_rejects_clock_skew_above_the_cap() {
    assert!(policy().with_clock_skew_secs(MAX_CLOCK_SKEW_SECS).is_ok());
    for skew in [MAX_CLOCK_SKEW_SECS + 1, u64::MAX] {
        assert_eq!(
            policy().with_clock_skew_secs(skew).unwrap_err(),
            PowPolicyError::InvalidClockSkew
        );
    }
}

#[test]
fn policy_rejects_challenge_max_age_above_the_ceiling() {
    assert!(PowPolicy::new(5, MAX_CHALLENGE_MAX_AGE_SECS).is_ok());
    for max_age in [MAX_CHALLENGE_MAX_AGE_SECS + 1, u64::MAX] {
        assert_eq!(
            PowPolicy::new(5, max_age).unwrap_err(),
            PowPolicyError::InvalidChallengeMaxAge
        );
    }
}
