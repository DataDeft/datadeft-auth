//! `PowPolicy` range validation (exhaustive at the boundaries) and the binding
//! of an admission (`dd_pow` cookie) to exactly the challenge that was solved.

use datadeft_auth_token_core::keyring::KeyRing;
use datadeft_auth_token_core::test_support::{PerCallRng, test_keyring};
use datadeft_pow_axum::{
    PowChallengeResponse, PowFlowError, PowPolicy, PowPolicyError, PowProofCookieConfig,
    PowSolutionRequest, mint_pow_challenge, verify_pow_solution,
};
use datadeft_pow_core::{
    MAX_CHALLENGE_MAX_AGE_SECS, MAX_CLOCK_SKEW_SECS, MAX_DIFFICULTY, PowProofCookie, PowSecret,
    UnixMillis, verify_pow_proof_cookie,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const TIM_UNIX: u64 = 1_783_598_400;

fn at(secs: u64) -> UnixMillis {
    UnixMillis::from_millis(secs * 1000)
}

fn secret() -> PowSecret {
    PowSecret::new([0x11; 32])
}

fn keyring() -> KeyRing<PowProofCookie> {
    test_keyring::<PowProofCookie>(0x22, "test-active")
}

fn policy(difficulty: u8) -> PowPolicy {
    PowPolicy::new(difficulty, 120).expect("policy")
}

fn solve(challenge: &PowChallengeResponse) -> PowSolutionRequest {
    let prefix = "0".repeat(usize::from(challenge.dif));
    let (nonce, sol) = (0u64..)
        .map(|n| {
            let hash = hex::encode(Sha256::digest(format!("{}{n}", challenge.chg).as_bytes()));
            (n, hash)
        })
        .find(|(_, hash)| hash.starts_with(&prefix))
        .expect("solution exists");
    PowSolutionRequest {
        chg: challenge.chg.clone(),
        sol,
        non: nonce.to_string(),
        tim: challenge.tim.clone(),
        tag: challenge.tag.clone(),
    }
}

fn admit(request: &PowSolutionRequest, policy: PowPolicy) -> Result<String, PowFlowError> {
    let mut rng = PerCallRng::starting_at(0x10);
    let admission = verify_pow_solution(
        &secret(),
        policy,
        request,
        &keyring(),
        &PowProofCookieConfig::production_defaults(),
        &mut rng,
        at(TIM_UNIX + 1),
        |_| None,
    )?;
    let header = admission.set_cookie.to_str().expect("ascii").to_owned();
    let value = header
        .strip_prefix("dd_pow=")
        .and_then(|rest| rest.split_once(';'))
        .map(|(value, _)| value.to_owned())
        .expect("cookie value");
    Ok(value)
}

#[test]
fn policy_difficulty_is_valid_exactly_in_one_to_max() {
    for difficulty in 0..=u8::MAX {
        let result = PowPolicy::new(difficulty, 120);
        if (1..=MAX_DIFFICULTY).contains(&difficulty) {
            assert_eq!(result.expect("in range").difficulty(), difficulty);
        } else {
            assert_eq!(result.unwrap_err(), PowPolicyError::InvalidDifficulty);
        }
    }
}

#[test]
fn policy_max_age_and_skew_are_valid_exactly_in_range() {
    for max_age in [
        0,
        1,
        MAX_CHALLENGE_MAX_AGE_SECS - 1,
        MAX_CHALLENGE_MAX_AGE_SECS,
    ] {
        let ok = max_age != 0;
        assert_eq!(PowPolicy::new(1, max_age).is_ok(), ok, "max_age={max_age}");
    }
    for max_age in [MAX_CHALLENGE_MAX_AGE_SECS + 1, u64::MAX] {
        assert_eq!(
            PowPolicy::new(1, max_age).unwrap_err(),
            PowPolicyError::InvalidChallengeMaxAge
        );
    }
    for skew in 0..=MAX_CLOCK_SKEW_SECS + 1 {
        let result = policy(1).with_clock_skew_secs(skew);
        if skew <= MAX_CLOCK_SKEW_SECS {
            assert_eq!(result.expect("in range").clock_skew_secs(), skew);
        } else {
            assert_eq!(result.unwrap_err(), PowPolicyError::InvalidClockSkew);
        }
    }
}

/// The client never sends `dif`: the server fills it from policy and the tag
/// binds it. Raising the policy difficulty rejects in-flight challenges, and
/// lowering it cannot admit a challenge minted harder.
#[test]
fn policy_difficulty_change_rejects_in_flight_challenges() {
    let challenge = mint_pow_challenge(&secret(), policy(2), at(TIM_UNIX), [3; 16]).expect("mint");
    let request = solve(&challenge);
    assert!(admit(&request, policy(2)).is_ok());
    assert_eq!(admit(&request, policy(3)), Err(PowFlowError::Rejected));
    assert_eq!(admit(&request, policy(1)), Err(PowFlowError::Rejected));
}

#[test]
fn admission_cookie_is_bound_to_the_solved_challenge_only() {
    let a = mint_pow_challenge(&secret(), policy(1), at(TIM_UNIX), [0xa1; 16]).expect("a");
    let b = mint_pow_challenge(&secret(), policy(1), at(TIM_UNIX), [0xb2; 16]).expect("b");
    let (solved_a, solved_b) = (solve(&a), solve(&b));

    let tid_of = |cookie: &str| {
        verify_pow_proof_cookie(cookie, &keyring(), TIM_UNIX + 1, 3 * 60 * 60)
            .expect("proof verifies")
            .tid()
            .to_owned()
    };
    let tid_a = tid_of(&admit(&solved_a, policy(1)).expect("a admits"));
    let tid_b = tid_of(&admit(&solved_b, policy(1)).expect("b admits"));
    assert_eq!(tid_a, blake3::hash(a.chg.as_bytes()).to_string());
    assert_eq!(tid_b, blake3::hash(b.chg.as_bytes()).to_string());
    assert_ne!(tid_a, tid_b);

    // Mixing any authenticated field of A into a solve of B is rejected.
    let mut mixes = Vec::new();
    for field in 0..3 {
        let mut mixed = solved_b.clone();
        match field {
            0 => mixed.tag = a.tag.clone(),
            1 => mixed.chg = a.chg.clone(),
            _ => {
                mixed.sol = solved_a.sol.clone();
                mixed.non = solved_a.non.clone();
            }
        }
        mixes.push(mixed);
    }
    for mixed in &mixes {
        assert_eq!(admit(mixed, policy(1)), Err(PowFlowError::Rejected));
    }
}

/// Wiring sanity for caller-supplied challenge entropy: OS-RNG entropy gives
/// a distinct challenge on every mint at the same instant.
#[test]
fn os_rng_entropy_gives_distinct_challenges() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..2048 {
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);
        let challenge =
            mint_pow_challenge(&secret(), policy(1), at(TIM_UNIX), entropy).expect("mint");
        assert!(seen.insert(challenge.chg), "challenge repeated");
    }
}
