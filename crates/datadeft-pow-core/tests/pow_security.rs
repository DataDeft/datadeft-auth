//! PoW security properties through the public API.
//!
//! - Work: an honest solution verifies iff its SHA-256 digest has at least the
//!   minted `dif` leading zero nibbles (checked against an independent
//!   bit-count reference), and the minted `dif` meets `max(min_difficulty, 1)`.
//! - Identity: `tid` is stable across different valid solves of one challenge
//!   and distinct across challenges.
//! - Proof cookie: pinned golden values (v1 and v2 body), binding to the
//!   solved challenge's `tid`, purpose separation from session/confirm
//!   cookies under the same root and kid, single-edit integrity, totality.
//! - Time: mint/verify at the epoch, the 2038 rollover, and an unformattable
//!   far-future clock.

use datadeft_auth_token_core::TokenError;
use datadeft_auth_token_core::branca;
use datadeft_auth_token_core::cookie::{MaxAge, mint_bound_cookie, parse_bound_cookie};
use datadeft_auth_token_core::keyring::{KeyPurpose, KeyRing};
use datadeft_auth_token_core::test_support::{FixedBytesRng, test_keyring};
use datadeft_pow_core::{
    Challenge, DEFAULT_POW_PROOF_TTL_SECS, PowError, PowProofCookie, PowSecret, Solution,
    UnixMillis, mint_challenge, mint_pow_proof_cookie, verify_pow_proof_cookie, verify_solution,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

const TIM_UNIX: u64 = 1_783_598_400;
const MAX_AGE: u64 = 300;
const NOW: u64 = 1_781_438_700;
const KID: &str = "test-active";

fn at(secs: u64) -> UnixMillis {
    UnixMillis::from_millis(secs * 1000)
}

fn secret() -> PowSecret {
    PowSecret::new([0x07; 32])
}

/// Independent reference: count leading zero BITS of the digest, then whole
/// nibbles. The implementation checks hex characters instead.
fn leading_zero_nibbles(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in digest {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits / 4
}

fn honest(challenge: &Challenge, non: &str) -> (Solution, u32) {
    let digest = Sha256::digest(format!("{}{non}", challenge.chg).as_bytes());
    let solution = Solution {
        chg: challenge.chg.clone(),
        sol: hex::encode(digest),
        non: non.to_owned(),
        dif: challenge.dif,
        tim: challenge.tim.clone(),
        tag: challenge.tag.clone(),
    };
    (solution, leading_zero_nibbles(&digest))
}

/// First nonce at or after `start` whose digest has at least `dif` zero nibbles.
fn solve_from(challenge: &Challenge, dif: u32, start: u64) -> Solution {
    (start..)
        .map(|n| honest(challenge, &n.to_string()))
        .find(|(_, zeros)| *zeros >= dif)
        .map(|(s, _)| s)
        .expect("a solution exists")
}

fn pow_ring() -> KeyRing<PowProofCookie> {
    test_keyring::<PowProofCookie>(0x11, KID)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    /// Valid iff the minted difficulty clears the floor AND the honest digest
    /// has at least `dif` leading zero nibbles. Half the cases use a solver
    /// nonce so the accepting branch is exercised, half a random nonce.
    #[test]
    fn verifies_iff_leading_zero_nibbles_meet_the_bound(
        entropy in prop::array::uniform16(any::<u8>()),
        minted in 0u8..=3,
        min_difficulty in 0u8..=4,
        random_nonce in any::<u64>(),
        use_solver in any::<bool>(),
    ) {
        let challenge = mint_challenge(&secret(), minted, at(TIM_UNIX), entropy).expect("mint");
        let (solution, zeros) = if use_solver {
            let s = solve_from(&challenge, u32::from(minted), random_nonce % 1_000_000);
            let z = leading_zero_nibbles(&hex::decode(&s.sol).expect("hex"));
            (s, z)
        } else {
            honest(&challenge, &random_nonce.to_string())
        };
        let expected = if minted < min_difficulty.max(1) {
            Err(PowError::DifficultyTooLow)
        } else if zeros < u32::from(minted) {
            Err(PowError::InvalidSolution)
        } else {
            Ok(())
        };
        let got = verify_solution(&secret(), &solution, at(TIM_UNIX + 1), MAX_AGE, min_difficulty)
            .map(|_| ());
        prop_assert_eq!(got, expected);
    }

    /// `tid` is a function of the challenge alone: two different valid solves
    /// share it, and two challenges (different entropy) never do.
    #[test]
    fn tid_is_stable_per_challenge_and_distinct_across_challenges(
        entropy_a in prop::array::uniform16(any::<u8>()),
        entropy_b in prop::array::uniform16(any::<u8>()),
    ) {
        prop_assume!(entropy_a != entropy_b);
        let a = mint_challenge(&secret(), 1, at(TIM_UNIX), entropy_a).expect("mint");
        let b = mint_challenge(&secret(), 1, at(TIM_UNIX), entropy_b).expect("mint");
        let first = solve_from(&a, 1, 0);
        let first_nonce: u64 = first.non.parse().expect("decimal");
        let second = solve_from(&a, 1, first_nonce + 1);
        prop_assert_ne!(&first.non, &second.non);
        let now = at(TIM_UNIX + 1);
        let t1 = verify_solution(&secret(), &first, now, MAX_AGE, 1).expect("first").tid;
        let t2 = verify_solution(&secret(), &second, now, MAX_AGE, 1).expect("second").tid;
        let tb = verify_solution(&secret(), &solve_from(&b, 1, 0), now, MAX_AGE, 1)
            .expect("b")
            .tid;
        prop_assert_eq!(&t1, &t2);
        prop_assert_eq!(&t1, &blake3::hash(a.chg.as_bytes()).to_string());
        prop_assert_ne!(&a.chg, &b.chg);
        prop_assert_ne!(t1, tb);
    }

    /// Any single-character substitution, truncation, or extension of a proof
    /// cookie is rejected.
    #[test]
    fn any_proof_cookie_edit_is_rejected(
        class in prop::option::of(any::<u8>()),
        pos in any::<prop::sample::Index>(),
        replacement in any::<char>(),
        cut in any::<prop::sample::Index>(),
        suffix in "[0-9A-Za-z.]{1,4}",
    ) {
        let mut rng = FixedBytesRng([0x3c; branca::NONCE_BYTES]);
        let cookie = mint_pow_proof_cookie(&"cd".repeat(32), class, &pow_ring(), &mut rng, NOW)
            .expect("mint");
        let value = cookie.as_secret_value();
        let verify = |v: &str| {
            verify_pow_proof_cookie(v, &pow_ring(), NOW + 1, DEFAULT_POW_PROOF_TTL_SECS)
        };
        prop_assert!(verify(value).is_ok());
        let mut chars: Vec<char> = value.chars().collect();
        let i = pos.index(chars.len());
        if chars[i] != replacement {
            chars[i] = replacement;
            prop_assert!(verify(&chars.into_iter().collect::<String>()).is_err());
        }
        prop_assert!(verify(&value[..cut.index(value.len())]).is_err());
        let extended = format!("{value}{suffix}");
        prop_assert!(verify(&extended).is_err());
    }

    /// Totality: arbitrary strings never panic the proof-cookie verifier.
    #[test]
    fn proof_cookie_verify_is_total(
        raw in "\\PC{0,200}|[\\x00-\\x7f]{0,200}",
        token in "[0-9A-Za-z]{0,300}",
        now in any::<u64>(),
        max_age in any::<u64>(),
    ) {
        let _ = verify_pow_proof_cookie(&raw, &pow_ring(), now, max_age);
        let shaped = format!("v1.{KID}.{token}");
        let _ = verify_pow_proof_cookie(&shaped, &pow_ring(), now, max_age);
    }
}

#[test]
fn proof_cookie_golden_values_are_pinned() {
    let tid = "ab".repeat(32);
    let mut rng = FixedBytesRng([0x3c; branca::NONCE_BYTES]);
    let v1 = mint_pow_proof_cookie(&tid, None, &pow_ring(), &mut rng, NOW).expect("v1");
    let mut rng = FixedBytesRng([0x3c; branca::NONCE_BYTES]);
    let v2 = mint_pow_proof_cookie(&tid, Some(9), &pow_ring(), &mut rng, NOW).expect("v2");
    assert_eq!(
        v1.as_secret_value(),
        "v1.test-active.18QcCWBuQ5iJKJIUytXPAf922o7Tz7lmMqNUVxZ1a7w4OJC12RISepaaDhGAncP1SxNXOurC7jzk7V8oC1mxWlsvm3oIhDD9pKbPWpg5yeecobqprjJvQKLWk4ZzV0boo1luAk9fja1R7am8XW"
    );
    assert_eq!(
        v2.as_secret_value(),
        "v1.test-active.4gntjgvAxjaxnrgNvRJvw1tIRawtoO5HiKGzzxwcXAlm8NFcI4iEKb13YYcmasZK3ZBBusle3xuwQyaNHBszhLMHjlaSQqKe9UKz9nu0XMd4B1m4hvtuDK0BJd1ztE9Sj0w3x8HGgQhtoKlzOE5"
    );
}

#[test]
fn proof_cookie_is_bound_to_the_solved_challenge() {
    let a = mint_challenge(&secret(), 1, at(TIM_UNIX), [0xa1; 16]).expect("mint a");
    let b = mint_challenge(&secret(), 1, at(TIM_UNIX), [0xb2; 16]).expect("mint b");
    let now = at(TIM_UNIX + 1);
    let tid_a = verify_solution(&secret(), &solve_from(&a, 1, 0), now, MAX_AGE, 1)
        .expect("a")
        .tid;
    let tid_b = verify_solution(&secret(), &solve_from(&b, 1, 0), now, MAX_AGE, 1)
        .expect("b")
        .tid;

    let mut rng = FixedBytesRng([0x3d; branca::NONCE_BYTES]);
    let cookie =
        mint_pow_proof_cookie(&tid_a, None, &pow_ring(), &mut rng, TIM_UNIX + 1).expect("mint");
    let proof = verify_pow_proof_cookie(
        cookie.as_secret_value(),
        &pow_ring(),
        TIM_UNIX + 2,
        DEFAULT_POW_PROOF_TTL_SECS,
    )
    .expect("verify");
    assert_eq!(proof.tid(), tid_a);
    assert_ne!(proof.tid(), tid_b);

    // A's tag cannot carry B's work.
    let mut mixed = solve_from(&b, 1, 0);
    mixed.tag = a.tag.clone();
    assert_eq!(
        verify_solution(&secret(), &mixed, now, MAX_AGE, 1),
        Err(PowError::InvalidTag)
    );
}

#[derive(Debug)]
enum MirrorSession {}
impl KeyPurpose for MirrorSession {
    const HKDF_INFO: &'static [u8] = b"auth/session-v1";
    const TOKEN_TYPE: &'static str = "session-v1";
    const MAX_BODY_BYTES: usize = 128;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 30 * 24 * 60 * 60;
}

#[derive(Debug)]
enum MirrorConfirm {}
impl KeyPurpose for MirrorConfirm {
    const HKDF_INFO: &'static [u8] = b"auth/magic-link-confirm-v1";
    const TOKEN_TYPE: &'static str = "ml-confirm-v1";
    const MAX_BODY_BYTES: usize = 256;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 5 * 60;
}

fn foreign<P: KeyPurpose>(body: &[u8]) -> (KeyRing<P>, String) {
    let ring = test_keyring::<P>(0x11, KID);
    let mut rng = FixedBytesRng([0x3e; branca::NONCE_BYTES]);
    let ts = u32::try_from(NOW).expect("fits");
    let value = mint_bound_cookie::<P, _>(body, &ring, &mut rng, ts, ts, NOW).expect("mint");
    (ring, value)
}

/// Same root byte and kid for every purpose: only purpose separation differs.
/// The foreign bodies are shaped like a valid v1 proof body.
#[test]
fn proof_cookie_never_crosses_purposes_with_session_or_confirm() {
    let mut proof_body = vec![1u8];
    proof_body.extend_from_slice(&[0xab; 32]);
    let (session_ring, session) = foreign::<MirrorSession>(&proof_body);
    let (confirm_ring, confirm) = foreign::<MirrorConfirm>(&proof_body);
    for value in [&session, &confirm] {
        assert_eq!(
            verify_pow_proof_cookie(value, &pow_ring(), NOW + 1, DEFAULT_POW_PROOF_TTL_SECS)
                .unwrap_err(),
            TokenError::InvalidToken
        );
    }
    let mut rng = FixedBytesRng([0x3f; branca::NONCE_BYTES]);
    let proof =
        mint_pow_proof_cookie(&"ab".repeat(32), None, &pow_ring(), &mut rng, NOW).expect("mint");
    let bound = MaxAge::fixed(60);
    assert!(parse_bound_cookie(proof.as_secret_value(), &session_ring, NOW, bound).is_err());
    assert!(parse_bound_cookie(proof.as_secret_value(), &confirm_ring, NOW, bound).is_err());
}

#[test]
fn challenge_time_extremes() {
    for secs in [0, i32::MAX as u64, i32::MAX as u64 + 1, u64::from(u32::MAX)] {
        let challenge = mint_challenge(&secret(), 1, at(secs), [1; 16]).expect("mint");
        let solution = solve_from(&challenge, 1, 0);
        assert!(verify_solution(&secret(), &solution, at(secs), MAX_AGE, 1).is_ok());
        assert_eq!(
            verify_solution(&secret(), &solution, at(secs + MAX_AGE + 1), MAX_AGE, 1),
            Err(PowError::Expired)
        );
    }
    assert_eq!(
        mint_challenge(&secret(), 1, UnixMillis::from_millis(u64::MAX), [1; 16]).unwrap_err(),
        PowError::InvalidTimestamp
    );
    // The proof cookie stamps u32 seconds: past 2106 is a typed error.
    let mut rng = FixedBytesRng([0x40; branca::NONCE_BYTES]);
    assert_eq!(
        mint_pow_proof_cookie(
            &"ab".repeat(32),
            None,
            &pow_ring(),
            &mut rng,
            u64::from(u32::MAX) + 1
        )
        .unwrap_err(),
        TokenError::InvalidTimestamp
    );
}
