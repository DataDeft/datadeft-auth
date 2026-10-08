//! Tests for the proof-of-work core. Time/entropy are injected data, so
//! generation is deterministic apart from proptest's own seeded RNG.

use crate::challenge::Solution;
use crate::clock::UnixMillis;
use crate::error::PowError;
use crate::ops::{has_leading_zero_prefix, hmac_tag_hex, tag_message};
use crate::secret::PowSecret;
use crate::{MAX_CHALLENGE_MAX_AGE_SECS, MAX_CLOCK_SKEW_SECS};
use crate::{
    MAX_DIFFICULTY, MAX_FUTURE_SKEW_SECS, RECOMMENDED_PRODUCTION_MIN_DIFFICULTY, mint_challenge,
    verify_solution, verify_solution_with_clock_skew,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const TIM: &str = "2026-07-09T12:00:00Z";
/// Unix timestamp of TIM (2026-07-09T12:00:00Z).
const TIM_UNIX: u64 = 1_783_598_400;
const MAX_AGE: u64 = 300;

/// Millisecond clock at a whole-second unix instant. The fixtures predate
/// millisecond resolution and are specified in seconds.
fn at(unix_secs: u64) -> UnixMillis {
    UnixMillis::from_millis(unix_secs * 1000)
}

fn secret() -> PowSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    PowSecret::new(bytes)
}

fn entropy() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    bytes
}

/// Mirrors the browser worker exactly: the worker hashes
/// `challenge + String(nonce)` (UTF-8, decimal nonce) with SHA-256 and
/// checks `difficulty` leading zero NIBBLES of the digest (its hex string
/// therefore starts with `difficulty` '0' chars). It reports the hash as
/// lowercase hex. Single-worker equivalent: startNonce=0, step=1.
fn solve_like_worker(chg: &str, dif: u8) -> (u64, String) {
    let mut nonce: u64 = 0;
    loop {
        let digest = Sha256::digest(format!("{chg}{nonce}").as_bytes());
        let ok = (0..usize::from(dif)).all(|i| {
            let byte = digest[i / 2];
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
            nibble == 0
        });
        if ok {
            return (nonce, hex::encode(digest));
        }
        nonce += 1;
    }
}

fn solved_solution(dif: u8) -> Solution {
    let challenge = mint_challenge(&secret(), dif, at(TIM_UNIX), entropy()).expect("mint");
    let (nonce, hash) = solve_like_worker(&challenge.chg, dif);
    // Field mapping as the client builds its Solution JSON: chg/tim/tag/dif
    // echoed, sol = hash, non = nonce.toString().
    Solution {
        chg: challenge.chg,
        sol: hash,
        non: nonce.to_string(),
        dif,
        tim: challenge.tim,
        tag: challenge.tag,
    }
}

// --- Leading-zero work check -----------------------------------------

/// Equivalence guard: `has_leading_zero_prefix` must match the original
/// `starts_with(&"0".repeat(..))` expression for every input, so the
/// allocation-free rewrite can never silently change verification.
#[test]
fn leading_zero_prefix_matches_repeat_reference() {
    fn reference(sol: &str, dif: u8) -> bool {
        sol.starts_with(&"0".repeat(usize::from(dif)))
    }
    // Hand-picked edge cases: empty, all-zeros, multibyte 'é', fullwidth
    // zero '\u{FF10}' (bytes EF BC 90, none 0x30), embedded NUL, whitespace,
    // hex, and a 64-char digest-length string.
    let samples: &[&str] = &[
        "",
        "0",
        "00",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0a",
        "a0",
        "abc",
        "00abc",
        "0é",
        "é0",
        "0\u{FF10}",
        "\u{FF10}0",
        "0\u{0000}",
        " 0",
        "0 ",
    ];
    for sol in samples {
        for dif in 0u8..=70 {
            assert_eq!(
                has_leading_zero_prefix(sol, dif),
                reference(sol, dif),
                "mismatch sol={sol:?} dif={dif}"
            );
        }
    }
    // Deterministic pseudo-random matrix over a charset that mixes '0',
    // other digits/letters, a multibyte char, and space.
    let charset = ["0", "1", "a", "f", "z", "é", "\u{FF10}", " "];
    let mut state: u64 = 0x1234_5678_9abc_def0;
    for _ in 0..5_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let len = (state >> 33) as usize % 40;
        let mut sol = String::new();
        for _ in 0..len {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            sol.push_str(charset[(state >> 40) as usize % charset.len()]);
        }
        for dif in 0u8..=42 {
            assert_eq!(
                has_leading_zero_prefix(&sol, dif),
                reference(&sol, dif),
                "mismatch sol={sol:?} dif={dif}"
            );
        }
    }
}

// --- Caller-facing text contracts ------------------------------------

#[test]
fn secret_debug_redacts_and_error_display_is_stable() {
    // A logged PowSecret must never show key bytes.
    assert_eq!(format!("{:?}", secret()), "PowSecret(..)");
    // Display strings are the caller's log vocabulary. Pin them.
    let cases = [
        (PowError::InvalidTag, "HMAC tag verification failed"),
        (
            PowError::InvalidTimestamp,
            "challenge timestamp has an invalid format",
        ),
        (PowError::Expired, "challenge has expired"),
        (
            PowError::FutureTimestamp,
            "challenge timestamp is in the future",
        ),
        (
            PowError::DifficultyTooLow,
            "solution difficulty is below the required minimum",
        ),
        (
            PowError::InvalidSolution,
            "proof-of-work solution is incorrect",
        ),
        (
            PowError::DifficultyTooHigh,
            "solution difficulty exceeds the supported maximum",
        ),
        (
            PowError::MaxAgeTooLarge,
            "maximum challenge age is too large",
        ),
    ];
    for (err, msg) in cases {
        assert_eq!(err.to_string(), msg);
    }
}

#[test]
fn production_difficulty_guidance_is_above_test_fixtures() {
    let max = MAX_DIFFICULTY;
    let recommended = RECOMMENDED_PRODUCTION_MIN_DIFFICULTY;
    assert_eq!(max, 64);
    assert!(recommended >= 5);
}

// --- Determinism goldens -------------------------------------------------

#[test]
fn mint_is_deterministic_golden() {
    let a = mint_challenge(&secret(), 3, at(TIM_UNIX), entropy()).expect("mint a");
    let b = mint_challenge(&secret(), 3, at(TIM_UNIX), entropy()).expect("mint b");
    assert_eq!(a, b);
    assert_eq!(a.dif, 3);
    assert_eq!(a.tim, TIM);
    // Golden values pin the derivation: chg = hex BLAKE3 of
    // "Time=2026-07-09T12:00:00Z:Nonce=000102030405060708090a0b0c0d0e0f",
    // tag = HMAC-SHA256 over framed ("pow-tag-v1", chg, 3, tim) with key
    // bytes 0..32 (the tag golden was computed externally with Python
    // hmac/hashlib).
    assert_eq!(
        a.chg,
        "c92da1677dc682632c77af723ed48d6ccd288ac1d99f68fcef2ff430433fd6f8"
    );
    assert_eq!(
        a.tag,
        "6d0e8bec7c1c4f0e3c1391ca873df6ffb67eddc32b641ae1cddd39b7c18287a6"
    );
}

#[test]
fn hmac_tag_matches_external_vector() {
    // Computed outside Rust (Python hmac/hashlib) to break circularity:
    // HMAC-SHA256(key=bytes(0..32), framed("pow-tag-v1", "somechg", 3, TIM)).
    assert_eq!(
        hmac_tag_hex(
            &secret(),
            &tag_message("somechg", 3, "2026-07-09T12:00:00Z"),
        ),
        "8b68060e834b2479e05ea4e7f2292500360351c2285ae2546da79502afed9850"
    );
}

// --- Cross-contract vector -----------------------------------------------

#[test]
fn accepts_real_worker_style_vector() {
    // REAL vector for the browser worker algorithm:
    //   sha256(existing challenge chg + "89").hexdigest()
    //     = "007060c2f73f6b7ce87ad3eccac9692a27449d0f012b607359cac1fd8a96d716"
    // i.e. the deterministic minted challenge below, nonce 89 (decimal string,
    // concatenated exactly as the worker does: challenge + nonce), and two
    // leading zero nibbles for dif=2.
    let chg = "c92da1677dc682632c77af723ed48d6ccd288ac1d99f68fcef2ff430433fd6f8";
    let expected_hash = "007060c2f73f6b7ce87ad3eccac9692a27449d0f012b607359cac1fd8a96d716";

    // Guard: our in-test worker mirror reproduces the external vector.
    let (nonce, hash) = solve_like_worker(chg, 2);
    assert_eq!(nonce, 89);
    assert_eq!(hash, expected_hash);

    // verify_solution accepts it (tag minted over the same chg:dif:tim).
    let s = secret();
    let sol = Solution {
        chg: chg.to_string(),
        sol: expected_hash.to_string(),
        non: nonce.to_string(),
        dif: 2,
        tim: TIM.to_string(),
        tag: hmac_tag_hex(&s, &tag_message(chg, 2, TIM)),
    };
    verify_solution(&s, &sol, at(TIM_UNIX + 1), MAX_AGE, 2).unwrap();
}

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
        PowError::MaxAgeTooLarge
    );
}

// --- Properties -------------------------------------------------------
//
// Time is injected as data (fixed TIM/TIM_UNIX constants + a generated
// age), so generation is deterministic apart from proptest's own seeded
// RNG. Case counts are fixed and modest to keep `verify` fast.

use proptest::prelude::*;

/// Replace the hex character at `pos` with a DIFFERENT hex character
/// (nibble XOR with a nonzero delta), preserving length and the lowercase
/// hex alphabet: the smallest possible tamper on a hex-encoded field.
fn mutate_hex(s: &str, pos: prop::sample::Index, nibble_delta: u8) -> String {
    let i = pos.index(s.len());
    let nibble = (s.as_bytes()[i] as char).to_digit(16).expect("hex input") as u8;
    let replacement = char::from_digit(u32::from(nibble ^ nibble_delta), 16).expect("nibble < 16");
    let mut out = s.to_string();
    out.replace_range(i..=i, replacement.encode_utf8(&mut [0u8; 4]));
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// PROPERTY (round trip): for ANY secret, entropy, difficulty 1..=2 and
    /// age within the freshness window, mint -> worker-solve -> verify
    /// succeeds, and the tid is stable across re-verification and equal to
    /// BLAKE3(chg): the replay-safe token identity.
    #[test]
    fn prop_mint_solve_verify_round_trip(
        secret_bytes in prop::array::uniform32(any::<u8>()),
        entropy in prop::array::uniform16(any::<u8>()),
        dif in 1u8..=2,
        age in 0u64..=MAX_AGE,
    ) {
        let s = PowSecret::new(secret_bytes);
        let challenge = mint_challenge(&s, dif, at(TIM_UNIX), entropy).unwrap();
        let (nonce, hash) = solve_like_worker(&challenge.chg, dif);
        let sol = Solution {
            chg: challenge.chg,
            sol: hash,
            non: nonce.to_string(),
            dif,
            tim: challenge.tim,
            tag: challenge.tag,
        };
        let v1 = verify_solution(&s, &sol, at(TIM_UNIX + age), MAX_AGE, dif).unwrap();
        // Replaying the same solve at another valid instant => same tid.
        let v2 = verify_solution(&s, &sol, at(TIM_UNIX), MAX_AGE, 1).unwrap();
        prop_assert_eq!(&v1.tid, &v2.tid);
        prop_assert_eq!(v1.tid, blake3::hash(sol.chg.as_bytes()).to_string());
        // The mint→verify delta is exactly the injected age, in milliseconds.
        prop_assert_eq!(v1.mint_to_verify_ms, Some(age * 1000));
        prop_assert_eq!(v2.mint_to_verify_ms, Some(0));
    }

    /// PROPERTY (single-field tamper): mutating exactly ONE field of a valid
    /// solution always fails verification, with the exact error of the layer
    /// that owns the field: chg/dif/tim/tag are HMAC-bound => InvalidTag
    /// (authenticity is checked FIRST, so even dif=0 downgrades or garbage
    /// tim die there). The sol/non fields are work-bound => InvalidSolution.
    #[test]
    fn prop_single_field_tamper_rejected(
        entropy in prop::array::uniform16(any::<u8>()),
        dif in 1u8..=2,
        field in 0usize..6,
        pos in any::<prop::sample::Index>(),
        nibble_delta in 1u8..16,
        variant in 0usize..3,
        dif_delta in 1u8..=255,
    ) {
        let s = secret();
        let challenge = mint_challenge(&s, dif, at(TIM_UNIX), entropy).unwrap();
        let (nonce, hash) = solve_like_worker(&challenge.chg, dif);
        let mut sol = Solution {
            chg: challenge.chg,
            sol: hash,
            non: nonce.to_string(),
            dif,
            tim: challenge.tim,
            tag: challenge.tag,
        };
        // Sanity: the untampered solution verifies.
        prop_assert!(verify_solution(&s, &sol, at(TIM_UNIX + 1), MAX_AGE, 1).is_ok());

        let expected = match field {
            // chg: any one-nibble change breaks the HMAC binding.
            0 => {
                sol.chg = mutate_hex(&sol.chg, pos, nibble_delta);
                PowError::InvalidTag
            }
            // sol: a one-nibble change (may or may not keep the zero
            // prefix) or an all-zero hash that passes the prefix check.
            1 => {
                sol.sol = if variant == 0 {
                    "0".repeat(64)
                } else {
                    mutate_hex(&sol.sol, pos, nibble_delta)
                };
                PowError::InvalidSolution
            }
            // non: any different decimal string no longer hashes to sol.
            2 => {
                sol.non = match variant {
                    0 => format!("{}0", sol.non),
                    1 => format!("1{}", sol.non),
                    _ => nonce.wrapping_add(1).to_string(),
                };
                PowError::InvalidSolution
            }
            // dif: supported alternate difficulties break the tag. The cheap
            // shape/config gate rejects values above the digest width.
            3 => {
                sol.dif = sol.dif.wrapping_add(dif_delta);
                if sol.dif > MAX_DIFFICULTY {
                    PowError::DifficultyTooHigh
                } else {
                    PowError::InvalidTag
                }
            }
            // tim: a shifted valid timestamp or garbage: tag dies first.
            4 => {
                sol.tim = match variant {
                    0 => "2026-07-09T12:00:01Z".to_string(),
                    1 => "2027-01-01T00:00:00Z".to_string(),
                    _ => "not-a-timestamp".to_string(),
                };
                PowError::InvalidTag
            }
            // tag: one-nibble flip, non-hex bytes, or truncation.
            _ => {
                sol.tag = match variant {
                    0 => mutate_hex(&sol.tag, pos, nibble_delta),
                    1 => "zz-not-hex".to_string(),
                    _ => sol.tag[..sol.tag.len() - 2].to_string(),
                };
                PowError::InvalidTag
            }
        };
        prop_assert_eq!(
            verify_solution(&s, &sol, at(TIM_UNIX + 1), MAX_AGE, 1),
            Err(expected)
        );
    }
}

// --- Tier 1: robustness, official vectors, frozen corpus ----------------

/// Official HMAC-SHA-256 vectors (RFC 4231 §4) validate the primitive
/// independent of our own golden pipeline. A wrong `hmac`/`sha2` version or
/// feature flag cannot pass this.
#[test]
fn hmac_matches_rfc_4231_vectors() {
    // Test Case 1: key = 0x0b * 20 (padded to 32), data = "Hi There".
    let mut k1 = [0u8; 32];
    for b in k1.iter_mut().take(20) {
        *b = 0x0b;
    }
    assert_eq!(
        hmac_tag_hex(&PowSecret::new(k1), b"Hi There"),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    // Test Case 2: key = "Jefe", data = "what do ya want for nothing?".
    let mut k2 = [0u8; 32];
    for (dst, src) in k2.iter_mut().zip(b"Jefe".iter()) {
        *dst = *src;
    }
    assert_eq!(
        hmac_tag_hex(&PowSecret::new(k2), b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// Official BLAKE3 KAT (empty input) validates `chg`'s hasher independently
/// of our own golden.
#[test]
fn blake3_matches_official_empty_kat() {
    assert_eq!(
        blake3::hash(b"").to_string(),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}

/// Robustness: `verify_solution` must never panic on hostile, fully
/// attacker-controlled input: only return Ok or Err. Curated cases
/// (arbitrary-input coverage lives in the proptest below). This one is
/// diagnosis-friendly and fast.
#[test]
#[allow(clippy::type_complexity)]
fn verify_never_panics_on_hostile_inputs() {
    let s = secret();
    let z64 = "0".repeat(64);
    let f64 = "f".repeat(64);
    // (chg, sol, non, tim, tag, dif, now_unix, max_age, min_dif)
    let cases: &[(&str, &str, &str, &str, &str, u8, u64, u64, u8)] = &[
        ("", "", "", "", "", 0, 0, 0, 0),
        ("\0", "\0", "\0", "\0", "\0", 1, 0, 0, 1),
        ("\r\n", " ", " ", " ", " ", 1, 0, 0, 1),
        ("é", "é", "1", "2026-07-09T12:00:00Z", "é", 1, 0, 0, 1),
        (
            "\u{FF10}",
            "\u{FF10}",
            "0",
            "2026-07-09T12:00:00Z",
            "\u{FF10}",
            1,
            0,
            0,
            1,
        ),
        (
            "not-a-timestamp-chg",
            z64.as_str(),
            "0",
            "not-a-timestamp",
            z64.as_str(),
            1,
            0,
            0,
            1,
        ),
        (
            "zz",
            "ff",
            "-1",
            "2026-13-99T99:99:99Z",
            "zz-not-hex",
            255,
            u64::MAX,
            u64::MAX,
            255,
        ),
        (
            z64.as_str(),
            f64.as_str(),
            "999999999999999999999999",
            "2026-07-09T12:00:00Z",
            z64.as_str(),
            0,
            u64::MAX,
            u64::MAX,
            0,
        ),
    ];
    for (chg, sol, non, tim, tag, dif, now, age, min) in cases {
        let _ = verify_solution(
            &s,
            &Solution {
                chg: chg.to_string(),
                sol: sol.to_string(),
                non: non.to_string(),
                dif: *dif,
                tim: tim.to_string(),
                tag: tag.to_string(),
            },
            UnixMillis::from_millis(*now),
            *age,
            *min,
        );
        // Invariant: returned Ok or Err. Reaching here means no panic.
    }
}

/// Frozen wire corpus: a permanent set of challenge/solution vectors
/// anchoring the cross-implementation contract. Later, the browser worker
/// (`dd-protect-client`) must reproduce these exactly. Loaded via
/// `include_str!` so the test stays IO-free at runtime.
#[derive(Debug, serde::Deserialize)]
struct CorpusEntry {
    chg: String,
    dif: u8,
    tim: String,
    tag: String,
    sol: String,
    non: String,
    now_unix: u64,
    max_age: u64,
    min_difficulty: u8,
    ok: bool,
    err: Option<String>,
}

impl CorpusEntry {
    fn expected_error(&self) -> PowError {
        match self.err.as_deref() {
            Some("InvalidTag") => PowError::InvalidTag,
            Some("InvalidTimestamp") => PowError::InvalidTimestamp,
            Some("Expired") => PowError::Expired,
            Some("FutureTimestamp") => PowError::FutureTimestamp,
            Some("DifficultyTooLow") => PowError::DifficultyTooLow,
            Some("InvalidSolution") => PowError::InvalidSolution,
            Some("DifficultyTooHigh") => PowError::DifficultyTooHigh,
            Some("MaxAgeTooLarge") => PowError::MaxAgeTooLarge,
            other => panic!("corpus fixture has unknown err kind {other:?}"),
        }
    }
}

#[test]
fn frozen_corpus_round_trips() {
    let corpus: Vec<CorpusEntry> =
        serde_json::from_str(include_str!("../tests/fixtures/pow_corpus.json"))
            .expect("corpus fixture must parse");
    let expected_errors = BTreeSet::from([
        "DifficultyTooHigh",
        "DifficultyTooLow",
        "Expired",
        "FutureTimestamp",
        "InvalidSolution",
        "InvalidTag",
        "InvalidTimestamp",
        "MaxAgeTooLarge",
    ]);
    let observed_errors = corpus
        .iter()
        .filter_map(|entry| entry.err.as_deref())
        .collect::<BTreeSet<_>>();
    assert_eq!(observed_errors, expected_errors);
    let s = secret();
    for entry in &corpus {
        let sol = Solution {
            chg: entry.chg.clone(),
            sol: entry.sol.clone(),
            non: entry.non.clone(),
            dif: entry.dif,
            tim: entry.tim.clone(),
            tag: entry.tag.clone(),
        };
        // The frozen corpus predates millisecond resolution: its clock is
        // whole unix seconds, converted here at the boundary.
        let result = verify_solution(
            &s,
            &sol,
            at(entry.now_unix),
            entry.max_age,
            entry.min_difficulty,
        );
        if entry.ok {
            assert!(result.is_ok(), "expected Ok for entry: {entry:?}");
        } else {
            assert_eq!(
                result.expect_err("expected Err for corpus entry"),
                entry.expected_error(),
                "error mismatch for entry: {entry:?}"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// PROPERTY (robustness / no-panic): for ANY strings in every field and
    /// any parameter values, `verify_solution` is total: it returns Ok or
    /// Err and never panics. Covers the u64 conversion branches
    /// (`now_unix`/`max_age` at full range) and pure garbage in every text
    /// field. Untrusted input must not be a DoS/oracle.
    #[test]
    fn prop_verify_is_total_on_arbitrary_input(
        chg in ".*",
        sol in ".*",
        non in ".*",
        tim in ".*",
        tag in ".*",
        dif in any::<u8>(),
        now_ms in any::<u64>(),
        max_age in any::<u64>(),
        min_dif in any::<u8>(),
        clock_skew_secs in any::<u64>(),
    ) {
        let s = Solution { chg, sol, non, dif, tim, tag };
        let _ = verify_solution(&secret(), &s, UnixMillis::from_millis(now_ms), max_age, min_dif);
        let _ = verify_solution_with_clock_skew(
            &secret(), &s, UnixMillis::from_millis(now_ms), max_age, min_dif, clock_skew_secs,
        );
    }
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
    for max_age in [MAX_CHALLENGE_MAX_AGE_SECS + 1, u64::MAX] {
        assert_eq!(
            verify_solution(&secret(), &sol, at(TIM_UNIX), max_age, 1),
            Err(PowError::MaxAgeTooLarge)
        );
    }
}
