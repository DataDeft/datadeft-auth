//! Property tests: round trip, single-field tamper, totality on arbitrary input.

//! Tests for the proof-of-work core. Time/entropy are injected data, so
//! generation is deterministic apart from proptest's own seeded RNG.

use crate::challenge::Solution;
use crate::clock::UnixMillis;
use crate::error::PowError;
use crate::secret::PowSecret;
use crate::{MAX_DIFFICULTY, mint_challenge, verify_solution, verify_solution_with_clock_skew};

use super::test_support::*;

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
