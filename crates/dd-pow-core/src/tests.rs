//! Tests for the proof-of-work core. Time/entropy are injected data, so
//! generation is deterministic apart from proptest's own seeded RNG.

use crate::challenge::Solution;
use crate::error::PowError;
use crate::ops::{has_leading_zero_prefix, hmac_tag_hex, tag_message};
use crate::secret::PowSecret;
use crate::{MAX_FUTURE_SKEW_SECS, mint_challenge, verify_solution};
use sha2::{Digest, Sha256};

const TIM: &str = "2026-07-09T12:00:00Z";
/// Unix timestamp of TIM (2026-07-09T12:00:00Z).
const TIM_UNIX: u64 = 1_783_598_400;
const MAX_AGE: u64 = 300;

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
    let challenge = mint_challenge(&secret(), dif, TIM, entropy());
    let (nonce, hash) = solve_like_worker(&challenge.chg, dif);
    // Field mapping as the client builds its Solution JSON: chg/tim/tag
    // echoed, sol = hash, non = nonce.toString(). dif is NOT sent by the
    // client; the API layer fills it with the server's difficulty.
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
    // Display strings are the caller's log vocabulary; pin them.
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
    ];
    for (err, msg) in cases {
        assert_eq!(err.to_string(), msg);
    }
}

// --- Determinism goldens -------------------------------------------------

#[test]
fn mint_is_deterministic_golden() {
    let a = mint_challenge(&secret(), 3, TIM, entropy());
    let b = mint_challenge(&secret(), 3, TIM, entropy());
    assert_eq!(a, b);
    assert_eq!(a.dif, 3);
    assert_eq!(a.tim, TIM);
    // Golden values pin the derivation: chg = hex BLAKE3 of
    // "Time=2026-07-09T12:00:00Z:Nonce=000102030405060708090a0b0c0d0e0f",
    // tag = HMAC-SHA256 over "{chg}:3:{tim}" with key bytes 0..32 (the tag
    // golden was computed externally with Python hmac/hashlib).
    assert_eq!(
        a.chg,
        "c92da1677dc682632c77af723ed48d6ccd288ac1d99f68fcef2ff430433fd6f8"
    );
    assert_eq!(
        a.tag,
        "401ccf864ad13ea45e065748ee51656811f4d472a45f32a4ee78b04a174de972"
    );
}

#[test]
fn hmac_tag_matches_external_vector() {
    // Computed outside Rust (Python hmac/hashlib) to break circularity:
    // HMAC-SHA256(key=bytes(0..32), "somechg:3:2026-07-09T12:00:00Z").
    assert_eq!(
        hmac_tag_hex(&secret(), "somechg:3:2026-07-09T12:00:00Z"),
        "c4ce585fc371a811032d5b5d269a60543cc5ec580361982daa20402e54084bd3"
    );
}

// --- Cross-contract vector -----------------------------------------------

#[test]
fn accepts_real_worker_style_vector() {
    // REAL vector for the browser worker algorithm, computed externally
    // (Python hashlib):
    //   sha256("cross-contract-vector" + "3").hexdigest()
    //     = "00a3d6e01cb95126d77b7dfc73fb0036827e6cfc83bc9fbad1f8dbcebd248b95"
    // i.e. challenge "cross-contract-vector", nonce 3 (decimal string,
    // concatenated exactly as the worker does: challenge + nonce), and the
    // digest happens to have two leading zero nibbles, satisfying dif=2.
    let chg = "cross-contract-vector";
    let expected_hash = "00a3d6e01cb95126d77b7dfc73fb0036827e6cfc83bc9fbad1f8dbcebd248b95";

    // Guard: our in-test worker mirror reproduces the external vector.
    let (nonce, hash) = solve_like_worker(chg, 2);
    assert_eq!(nonce, 3);
    assert_eq!(hash, expected_hash);

    // verify_solution accepts it (tag minted over the same chg:dif:tim).
    let s = secret();
    let sol = Solution {
        chg: chg.to_string(),
        sol: expected_hash.to_string(),
        non: "3".to_string(),
        dif: 2,
        tim: TIM.to_string(),
        tag: hmac_tag_hex(&s, &tag_message(chg, 2, TIM)),
    };
    verify_solution(&s, &sol, TIM_UNIX + 1, MAX_AGE, 2).unwrap();
}

// --- Tamper (examples the property does not construct) ----------------

#[test]
fn wrong_secret_rejected() {
    let sol = solved_solution(1);
    let other = PowSecret::new([0x42; 32]);
    assert_eq!(
        verify_solution(&other, &sol, TIM_UNIX + 1, MAX_AGE, 1),
        Err(PowError::InvalidTag)
    );
}

#[test]
fn solution_for_different_challenge_rejected() {
    // Valid tag/chg from challenge A, but sol/non solve challenge B.
    let a = mint_challenge(&secret(), 1, TIM, entropy());
    let b = mint_challenge(&secret(), 1, TIM, [0xFF; 16]);
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
        verify_solution(&secret(), &sol, TIM_UNIX + 1, MAX_AGE, 1),
        Err(PowError::InvalidSolution)
    );
}

#[test]
fn missing_leading_zeros_rejected() {
    // Honest hash of chg+non, but the nonce does no work (no zeros).
    let challenge = mint_challenge(&secret(), 1, TIM, entropy());
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
        verify_solution(&secret(), &sol, TIM_UNIX + 1, MAX_AGE, 1),
        Err(PowError::InvalidSolution)
    );
}

// --- Expiry ---------------------------------------------------------

#[test]
fn stale_tim_rejected() {
    let sol = solved_solution(1);
    assert_eq!(
        verify_solution(&secret(), &sol, TIM_UNIX + MAX_AGE + 1, MAX_AGE, 1),
        Err(PowError::Expired)
    );
}

#[test]
fn expiry_boundary_accepted() {
    let sol = solved_solution(1);
    // age == max_age exactly: still valid.
    verify_solution(&secret(), &sol, TIM_UNIX + MAX_AGE, MAX_AGE, 1).unwrap();
}

#[test]
fn future_tim_rejected() {
    let sol = solved_solution(1);
    // now is MAX_FUTURE_SKEW_SECS + 1 before tim => beyond allowed skew.
    assert_eq!(
        verify_solution(
            &secret(),
            &sol,
            TIM_UNIX - MAX_FUTURE_SKEW_SECS - 1,
            MAX_AGE,
            1
        ),
        Err(PowError::FutureTimestamp)
    );
}

#[test]
fn future_tim_within_skew_accepted() {
    let sol = solved_solution(1);
    verify_solution(&secret(), &sol, TIM_UNIX - MAX_FUTURE_SKEW_SECS, MAX_AGE, 1).unwrap();
}

#[test]
fn garbage_tim_needs_valid_tag_first() {
    // A non-RFC3339 tim with a correctly minted tag reaches the timestamp
    // check and fails there (proves order: authenticity before parsing).
    let s = secret();
    let chg = "garbage-tim-chg";
    let sol = Solution {
        chg: chg.to_string(),
        sol: "0".repeat(64),
        non: "0".to_string(),
        dif: 1,
        tim: "not-a-timestamp".to_string(),
        tag: hmac_tag_hex(&s, &tag_message(chg, 1, "not-a-timestamp")),
    };
    assert_eq!(
        verify_solution(&s, &sol, TIM_UNIX, MAX_AGE, 1),
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
        verify_solution(&secret(), &sol, TIM_UNIX + 1, MAX_AGE, 2),
        Err(PowError::DifficultyTooLow)
    );
}

#[test]
fn higher_difficulty_than_min_accepted() {
    let sol = solved_solution(2);
    verify_solution(&secret(), &sol, TIM_UNIX + 1, MAX_AGE, 1).unwrap();
}

// --- Properties -------------------------------------------------------
//
// Time is injected as data (fixed TIM/TIM_UNIX constants + a generated
// age), so generation is deterministic apart from proptest's own seeded
// RNG; case counts are fixed and modest to keep `verify` fast.

use proptest::prelude::*;

/// Replace the hex character at `pos` with a DIFFERENT hex character
/// (nibble XOR with a nonzero delta), preserving length and the lowercase
/// hex alphabet — the smallest possible tamper on a hex-encoded field.
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
    /// BLAKE3(chg) — the replay-safe token identity.
    #[test]
    fn prop_mint_solve_verify_round_trip(
        secret_bytes in prop::array::uniform32(any::<u8>()),
        entropy in prop::array::uniform16(any::<u8>()),
        dif in 1u8..=2,
        age in 0u64..=MAX_AGE,
    ) {
        let s = PowSecret::new(secret_bytes);
        let challenge = mint_challenge(&s, dif, TIM, entropy);
        let (nonce, hash) = solve_like_worker(&challenge.chg, dif);
        let sol = Solution {
            chg: challenge.chg,
            sol: hash,
            non: nonce.to_string(),
            dif,
            tim: challenge.tim,
            tag: challenge.tag,
        };
        let v1 = verify_solution(&s, &sol, TIM_UNIX + age, MAX_AGE, dif).unwrap();
        // Replaying the same solve at another valid instant => same tid.
        let v2 = verify_solution(&s, &sol, TIM_UNIX, MAX_AGE, 1).unwrap();
        prop_assert_eq!(&v1.tid, &v2.tid);
        prop_assert_eq!(v1.tid, blake3::hash(sol.chg.as_bytes()).to_string());
    }

    /// PROPERTY (single-field tamper): mutating exactly ONE field of a valid
    /// solution always fails verification, with the exact error of the layer
    /// that owns the field: chg/dif/tim/tag are HMAC-bound => InvalidTag
    /// (authenticity is checked FIRST, so even dif=0 downgrades or garbage
    /// tim die there); sol/non are work-bound => InvalidSolution.
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
        let challenge = mint_challenge(&s, dif, TIM, entropy);
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
        prop_assert!(verify_solution(&s, &sol, TIM_UNIX + 1, MAX_AGE, 1).is_ok());

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
            // dif: ANY other claimed difficulty (including 0) breaks the tag.
            3 => {
                sol.dif = sol.dif.wrapping_add(dif_delta);
                PowError::InvalidTag
            }
            // tim: a shifted valid timestamp or garbage — tag dies first.
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
            verify_solution(&s, &sol, TIM_UNIX + 1, MAX_AGE, 1),
            Err(expected)
        );
    }
}
