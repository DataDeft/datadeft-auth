//! Golden, cross-contract, and official vectors, text contracts, and the frozen corpus.

//! Tests for the proof-of-work core. Time/entropy are injected data, so
//! generation is deterministic apart from proptest's own seeded RNG.

use crate::challenge::Solution;
use crate::clock::UnixMillis;
use crate::error::PowError;
use crate::ops::{has_leading_zero_prefix, hmac_tag_hex, tag_message};
use crate::secret::PowSecret;
use crate::{
    MAX_DIFFICULTY, RECOMMENDED_PRODUCTION_MIN_DIFFICULTY, mint_challenge, verify_solution,
};
use std::collections::BTreeSet;

use super::test_support::*;

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
            PowError::InvalidMaxAge,
            "maximum challenge age is out of range",
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
            Some("InvalidMaxAge") => PowError::InvalidMaxAge,
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
        "InvalidMaxAge",
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
