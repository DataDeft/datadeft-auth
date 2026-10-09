//! Bound-cookie format, freshness, integrity, and totality properties.
//!
//! Needs `test-support` (fixture RNG, derived-key bytes, fixed-nonce Branca).
//!
//! - Golden: one pinned `v1.{kid}.{branca}` value plus the exact encrypted
//!   framing `v(1) || iat(4 BE) || typ_len || typ || kid_len || kid || body`.
//!   A format change fails here.
//! - Time: a reference model of the idle, absolute, and skew bounds is checked
//!   at every boundary (exactly at the bound, one past it), including 0, the
//!   2038 signed rollover, and `u32::MAX`. A crafted `iat > timestamp` is
//!   rejected at parse, not just at mint.
//! - Integrity / canonicality: any single-character edit, truncation, or
//!   extension of a cookie string is rejected, and no second spelling verifies.
//! - Totality: wrapper and cookie parsers never panic on arbitrary strings.

#![cfg(feature = "test-support")]

use datadeft_auth_token_core::TokenError;
use datadeft_auth_token_core::branca;
use datadeft_auth_token_core::cookie::{
    CLOCK_SKEW_TOLERANCE_SECS, MAX_CLOCK_SKEW_SECS, MaxAge, mint_bound_cookie,
    mint_bound_cookie_with_clock_skew, parse_bound_cookie, parse_bound_cookie_with_clock_skew,
    parse_cookie_wrapper,
};
use datadeft_auth_token_core::keyring::{KEY_BYTES, KeyId, KeyPurpose, KeyRing, RootSecret};
use datadeft_auth_token_core::test_support::{FixedBytesRng, test_keyring};
use proptest::prelude::*;

#[derive(Debug)]
enum Golden {}
impl KeyPurpose for Golden {
    const HKDF_INFO: &'static [u8] = b"auth/test-golden-v1";
    const TOKEN_TYPE: &'static str = "test-golden-v1";
    const MAX_BODY_BYTES: usize = 128;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 30 * 24 * 60 * 60;
}

const ROOT: u8 = 0x5a;
const KID: &str = "golden-kid";
const NONCE: [u8; branca::NONCE_BYTES] = [0x24; branca::NONCE_BYTES];

fn ring() -> KeyRing<Golden> {
    test_keyring::<Golden>(ROOT, KID)
}

fn key_bytes() -> [u8; KEY_BYTES] {
    *RootSecret::new([ROOT; KEY_BYTES])
        .derive_key::<Golden>(&KeyId::parse(KID).expect("kid"))
        .expect("derive")
        .as_test_bytes()
}

fn mint_at(body: &[u8], timestamp: u32, iat: u32) -> String {
    let mut rng = FixedBytesRng(NONCE);
    mint_bound_cookie_with_clock_skew::<Golden, _>(
        body,
        &ring(),
        &mut rng,
        timestamp,
        iat,
        u64::from(timestamp),
        0,
    )
    .expect("mint")
}

/// Hand-built encrypted framing, independent of the crate's encoder.
fn framing(iat: u32, typ: &str, kid: &str, body: &[u8]) -> Vec<u8> {
    let mut out = vec![1u8];
    out.extend_from_slice(&iat.to_be_bytes());
    out.push(u8::try_from(typ.len()).expect("typ len"));
    out.extend_from_slice(typ.as_bytes());
    out.push(u8::try_from(kid.len()).expect("kid len"));
    out.extend_from_slice(kid.as_bytes());
    out.extend_from_slice(body);
    out
}

/// Wrap a hand-framed payload under the real key, bypassing mint-side checks.
fn forge_with_real_key(payload: &[u8], timestamp: u32) -> String {
    let token =
        branca::encode_with_nonce(payload, &key_bytes(), &NONCE, timestamp).expect("encode");
    format!("v1.{KID}.{token}")
}

// --- Golden ----------------------------------------------------------------

#[test]
fn bound_cookie_golden_vector_is_pinned() {
    let value = mint_at(b"golden-body", 1_700_000_000, 1_699_999_000);
    assert_eq!(
        value,
        "v1.golden-kid.SwqsletjNAIcQFCjNJtBBYdwPfd0eJXSrY0Us5E4ZJsEzOC8NKBLeQWshFJeailtCaRQ0dIbLallCds0XhSfaaaC9yfN2TxrXKxOqRxZtLiQirFHiMfCq"
    );
}

#[test]
fn encrypted_framing_matches_the_documented_layout() {
    let (ts, iat) = (1_700_000_000, 1_699_999_000);
    let value = mint_at(b"golden-body", ts, iat);
    let token = parse_cookie_wrapper(&value)
        .expect("wrapper")
        .token()
        .to_owned();
    let raw = branca::decode(&token, &key_bytes()).expect("decode");
    assert_eq!(
        raw.payload(),
        framing(iat, Golden::TOKEN_TYPE, KID, b"golden-body").as_slice()
    );
    assert_eq!(raw.timestamp(), ts);
    assert_eq!(raw.nonce(), &NONCE);
    // The hand-built framing under the real key verifies like a minted value.
    let forged = forge_with_real_key(&framing(iat, Golden::TOKEN_TYPE, KID, b"x"), ts);
    let parsed = parse_bound_cookie(&forged, &ring(), u64::from(ts), MaxAge::fixed(3_600))
        .expect("hand framing verifies");
    assert_eq!(parsed.body(), b"x");
}

#[test]
fn malformed_authenticated_framing_is_rejected() {
    let ts = 1_700_000_000u32;
    let now = u64::from(ts);
    let good = framing(ts, Golden::TOKEN_TYPE, KID, b"b");
    let mut bad_version = good.clone();
    bad_version[0] = 2;
    let mut long_typ_len = good.clone();
    long_typ_len[5] = 0xff;
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![1],
        good[..5].to_vec(),
        bad_version,
        long_typ_len,
        // iat after the activity timestamp: rejected at parse, not only mint.
        framing(ts + 1, Golden::TOKEN_TYPE, KID, b"b"),
        framing(ts, "test-golden-v1x", KID, b"b"),
        framing(ts, Golden::TOKEN_TYPE, "other-kid", b"b"),
    ];
    for payload in cases {
        let forged = forge_with_real_key(&payload, ts);
        assert_eq!(
            parse_bound_cookie(&forged, &ring(), now, MaxAge::fixed(3_600)).unwrap_err(),
            TokenError::InvalidToken,
            "payload {payload:?}"
        );
    }
}

// --- Time ----------------------------------------------------------------------

/// Reference model of the documented freshness rules.
fn model_accepts(ts: u64, iat: u64, now: u64, max_age: MaxAge, skew: u64) -> bool {
    iat <= ts
        && ts <= now.saturating_add(skew)
        && iat <= now.saturating_add(skew)
        && now.saturating_sub(ts) <= max_age.idle_secs
        && now.saturating_sub(iat) <= max_age.absolute_secs
}

fn check_boundaries(ts: u32, iat: u32, max_age: MaxAge, skew: u64) {
    let value = mint_at(b"t", ts, iat);
    let (ts64, iat64) = (u64::from(ts), u64::from(iat));
    let mut instants = vec![
        ts64.saturating_sub(skew),
        ts64.saturating_sub(skew + 1),
        ts64,
        ts64 + max_age.idle_secs,
        ts64 + max_age.idle_secs + 1,
        iat64 + max_age.absolute_secs,
        iat64 + max_age.absolute_secs + 1,
        u64::MAX,
    ];
    instants.sort_unstable();
    instants.dedup();
    for now in instants {
        let got = parse_bound_cookie_with_clock_skew(&value, &ring(), now, max_age, skew).is_ok();
        assert_eq!(
            got,
            model_accepts(ts64, iat64, now, max_age, skew),
            "ts={ts} iat={iat} now={now} max_age={max_age:?} skew={skew}"
        );
    }
}

#[test]
fn freshness_boundaries_at_time_extremes() {
    let day: u32 = 86_400;
    for ts in [
        0,
        1,
        1_700_000_000,
        i32::MAX as u32,
        (i32::MAX as u32) + 1,
        u32::MAX,
    ] {
        for skew in [0, 1, CLOCK_SKEW_TOLERANCE_SECS, MAX_CLOCK_SKEW_SECS] {
            check_boundaries(ts, ts, MaxAge::fixed(60), skew);
            check_boundaries(
                ts,
                ts.saturating_sub(day),
                MaxAge::new(3_600, 2 * u64::from(day)),
                skew,
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// The implementation agrees with the reference model at every boundary
    /// for random times, idle/absolute bounds, sliding offsets, and skews.
    #[test]
    fn freshness_matches_reference_model(
        ts in any::<u32>(),
        slide in 0u32..200_000,
        idle in 0u64..=Golden::MAX_ABSOLUTE_AGE_SECS,
        absolute in 0u64..=Golden::MAX_ABSOLUTE_AGE_SECS,
        skew in 0u64..=MAX_CLOCK_SKEW_SECS,
    ) {
        check_boundaries(ts, ts.saturating_sub(slide), MaxAge::new(idle, absolute), skew);
    }

    /// Any single-character substitution anywhere in `v1.{kid}.{token}`
    /// (prefix, separators, kid, or token), any truncation, and any extension
    /// is rejected. If an edit ever verified, it must equal the original.
    #[test]
    fn any_cookie_edit_is_rejected(
        body in prop::collection::vec(any::<u8>(), 0..64),
        pos in any::<prop::sample::Index>(),
        replacement in any::<char>(),
        cut in any::<prop::sample::Index>(),
        suffix in "[0-9A-Za-z.]{1,4}",
    ) {
        let value = mint_at(&body, 1_700_000_000, 1_700_000_000);
        let now = 1_700_000_000u64;
        let bound = MaxAge::fixed(60);

        let mut chars: Vec<char> = value.chars().collect();
        let i = pos.index(chars.len());
        if chars[i] != replacement {
            chars[i] = replacement;
            let edited: String = chars.into_iter().collect();
            prop_assert!(parse_bound_cookie(&edited, &ring(), now, bound).is_err());
        }
        let truncated = &value[..cut.index(value.len())];
        prop_assert!(parse_bound_cookie(truncated, &ring(), now, bound).is_err());
        let extended = format!("{value}{suffix}");
        prop_assert!(parse_bound_cookie(&extended, &ring(), now, bound).is_err());
        let zero_prefixed = value.replacen(&format!("{KID}."), &format!("{KID}.0"), 1);
        prop_assert!(parse_bound_cookie(&zero_prefixed, &ring(), now, bound).is_err());
    }

    /// Totality on arbitrary input, including NUL, control characters,
    /// non-ASCII, and well-shaped wrappers around garbage tokens.
    #[test]
    fn cookie_parsers_are_total(
        raw in "\\PC{0,200}|[\\x00-\\x7f]{0,200}",
        kid in "[A-Za-z0-9_-]{0,70}",
        token in "[0-9A-Za-z]{0,400}",
        now in any::<u64>(),
        idle in any::<u64>(),
        absolute in any::<u64>(),
        skew in any::<u64>(),
    ) {
        let _ = parse_cookie_wrapper(&raw);
        let ring = ring();
        let bound = MaxAge::new(idle, absolute);
        let _ = parse_bound_cookie_with_clock_skew(&raw, &ring, now, bound, skew);
        let shaped = format!("v1.{kid}.{token}");
        let _ = parse_cookie_wrapper(&shaped);
        let _ = parse_bound_cookie_with_clock_skew(&shaped, &ring, now, bound, skew);
    }
}

#[test]
fn huge_cookie_is_rejected_without_panicking() {
    let huge = format!("v1.{KID}.{}", "z".repeat(4 * 1024 * 1024));
    assert_eq!(
        parse_bound_cookie(&huge, &ring(), 0, MaxAge::fixed(60)).unwrap_err(),
        TokenError::InvalidToken
    );
    let mut rng = FixedBytesRng(NONCE);
    assert!(mint_bound_cookie::<Golden, _>(b"x", &ring(), &mut rng, 0, 0, 0).is_ok());
}
