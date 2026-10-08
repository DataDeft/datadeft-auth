//! PoW proof-cookie tests.

use datadeft_auth_token_core::test_support::{PerCallRng, test_keyring};

use super::*;

const NOW: u64 = 1_781_438_700;
const KID: &str = "test-active";

fn keyring() -> datadeft_auth_token_core::keyring::KeyRing<PowProofCookie> {
    test_keyring::<PowProofCookie>(0x11, KID)
}

fn test_tid() -> String {
    "ab".repeat(32)
}

#[test]
fn proof_cookie_round_trips_tid() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie =
        mint_pow_proof_cookie(&test_tid(), None, &keyring, &mut rng, NOW).expect("cookie mints");

    let verified = verify_pow_proof_cookie(
        cookie.as_secret_value(),
        &keyring,
        NOW + 10,
        DEFAULT_POW_PROOF_TTL_SECS,
    )
    .expect("cookie parses");
    assert_eq!(verified.tid(), test_tid());
    // A v1 cookie (minted without a class) reports no solve class.
    assert_eq!(verified.solve_class(), None);
}

#[test]
fn v2_proof_cookie_round_trips_solve_class() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    // Every byte value is opaque app data, including 0.
    for class in [0u8, 1, 3, 255] {
        let cookie = mint_pow_proof_cookie(&test_tid(), Some(class), &keyring, &mut rng, NOW)
            .expect("cookie mints");
        let verified = verify_pow_proof_cookie(
            cookie.as_secret_value(),
            &keyring,
            NOW + 10,
            DEFAULT_POW_PROOF_TTL_SECS,
        )
        .expect("cookie parses");
        assert_eq!(verified.tid(), test_tid());
        assert_eq!(verified.solve_class(), Some(class));
    }
}

/// The v1 integration contract fits kids up to 12 bytes; the one-byte-larger
/// v2 body must not shrink that budget (pinned by `MAX_BODY_BYTES = 65`).
#[test]
fn v2_body_fits_with_a_twelve_byte_kid() {
    let keyring = test_keyring::<PowProofCookie>(0x33, "kid-12-bytes");
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie = mint_pow_proof_cookie(&test_tid(), Some(7), &keyring, &mut rng, NOW)
        .expect("v2 body must mint under a 12-byte kid");
    let verified = verify_pow_proof_cookie(
        cookie.as_secret_value(),
        &keyring,
        NOW + 1,
        DEFAULT_POW_PROOF_TTL_SECS,
    )
    .expect("cookie parses");
    assert_eq!(verified.solve_class(), Some(7));
}

/// Version and length must pair exactly: an unknown version byte, a v1 tag
/// with a trailing byte, or a v2 tag without one are all malformed. Bodies
/// are crafted with the generic bound-cookie mint the proof cookie itself
/// uses, so only the body shape is wrong.
#[test]
fn verify_rejects_mismatched_body_version_and_length() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let now_u32 = u32::try_from(NOW).expect("fixture fits u32");
    let bad_bodies: &[&[u8]] = &[
        &[3u8; 34], // unknown version
        &[1u8; 34], // v1 tag, v2 length
        &[2u8; 33], // v2 tag, v1 length
        &[1u8; 1],  // version byte only
        &[2u8; 35], // v2 tag, trailing junk
    ];
    for bad_body in bad_bodies {
        let cookie = mint_bound_cookie::<PowProofCookie, _>(
            bad_body, &keyring, &mut rng, now_u32, now_u32, NOW,
        )
        .expect("bound cookie mints");
        assert_eq!(
            verify_pow_proof_cookie(&cookie, &keyring, NOW + 1, DEFAULT_POW_PROOF_TTL_SECS).err(),
            Some(TokenError::InvalidToken),
            "body {bad_body:?} must be rejected"
        );
    }
}

#[test]
fn proof_cookie_expiry_is_inclusive_at_the_boundary() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie =
        mint_pow_proof_cookie(&test_tid(), None, &keyring, &mut rng, NOW).expect("cookie mints");

    let boundary = NOW + DEFAULT_POW_PROOF_TTL_SECS;
    assert!(
        verify_pow_proof_cookie(
            cookie.as_secret_value(),
            &keyring,
            boundary,
            DEFAULT_POW_PROOF_TTL_SECS
        )
        .is_ok()
    );
    assert_eq!(
        verify_pow_proof_cookie(
            cookie.as_secret_value(),
            &keyring,
            boundary + 1,
            DEFAULT_POW_PROOF_TTL_SECS
        )
        .err(),
        Some(TokenError::InvalidToken)
    );
}

#[test]
fn proof_cookie_accepts_configured_skew_boundary_and_rejects_beyond_it() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie =
        mint_pow_proof_cookie(&test_tid(), None, &keyring, &mut rng, NOW).expect("cookie mints");

    for clock_skew_secs in [0, 30, 60] {
        assert!(
            verify_pow_proof_cookie_with_clock_skew(
                cookie.as_secret_value(),
                &keyring,
                NOW - clock_skew_secs,
                DEFAULT_POW_PROOF_TTL_SECS,
                clock_skew_secs,
            )
            .is_ok()
        );
        assert_eq!(
            verify_pow_proof_cookie_with_clock_skew(
                cookie.as_secret_value(),
                &keyring,
                NOW - clock_skew_secs - 1,
                DEFAULT_POW_PROOF_TTL_SECS,
                clock_skew_secs,
            )
            .err(),
            Some(TokenError::InvalidToken)
        );
    }
}

#[test]
fn proof_cookie_default_skew_remains_sixty_seconds() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie =
        mint_pow_proof_cookie(&test_tid(), None, &keyring, &mut rng, NOW).expect("cookie mints");

    for offset_secs in [0, 30, 31, 60, 61] {
        assert_eq!(
            verify_pow_proof_cookie(
                cookie.as_secret_value(),
                &keyring,
                NOW - offset_secs,
                DEFAULT_POW_PROOF_TTL_SECS,
            ),
            verify_pow_proof_cookie_with_clock_skew(
                cookie.as_secret_value(),
                &keyring,
                NOW - offset_secs,
                DEFAULT_POW_PROOF_TTL_SECS,
                60,
            )
        );
    }
}

#[test]
fn proof_cookie_configured_skew_preserves_expiry_and_handles_full_u64_range() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie =
        mint_pow_proof_cookie(&test_tid(), None, &keyring, &mut rng, NOW).expect("cookie mints");
    let boundary = NOW + DEFAULT_POW_PROOF_TTL_SECS;

    for clock_skew_secs in [0, 30, 60, u64::MAX] {
        assert!(
            verify_pow_proof_cookie_with_clock_skew(
                cookie.as_secret_value(),
                &keyring,
                boundary,
                DEFAULT_POW_PROOF_TTL_SECS,
                clock_skew_secs,
            )
            .is_ok()
        );
        for now_unix in [boundary + 1, u64::MAX] {
            assert_eq!(
                verify_pow_proof_cookie_with_clock_skew(
                    cookie.as_secret_value(),
                    &keyring,
                    now_unix,
                    DEFAULT_POW_PROOF_TTL_SECS,
                    clock_skew_secs,
                )
                .err(),
                Some(TokenError::InvalidToken)
            );
        }
    }
    assert!(
        verify_pow_proof_cookie_with_clock_skew(
            cookie.as_secret_value(),
            &keyring,
            0,
            DEFAULT_POW_PROOF_TTL_SECS,
            u64::MAX,
        )
        .is_ok()
    );
}

#[test]
fn verify_rejects_out_of_range_max_age() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie =
        mint_pow_proof_cookie(&test_tid(), None, &keyring, &mut rng, NOW).expect("cookie mints");

    for bad in [0, POW_PROOF_MAX_AGE_SECS + 1] {
        assert_eq!(
            verify_pow_proof_cookie(cookie.as_secret_value(), &keyring, NOW + 1, bad).err(),
            Some(TokenError::InvalidToken)
        );
    }
}

#[test]
fn verify_rejects_tampering_and_garbage() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie =
        mint_pow_proof_cookie(&test_tid(), None, &keyring, &mut rng, NOW).expect("cookie mints");

    let mut tampered = cookie.as_secret_value().to_owned();
    tampered.pop();
    for bad in [tampered.as_str(), "not-a-cookie", "", "v1..", "v1.kid."] {
        assert!(
            verify_pow_proof_cookie(bad, &keyring, NOW + 1, DEFAULT_POW_PROOF_TTL_SECS).is_err(),
            "{bad:?} must be rejected"
        );
    }
}

#[test]
fn proof_cookie_from_a_different_keyring_is_rejected() {
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie =
        mint_pow_proof_cookie(&test_tid(), None, &keyring(), &mut rng, NOW).expect("mints");

    let other = test_keyring::<PowProofCookie>(0x22, KID);
    assert_eq!(
        verify_pow_proof_cookie(
            cookie.as_secret_value(),
            &other,
            NOW + 1,
            DEFAULT_POW_PROOF_TTL_SECS
        )
        .err(),
        Some(TokenError::InvalidToken)
    );
}

#[test]
fn mint_rejects_malformed_tid() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    for bad in ["", "abc", &"AB".repeat(32), &"zz".repeat(32)] {
        assert_eq!(
            mint_pow_proof_cookie(bad, None, &keyring, &mut rng, NOW).err(),
            Some(TokenError::InvalidToken),
            "{bad:?} must be rejected"
        );
    }
}

#[test]
fn value_debug_is_redacted() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie = mint_pow_proof_cookie(&test_tid(), None, &keyring, &mut rng, NOW).expect("mints");
    assert_eq!(format!("{cookie:?}"), "PowProofCookieValue(..)");

    let verified = verify_pow_proof_cookie(
        cookie.as_secret_value(),
        &keyring,
        NOW + 1,
        DEFAULT_POW_PROOF_TTL_SECS,
    )
    .expect("parses");
    assert_eq!(format!("{verified:?}"), "VerifiedPowProof(..)");
}
