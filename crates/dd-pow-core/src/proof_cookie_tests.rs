//! PoW proof-cookie tests.

use dd_auth_token_core::test_support::{PerCallRng, test_keyring};

use super::*;

const NOW: u64 = 1_781_438_700;
const KID: &str = "test-active";

fn keyring() -> dd_auth_token_core::keyring::KeyRing<PowProofCookie> {
    test_keyring::<PowProofCookie>(0x11, KID)
}

fn test_tid() -> String {
    "ab".repeat(32)
}

#[test]
fn proof_cookie_round_trips_tid() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie = mint_pow_proof_cookie(&test_tid(), &keyring, &mut rng, NOW).expect("cookie mints");

    let verified = verify_pow_proof_cookie(
        cookie.as_secret_value(),
        &keyring,
        NOW + 10,
        DEFAULT_POW_PROOF_TTL_SECS,
    )
    .expect("cookie parses");
    assert_eq!(verified.tid(), test_tid());
}

#[test]
fn proof_cookie_expiry_is_inclusive_at_the_boundary() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie = mint_pow_proof_cookie(&test_tid(), &keyring, &mut rng, NOW).expect("cookie mints");

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
fn verify_rejects_out_of_range_max_age() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie = mint_pow_proof_cookie(&test_tid(), &keyring, &mut rng, NOW).expect("cookie mints");

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
    let cookie = mint_pow_proof_cookie(&test_tid(), &keyring, &mut rng, NOW).expect("cookie mints");

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
    let cookie = mint_pow_proof_cookie(&test_tid(), &keyring(), &mut rng, NOW).expect("mints");

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
            mint_pow_proof_cookie(bad, &keyring, &mut rng, NOW).err(),
            Some(TokenError::InvalidToken),
            "{bad:?} must be rejected"
        );
    }
}

#[test]
fn value_debug_is_redacted() {
    let keyring = keyring();
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie = mint_pow_proof_cookie(&test_tid(), &keyring, &mut rng, NOW).expect("mints");
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
