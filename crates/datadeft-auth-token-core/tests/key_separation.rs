//! Key separation, rotation, HKDF known-answer, and redaction properties.
//!
//! Needs `test-support` (fixture RNG, unbounded test slots, derived-key bytes).
//! `mise run test` enables it via `--all-features`.
//!
//! - HKDF-SHA256: an independent from-scratch HMAC/HKDF reference is checked
//!   against RFC 4231 and RFC 5869, then `RootSecret::derive_key` must equal
//!   the reference for random roots and kids under the documented
//!   `info = HKDF_INFO || 0x00 || kid` framing.
//! - Purpose separation: a cookie minted for one purpose never verifies as
//!   another, even under the same root and kid; key separation and the
//!   encrypted `typ` binding are each sufficient on their own.
//! - Rotation: verify-only keys verify but never mint (no fallback), removed
//!   kids and closed windows fail, and wrapper kid swaps fail.
//! - Redaction: no secret type's `Debug` contains its secret bytes.

#![cfg(feature = "test-support")]

use datadeft_auth_token_core::TokenError;
use datadeft_auth_token_core::branca;
use datadeft_auth_token_core::cookie::{
    MaxAge, mint_bound_cookie, parse_bound_cookie, parse_cookie_wrapper,
};
use datadeft_auth_token_core::keyring::{
    KEY_BYTES, KeyId, KeyPurpose, KeyRing, KeySlot, KeyStatus, RootSecret,
};
use datadeft_auth_token_core::test_support::{FixedBytesRng, PerCallRng, test_keyring};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

// --- Purposes ----------------------------------------------------------------

#[derive(Debug)]
enum PurposeA {}
impl KeyPurpose for PurposeA {
    const HKDF_INFO: &'static [u8] = b"auth/test-a-v1";
    const TOKEN_TYPE: &'static str = "test-a-v1";
    const MAX_BODY_BYTES: usize = 128;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 3_600;
}

/// Same `typ` as A, different HKDF info: only key separation stops it.
#[derive(Debug)]
enum SameTypOtherInfo {}
impl KeyPurpose for SameTypOtherInfo {
    const HKDF_INFO: &'static [u8] = b"auth/test-a-v2";
    const TOKEN_TYPE: &'static str = "test-a-v1";
    const MAX_BODY_BYTES: usize = 128;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 3_600;
}

/// Same HKDF info as A (so the same key), different `typ`: only the encrypted
/// `typ` binding stops it.
#[derive(Debug)]
enum SameInfoOtherTyp {}
impl KeyPurpose for SameInfoOtherTyp {
    const HKDF_INFO: &'static [u8] = b"auth/test-a-v1";
    const TOKEN_TYPE: &'static str = "test-b-v1";
    const MAX_BODY_BYTES: usize = 128;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 3_600;
}

/// Mirrors of the product purposes. Their constants are pinned in the owning
/// crates (`session_body_tests`, `confirm_cookie_tests`, `proof_cookie_tests`);
/// this crate cannot depend on them, so the literals are repeated here.
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

#[derive(Debug)]
enum MirrorPowProof {}
impl KeyPurpose for MirrorPowProof {
    const HKDF_INFO: &'static [u8] = b"auth/pow-proof-v1";
    const TOKEN_TYPE: &'static str = "pow-proof-v1";
    const MAX_BODY_BYTES: usize = 65;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 24 * 60 * 60;
}

const NOW: u64 = 1_000_000;

fn kid(value: &str) -> KeyId {
    KeyId::parse(value).expect("kid parses")
}

fn mint<P: KeyPurpose>(ring: &KeyRing<P>, body: &[u8]) -> String {
    let mut rng = FixedBytesRng([0x5c; branca::NONCE_BYTES]);
    let ts = u32::try_from(NOW).expect("fits");
    mint_bound_cookie::<P, _>(body, ring, &mut rng, ts, ts, NOW).expect("mint")
}

fn verifies<P: KeyPurpose>(value: &str, ring: &KeyRing<P>) -> bool {
    parse_bound_cookie::<P>(value, ring, NOW, MaxAge::fixed(60)).is_ok()
}

// --- Independent HMAC-SHA256 / HKDF-SHA256 reference (RFC 2104 / RFC 5869) --

fn ref_hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn ref_hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> (Vec<u8>, [u8; 32]) {
    let prk = ref_hmac(salt, ikm);
    let mut okm = Vec::new();
    let mut previous: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut message = previous.clone();
        message.extend_from_slice(info);
        message.push(counter);
        previous = ref_hmac(&prk, &message).to_vec();
        okm.extend_from_slice(&previous);
        counter += 1;
    }
    okm.truncate(len);
    (okm, prk)
}

#[test]
fn reference_hmac_matches_rfc_4231() {
    // Test Case 1, 2, and 6 (key longer than the block size).
    assert_eq!(
        hex::encode(ref_hmac(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex::encode(ref_hmac(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(
        hex::encode(ref_hmac(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn reference_and_linked_hkdf_match_rfc_5869() {
    let ikm = [0x0b; 22];
    // Test Case 1.
    let salt: Vec<u8> = (0x00..=0x0c).collect();
    let info: Vec<u8> = (0xf0..=0xf9).collect();
    let (okm, prk) = ref_hkdf(&salt, &ikm, &info, 42);
    assert_eq!(
        hex::encode(prk),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    let tc1 =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
    assert_eq!(hex::encode(&okm), tc1);
    // Test Case 3: zero-length salt and info. A zero-length salt equals the
    // `salt = None` (HashLen zeros) form `derive_key` uses.
    let tc3 =
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";
    let (okm, prk) = ref_hkdf(&[], &ikm, &[], 42);
    assert_eq!(
        hex::encode(prk),
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    );
    assert_eq!(hex::encode(&okm), tc3);
    assert_eq!(ref_hkdf(&[0u8; 32], &ikm, &[], 42).0, okm);

    // The linked `hkdf` crate (what `derive_key` calls) agrees on both.
    let mut out = [0u8; 42];
    hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm)
        .expand(&info, &mut out)
        .expect("expand");
    assert_eq!(hex::encode(out), tc1);
    hkdf::Hkdf::<Sha256>::new(None, &ikm)
        .expand(&[], &mut out)
        .expect("expand");
    assert_eq!(hex::encode(out), tc3);
}

/// Every purpose's HKDF info is distinct, NUL-free (so `info || 0x00 || kid`
/// is an injective framing given the NUL-free `KeyId` charset), and no `typ`
/// repeats.
#[test]
fn product_purpose_constants_are_pairwise_distinct_and_nul_free() {
    let infos: [&[u8]; 3] = [
        MirrorSession::HKDF_INFO,
        MirrorConfirm::HKDF_INFO,
        MirrorPowProof::HKDF_INFO,
    ];
    let typs = [
        MirrorSession::TOKEN_TYPE,
        MirrorConfirm::TOKEN_TYPE,
        MirrorPowProof::TOKEN_TYPE,
    ];
    for (i, a) in infos.iter().enumerate() {
        assert!(!a.contains(&0), "HKDF info must be NUL-free");
        for b in &infos[i + 1..] {
            assert_ne!(a, b);
        }
    }
    for (i, a) in typs.iter().enumerate() {
        for b in &typs[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn product_purposes_never_cross_verify_under_one_root_and_kid() {
    let session = test_keyring::<MirrorSession>(0x77, "shared");
    let confirm = test_keyring::<MirrorConfirm>(0x77, "shared");
    let pow = test_keyring::<MirrorPowProof>(0x77, "shared");
    let s = mint(&session, b"body");
    let c = mint(&confirm, b"body");
    let p = mint(&pow, b"body");

    assert!(verifies(&s, &session) && verifies(&c, &confirm) && verifies(&p, &pow));
    assert!(!verifies(&s, &confirm) && !verifies(&s, &pow));
    assert!(!verifies(&c, &session) && !verifies(&c, &pow));
    assert!(!verifies(&p, &session) && !verifies(&p, &confirm));
}

#[test]
fn key_separation_alone_and_typ_binding_alone_each_reject_cross_purpose() {
    let a = test_keyring::<PurposeA>(0x31, "k1");
    let value = mint(&a, b"body");
    assert!(verifies(&value, &a));
    // Same typ, different key: AEAD fails.
    assert!(!verifies(
        &value,
        &test_keyring::<SameTypOtherInfo>(0x31, "k1")
    ));
    // Same key, different typ: decrypts, then the encrypted typ check fails.
    assert!(!verifies(
        &value,
        &test_keyring::<SameInfoOtherTyp>(0x31, "k1")
    ));
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// `derive_key` is exactly HKDF-SHA256(salt = none, IKM = root,
    /// info = HKDF_INFO || 0x00 || kid, L = 32), checked against the
    /// independent reference above. Distinct kids or purposes give distinct keys.
    #[test]
    fn derive_key_matches_reference_hkdf(
        root in prop::array::uniform32(any::<u8>()),
        kid_a in "[A-Za-z0-9_-]{1,64}",
        kid_b in "[A-Za-z0-9_-]{1,64}",
    ) {
        let secret = RootSecret::new(root);
        for kid_str in [&kid_a, &kid_b] {
            let derived = secret.derive_key::<PurposeA>(&kid(kid_str)).expect("derive");
            let mut info = PurposeA::HKDF_INFO.to_vec();
            info.push(0);
            info.extend_from_slice(kid_str.as_bytes());
            let (expected, _) = ref_hkdf(&[], &root, &info, KEY_BYTES);
            prop_assert_eq!(derived.as_test_bytes().as_slice(), expected.as_slice());
        }
        let a = secret.derive_key::<PurposeA>(&kid(&kid_a)).expect("derive");
        let b = secret.derive_key::<PurposeA>(&kid(&kid_b)).expect("derive");
        prop_assert_eq!(kid_a == kid_b, a.as_test_bytes() == b.as_test_bytes());
        let other = secret.derive_key::<SameTypOtherInfo>(&kid(&kid_a)).expect("derive");
        prop_assert_ne!(a.as_test_bytes(), other.as_test_bytes());
    }
}

// --- Rotation ----------------------------------------------------------------

fn slot<P: KeyPurpose>(root: u8, kid_str: &str) -> datadeft_auth_token_core::keyring::BrancaKey<P> {
    RootSecret::new([root; KEY_BYTES])
        .derive_key::<P>(&kid(kid_str))
        .expect("derive")
}

#[test]
fn verify_only_key_verifies_until_its_window_and_never_mints() {
    let old = test_keyring::<PurposeA>(0x41, "old");
    let value = mint(&old, b"body");
    let verify_until = NOW + 10;
    let rotated = KeyRing::<PurposeA>::new(vec![
        KeySlot::active(kid("new"), slot(0x42, "new")),
        KeySlot::verify_only(kid("old"), slot(0x41, "old"), verify_until),
    ])
    .expect("ring");

    for now in [NOW, verify_until] {
        assert!(parse_bound_cookie(&value, &rotated, now, MaxAge::fixed(60)).is_ok());
    }
    assert_eq!(
        parse_bound_cookie(&value, &rotated, verify_until + 1, MaxAge::fixed(60)).unwrap_err(),
        TokenError::InvalidToken
    );
    // New values always carry the active kid.
    let fresh = mint(&rotated, b"body");
    assert!(fresh.starts_with("v1.new."));
    assert_eq!(rotated.active().status(), KeyStatus::Active);

    // Removing the old kid makes the old cookie unknown.
    let removed = test_keyring::<PurposeA>(0x42, "new");
    assert!(!verifies(&value, &removed));
}

#[test]
fn expired_active_key_never_falls_back_to_a_verify_only_key() {
    let mint_until = NOW - 1;
    let ring = KeyRing::<PurposeA>::new(vec![
        KeySlot::active_with_windows(
            kid("new"),
            slot(0x51, "new"),
            mint_until,
            mint_until + PurposeA::MAX_ABSOLUTE_AGE_SECS,
        ),
        KeySlot::verify_only(kid("old"), slot(0x50, "old"), u64::MAX),
    ])
    .expect("ring");
    let mut rng = PerCallRng::starting_at(1);
    let ts = u32::try_from(NOW).expect("fits");
    assert_eq!(
        mint_bound_cookie::<PurposeA, _>(b"body", &ring, &mut rng, ts, ts, NOW).unwrap_err(),
        TokenError::KeyExpired
    );
    // A ring of only verify-only keys cannot be built at all.
    assert_eq!(
        KeyRing::<PurposeA>::new(vec![KeySlot::verify_only(
            kid("old"),
            slot(0x50, "old"),
            u64::MAX
        )])
        .unwrap_err(),
        TokenError::KeyringMisconfigured
    );
}

#[test]
fn wrapper_kid_swap_is_rejected_by_key_and_by_encrypted_kid() {
    let value = mint(&test_keyring::<PurposeA>(0x61, "k-a"), b"body");
    let token = parse_cookie_wrapper(&value)
        .expect("wrapper")
        .token()
        .to_owned();
    let swapped = format!("v1.k-b.{token}");

    // Correctly derived k-b: a different key, so AEAD fails.
    let ring = KeyRing::<PurposeA>::new(vec![
        KeySlot::active(kid("k-a"), slot(0x61, "k-a")),
        KeySlot::verify_only(kid("k-b"), slot(0x61, "k-b"), u64::MAX),
    ])
    .expect("ring");
    assert!(verifies(&value, &ring));
    assert!(!verifies(&swapped, &ring));

    // Misconfigured slot holding k-a's key bytes under kid k-b: AEAD passes,
    // the encrypted kid binding still rejects the swap.
    let aliased = KeyRing::<PurposeA>::new(vec![
        KeySlot::active(kid("k-a"), slot(0x61, "k-a")),
        KeySlot::verify_only(kid("k-b"), slot(0x61, "k-a"), u64::MAX),
    ])
    .expect("ring");
    assert!(verifies(&value, &aliased));
    assert!(!verifies(&swapped, &aliased));
}

// --- Redaction -----------------------------------------------------------------

/// Every rendering a secret could leak through: lower/upper hex, the
/// `[u8]` Debug list, and printable ASCII.
fn assert_redacted(debug: &str, secret: &[u8]) {
    assert!(
        !debug.contains(&hex::encode(secret)),
        "lower hex in {debug}"
    );
    assert!(
        !debug.contains(&hex::encode_upper(secret)),
        "upper hex in {debug}"
    );
    let list = format!("{:?}", &secret[..secret.len().min(4)]);
    assert!(
        !debug.contains(list.trim_end_matches(']')),
        "byte list in {debug}"
    );
    if let Ok(text) = std::str::from_utf8(secret)
        && text.len() >= 4
    {
        assert!(!debug.contains(text), "ascii in {debug}");
    }
}

#[test]
fn debug_of_every_secret_type_omits_the_secret() {
    let root_bytes: [u8; KEY_BYTES] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x9e);
    let root = RootSecret::new(root_bytes);
    let key = root
        .derive_key::<PurposeA>(&kid("secret-kid"))
        .expect("derive");
    let key_bytes = *key.as_test_bytes();
    assert_redacted(&format!("{root:?}"), &root_bytes);
    assert_redacted(&format!("{key:?}"), &key_bytes);

    let ring =
        KeyRing::<PurposeA>::new(vec![KeySlot::active(kid("secret-kid"), key)]).expect("ring");
    let ring_debug = format!("{ring:?}");
    assert_redacted(&ring_debug, &key_bytes);
    assert_redacted(&ring_debug, &root_bytes);
    assert!(!ring_debug.contains("secret-kid"));
    assert_redacted(&format!("{:?}", ring.active()), &key_bytes);

    let body = b"sensitive-session-body";
    let value = mint(&ring, body);
    let token = parse_cookie_wrapper(&value)
        .expect("wrapper")
        .token()
        .to_owned();
    let parts = parse_cookie_wrapper(&value).expect("wrapper");
    let parts_debug = format!("{parts:?}");
    assert!(!parts_debug.contains(&token) && !parts_debug.contains("secret-kid"));

    let verified = parse_bound_cookie(&value, &ring, NOW, MaxAge::fixed(60)).expect("parse");
    let verified_debug = format!("{verified:?}");
    assert_redacted(&verified_debug, body);
    assert_redacted(&verified_debug, &[0x5c; branca::NONCE_BYTES]);
    assert!(!verified_debug.contains("secret-kid"));
    assert_eq!(format!("{:?}", verified.jti()), "Jti(..)");

    let raw = branca::decode(&token, &key_bytes).expect("decode");
    let raw_debug = format!("{raw:?}");
    assert_redacted(&raw_debug, raw.payload());
    assert_redacted(&raw_debug, raw.nonce());
}
