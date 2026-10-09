//! Keyed-lookup HMAC framing / domain separation, the verifier-hash
//! comparison API, and confirm-cookie binding properties.
//!
//! Constant-time behavior cannot be observed by a unit test. These tests pin
//! the API contract (the only comparison offered is the `*_constant_time`
//! method, and it answers correctly); timing needs a dudect-style harness.

use datadeft_auth_token_core::TokenError;
use datadeft_auth_token_core::branca;
use datadeft_auth_token_core::keyring::KeyRing;
use datadeft_auth_token_core::test_support::{PerCallRng, test_keyring};
use datadeft_magic_link_core::{
    ConfirmAccountBinding, ConfirmSelectorBinding, ConfirmVerifierBinding, EMAIL_LOOKUP_PREFIX,
    LookupHmacKey, MAGIC_LINK_CONFIRM_BINDING_BYTES, MAGIC_LINK_CONFIRM_MAX_AGE_SECS,
    MagicLinkConfirmBindings, MagicLinkConfirmCookie, MagicLinkError, MagicLinkSelector,
    MagicLinkVerifier, NormalizedEmail, SELECTOR_LOOKUP_PREFIX, VERIFIER_HASH_PREFIX,
    confirm_selector_binding, confirm_verifier_binding, domain_separated_lookup_hmac,
    email_lookup_hmac, mint_magic_link_confirm, selector_lookup_hmac,
    selector_lookup_hmac_from_confirm_binding, verifier_hash, verifier_hash_from_confirm_binding,
    verify_magic_link_confirm,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

/// Independent RFC 2104 HMAC-SHA256 built only on SHA-256.
fn ref_hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

#[test]
fn reference_hmac_matches_rfc_4231_and_the_pinned_lookup_vector() {
    assert_eq!(
        hex::encode(ref_hmac(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // The crate's pinned email vector (`hmac_lookup_tests`) recomputed from
    // the documented framing with the independent reference.
    let message = b"magic-link-lookup-v1\0emh\0user@example.com";
    assert_eq!(
        format!("emh_{}", hex::encode(ref_hmac(&[0x42; 32], message))),
        "emh_7330b67f746ac427ff0777354000ca197fd1120ee6cf99371c484b92b8d517c8"
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Known-answer equivalence: the framing is exactly
    /// `HMAC(key, domain || 0x00 || prefix || 0x00 || value)` as `{prefix}_{hex}`.
    #[test]
    fn lookup_hmac_matches_documented_framing(
        key in prop::array::uniform32(any::<u8>()),
        domain in "[a-z0-9/-]{1,24}",
        prefix in "[a-z]{2,4}",
        value in "[ -~]{0,80}",
    ) {
        let got = domain_separated_lookup_hmac(&LookupHmacKey::new(key), domain.as_bytes(), &prefix, &value)
            .expect("hmac");
        let message = [domain.as_bytes(), b"\0", prefix.as_bytes(), b"\0", value.as_bytes()].concat();
        prop_assert_eq!(got, format!("{prefix}_{}", hex::encode(ref_hmac(&key, &message))));
    }

    /// Domain separation: for the same input value, the email, selector, and
    /// verifier helpers, a different domain, and a different key all produce
    /// pairwise-different MAC bytes (not just different prefixes).
    #[test]
    fn same_input_never_collides_across_purposes_domains_or_keys(
        key in prop::array::uniform32(any::<u8>()),
        other_key in prop::array::uniform32(any::<u8>()),
        selector in prop::array::uniform16(any::<u8>()),
    ) {
        prop_assume!(key != other_key);
        let k = LookupHmacKey::new(key);
        let value = hex::encode(selector);
        let mac = |s: String| s.split_once('_').map(|(_, h)| h.to_owned()).expect("prefixed");
        let sel = selector_lookup_hmac(&k, &MagicLinkSelector::parse(&value).expect("sel"))
            .expect("hmac").as_storage_value().to_owned();
        // A 32-hex verifier-shaped value is not a valid verifier; use the
        // generic framing under each product prefix for the same input.
        let macs = [
            mac(sel.clone()),
            mac(domain_separated_lookup_hmac(&k, b"magic-link-lookup-v1", EMAIL_LOOKUP_PREFIX, &value).expect("emh")),
            mac(domain_separated_lookup_hmac(&k, b"magic-link-lookup-v1", VERIFIER_HASH_PREFIX, &value).expect("mlv")),
            mac(domain_separated_lookup_hmac(&k, b"other-adapter-v1", SELECTOR_LOOKUP_PREFIX, &value).expect("adapter")),
            mac(domain_separated_lookup_hmac(&LookupHmacKey::new(other_key), b"magic-link-lookup-v1", SELECTOR_LOOKUP_PREFIX, &value).expect("key")),
        ];
        prop_assert!(sel.starts_with("mlh_"));
        for (i, a) in macs.iter().enumerate() {
            for b in &macs[i + 1..] {
                prop_assert_ne!(a, b);
            }
        }
    }

    /// The verifier-hash comparison API answers "same verifier" exactly, and
    /// a different lookup key never matches.
    #[test]
    fn verifier_hash_comparison_api_is_exact(
        key in prop::array::uniform32(any::<u8>()),
        other_key in prop::array::uniform32(any::<u8>()),
        a in prop::array::uniform32(any::<u8>()),
        b in prop::array::uniform32(any::<u8>()),
    ) {
        let k = LookupHmacKey::new(key);
        let va = MagicLinkVerifier::parse(&hex::encode(a)).expect("verifier");
        let vb = MagicLinkVerifier::parse(&hex::encode(b)).expect("verifier");
        let stored = verifier_hash(&k, &va).expect("hash");
        prop_assert!(stored.matches_verifier_constant_time(&k, &va).expect("cmp"));
        prop_assert_eq!(stored.matches_verifier_constant_time(&k, &vb).expect("cmp"), a == b);
        prop_assert_eq!(
            stored.matches_hash_constant_time(&verifier_hash(&k, &vb).expect("hash")),
            a == b
        );
        if key != other_key {
            let other = LookupHmacKey::new(other_key);
            prop_assert!(!stored.matches_verifier_constant_time(&other, &va).expect("cmp"));
        }
        // Binding round trip back to the canonical storage form.
        let binding = confirm_verifier_binding(&stored).expect("binding");
        prop_assert!(verifier_hash_from_confirm_binding(&binding).matches_hash_constant_time(&stored));
    }
}

/// The product domain and prefixes are NUL-free, which is what keeps the
/// `domain || 0 || prefix || 0 || value` framing injective for them.
#[test]
fn product_framing_constants_are_nul_free_and_distinct() {
    for prefix in [
        EMAIL_LOOKUP_PREFIX,
        SELECTOR_LOOKUP_PREFIX,
        VERIFIER_HASH_PREFIX,
    ] {
        assert!(!prefix.contains('\0') && !prefix.contains('_'));
    }
    assert_ne!(EMAIL_LOOKUP_PREFIX, SELECTOR_LOOKUP_PREFIX);
    assert_ne!(SELECTOR_LOOKUP_PREFIX, VERIFIER_HASH_PREFIX);
    assert_ne!(EMAIL_LOOKUP_PREFIX, VERIFIER_HASH_PREFIX);
    // Email values are validated NUL-free before they reach the framing.
    assert!(NormalizedEmail::parse("a\0b@example.com").is_err());
}

/// The framing is NUL-separated, so it is injective only while `domain` and
/// `prefix` are NUL-free; the helper enforces that. This pair used to collide
/// (`d ‖ 0 ‖ p ‖ 0 ‖ a‖0‖p‖0‖b` both ways); now the NUL-bearing domain is refused.
#[test]
fn framing_rejects_nul_in_domain_or_prefix() {
    let key = LookupHmacKey::new([0x42; 32]);
    assert!(domain_separated_lookup_hmac(&key, b"d", "p", "a\0p\0b").is_ok());
    assert_eq!(
        domain_separated_lookup_hmac(&key, b"d\0p\0a", "p", "b"),
        Err(MagicLinkError::Internal)
    );
    assert_eq!(
        domain_separated_lookup_hmac(&key, b"d", "p\0x", "b"),
        Err(MagicLinkError::Internal)
    );
    assert_eq!(
        domain_separated_lookup_hmac(&key, b"\0", "p", "b"),
        Err(MagicLinkError::Internal)
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Injectivity: with NUL-free `domain` and `prefix` (enforced), distinct
    /// `(domain, prefix, value)` triples never produce the same lookup string,
    /// even when values contain NUL. Short alphabets make near-collisions such
    /// as shifted field boundaries likely to be generated.
    #[test]
    fn framing_is_injective_for_accepted_inputs(
        d1 in "[ab]{0,3}", p1 in "[ab]{0,3}", v1 in "[ab\\x00]{0,4}",
        d2 in "[ab]{0,3}", p2 in "[ab]{0,3}", v2 in "[ab\\x00]{0,4}",
    ) {
        let key = LookupHmacKey::new([0x42; 32]);
        let first = domain_separated_lookup_hmac(&key, d1.as_bytes(), &p1, &v1).expect("first");
        let second = domain_separated_lookup_hmac(&key, d2.as_bytes(), &p2, &v2).expect("second");
        prop_assert_eq!(first == second, (d1, p1, v1) == (d2, p2, v2));
    }
}

// --- Confirm cookie binding ------------------------------------------------------

const NOW: u64 = 1_000_000;

fn ring() -> KeyRing<MagicLinkConfirmCookie> {
    test_keyring::<MagicLinkConfirmCookie>(0x71, "confirm-active")
}

fn flip(mut bytes: [u8; 32], bit: usize) -> [u8; 32] {
    bytes[bit / 8] ^= 1 << (bit % 8);
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Binding: the cookie authenticates exactly the minted selector,
    /// verifier proof, account, expiry, and confirmation nonce. Changing any
    /// one (a single bit of a binding, one nibble of the nonce, the expiry
    /// instant, or any character of the cookie) fails.
    #[test]
    fn confirm_cookie_binds_every_field(
        selector in prop::array::uniform32(any::<u8>()),
        verifier in prop::array::uniform32(any::<u8>()),
        account in prop::array::uniform32(any::<u8>()),
        ttl in 0u64..=MAGIC_LINK_CONFIRM_MAX_AGE_SECS,
        bit in 0usize..256,
        nibble in 0usize..64,
        pos in any::<prop::sample::Index>(),
        replacement in any::<char>(),
    ) {
        let expires = u32::try_from(NOW + ttl).expect("fits");
        let bindings = MagicLinkConfirmBindings::new(
            ConfirmSelectorBinding::new(selector),
            ConfirmVerifierBinding::new(verifier),
            ConfirmAccountBinding::new(account),
            expires,
        );
        let mut rng = PerCallRng::starting_at(0x10);
        let minted = mint_magic_link_confirm(bindings, &ring(), &mut rng, NOW).expect("mint");
        let cookie = minted.cookie().as_secret_value().to_owned();
        let confirmation = minted.confirmation().as_value().to_owned();
        let max_age = MAGIC_LINK_CONFIRM_MAX_AGE_SECS;
        let verify = |c: &str, n: &str, now: u64| verify_magic_link_confirm(c, n, &ring(), now, max_age);

        let verified = verify(&cookie, &confirmation, NOW).expect("verify");
        prop_assert!(verified.selector().matches_constant_time(&ConfirmSelectorBinding::new(selector)));
        prop_assert!(verified.verifier().matches_constant_time(&ConfirmVerifierBinding::new(verifier)));
        prop_assert!(verified.account().matches_constant_time(&ConfirmAccountBinding::new(account)));
        prop_assert!(!verified.selector().matches_constant_time(&ConfirmSelectorBinding::new(flip(selector, bit))));
        prop_assert!(!verified.verifier().matches_constant_time(&ConfirmVerifierBinding::new(flip(verifier, bit))));
        prop_assert!(!verified.account().matches_constant_time(&ConfirmAccountBinding::new(flip(account, bit))));
        prop_assert_eq!(verified.expires_at_unix(), expires);

        // Expiry is inclusive and enforced.
        prop_assert!(verify(&cookie, &confirmation, u64::from(expires)).is_ok());
        prop_assert_eq!(
            verify(&cookie, &confirmation, u64::from(expires) + 1).err(),
            Some(TokenError::InvalidToken)
        );

        // Confirmation nonce: one changed nibble, or uppercase, fails.
        let mut nonce: Vec<u8> = confirmation.clone().into_bytes();
        nonce[nibble] = if nonce[nibble] == b'0' { b'1' } else { b'0' };
        let changed = String::from_utf8(nonce).expect("ascii");
        prop_assert!(verify(&cookie, &changed, NOW).is_err());
        if confirmation.bytes().any(|b| b.is_ascii_lowercase()) {
            prop_assert!(verify(&cookie, &confirmation.to_uppercase(), NOW).is_err());
        }

        // Any single-character edit of the cookie fails.
        let mut chars: Vec<char> = cookie.chars().collect();
        let i = pos.index(chars.len());
        if chars[i] != replacement {
            chars[i] = replacement;
            let edited: String = chars.into_iter().collect();
            prop_assert!(verify(&edited, &confirmation, NOW).is_err());
        }
    }

    /// Totality on arbitrary cookie and confirmation input.
    #[test]
    fn confirm_verify_is_total(
        cookie in "\\PC{0,200}|v1\\.confirm-active\\.[0-9A-Za-z]{0,300}",
        confirmation in "[0-9a-fA-F]{0,70}|\\PC{0,80}",
        now in any::<u64>(),
        max_age in any::<u64>(),
    ) {
        let _ = verify_magic_link_confirm(&cookie, &confirmation, &ring(), now, max_age);
    }
}

#[test]
fn confirmation_nonce_from_another_flow_is_rejected() {
    let mint = |seed: u8| {
        let bindings = MagicLinkConfirmBindings::new(
            ConfirmSelectorBinding::new([1; MAGIC_LINK_CONFIRM_BINDING_BYTES]),
            ConfirmVerifierBinding::new([2; MAGIC_LINK_CONFIRM_BINDING_BYTES]),
            ConfirmAccountBinding::new([3; MAGIC_LINK_CONFIRM_BINDING_BYTES]),
            u32::try_from(NOW + 60).expect("fits"),
        );
        let mut rng = PerCallRng::starting_at(seed);
        mint_magic_link_confirm(bindings, &ring(), &mut rng, NOW).expect("mint")
    };
    let (a, b) = (mint(0x10), mint(0x20));
    assert!(
        verify_magic_link_confirm(
            a.cookie().as_secret_value(),
            b.confirmation().as_value(),
            &ring(),
            NOW,
            300
        )
        .is_err()
    );
}

#[test]
fn selector_binding_round_trips_to_the_lookup_key() {
    let key = LookupHmacKey::new([9; 32]);
    let selector = MagicLinkSelector::parse(&"0f".repeat(16)).expect("selector");
    let lookup = selector_lookup_hmac(&key, &selector).expect("lookup");
    let binding = confirm_selector_binding(&lookup).expect("binding");
    assert_eq!(selector_lookup_hmac_from_confirm_binding(&binding), lookup);
    // An email lookup cannot be smuggled in as a selector binding.
    let email = NormalizedEmail::parse("user@example.com").expect("email");
    let email_lookup = email_lookup_hmac(&key, &email).expect("email lookup");
    assert!(confirm_selector_binding(&email_lookup).is_err());
}

#[test]
fn confirm_golden_cookie_is_pinned() {
    let bindings = MagicLinkConfirmBindings::new(
        ConfirmSelectorBinding::new([0x11; MAGIC_LINK_CONFIRM_BINDING_BYTES]),
        ConfirmVerifierBinding::new([0x22; MAGIC_LINK_CONFIRM_BINDING_BYTES]),
        ConfirmAccountBinding::new([0x33; MAGIC_LINK_CONFIRM_BINDING_BYTES]),
        1_000_300,
    );
    // Two draws: the 32-byte confirmation nonce, then the 24-byte Branca nonce.
    struct TwoDraws(Vec<Vec<u8>>);
    impl rand_core::RngCore for TwoDraws {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.copy_from_slice(&self.0.remove(0));
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for TwoDraws {}
    let mut rng = TwoDraws(vec![vec![0xaa; 32], vec![0x5b; branca::NONCE_BYTES]]);
    let minted = mint_magic_link_confirm(bindings, &ring(), &mut rng, NOW).expect("mint");
    assert_eq!(minted.confirmation().as_value(), "aa".repeat(32));
    assert_eq!(
        minted.cookie().as_secret_value(),
        "v1.confirm-active.NNlWAqX5xc6jq7GzUI47gQXtzI4XS9pPV51ScUNA0tLgXgFOFNUlLzRMC8Fw40zHqTCvxzmVmu4SDUISDFC59tPF6dOj5MZMAmnJwxZMqCwcECrCLw9U43KSdlVHmUljnpfEP6oRFpjJyF8U2TC97TbqygLJesbeIDJNglCN8r2QzTD90w793JFGmvhDrhRPFDfn26fKoHNkyzd7IrEDTOKgXRC92RmRZggkNp66tg3rx6rnnbLwOkJSjtROvrbXqTZ73eNGSwmNVnBw71aRe9Oq3kQky"
    );
}
