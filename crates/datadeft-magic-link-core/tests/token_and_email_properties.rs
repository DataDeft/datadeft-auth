//! Magic-link token grammar, selector/verifier independence, and
//! `NormalizedEmail` structure properties.
//!
//! Independence is checked structurally (exactly two RNG draws, each part a
//! function of its own draw only) and statistically as a sanity check over OS
//! RNG mints. Neither proves RNG quality; see the crate-level report.

use datadeft_auth_token_core::test_support::{CountingRng, FailOnCallRng};
use datadeft_magic_link_core::{
    MagicLinkError, MagicLinkSelector, MagicLinkToken, MagicLinkVerifier, NormalizedEmail,
    SELECTOR_BYTES, SELECTOR_HEX_LEN, VERIFIER_BYTES, VERIFIER_HEX_LEN,
};
use proptest::prelude::*;
use rand_core::{CryptoRng, OsRng, RngCore};

/// Serves one scripted buffer per `try_fill_bytes` call and records sizes.
struct ScriptedRng {
    draws: Vec<Vec<u8>>,
    sizes: Vec<usize>,
}

impl RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).expect("scripted draw");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        let draw = self.draws.remove(0);
        dest.copy_from_slice(&draw[..dest.len()]);
        self.sizes.push(dest.len());
        Ok(())
    }
}

impl CryptoRng for ScriptedRng {}

fn scripted(selector: [u8; SELECTOR_BYTES], verifier: [u8; VERIFIER_BYTES]) -> MagicLinkToken {
    let mut rng = ScriptedRng {
        draws: vec![selector.to_vec(), verifier.to_vec()],
        sizes: Vec::new(),
    };
    let token = MagicLinkToken::generate(&mut rng).expect("generate");
    assert_eq!(rng.sizes, vec![SELECTOR_BYTES, VERIFIER_BYTES]);
    token
}

// --- Independence ------------------------------------------------------------

#[test]
fn selector_and_verifier_are_two_independent_draws() {
    let mut counting = CountingRng::starting_at(0);
    MagicLinkToken::generate(&mut counting).expect("generate");
    assert_eq!(counting.calls(), 2, "exactly one draw per part, no slicing");

    // A failure on either draw fails generation: the verifier is never
    // derived from the selector draw as a fallback.
    for call in [0, 1] {
        let mut failing = FailOnCallRng::failing_on(call);
        assert_eq!(
            MagicLinkToken::generate(&mut failing).unwrap_err(),
            MagicLinkError::EntropyUnavailable
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// The selector is exactly hex(draw 1) and the verifier exactly hex(draw 2).
    /// Changing one draw leaves the other part unchanged, so neither part is a
    /// function of the other.
    #[test]
    fn each_part_depends_only_on_its_own_draw(
        s1 in prop::array::uniform16(any::<u8>()),
        s2 in prop::array::uniform16(any::<u8>()),
        v1 in prop::array::uniform32(any::<u8>()),
        v2 in prop::array::uniform32(any::<u8>()),
    ) {
        let base = scripted(s1, v1);
        prop_assert_eq!(base.selector().as_lookup_value(), hex::encode(s1));
        prop_assert_eq!(base.verifier().as_secret_value(), hex::encode(v1));
        let other_selector = scripted(s2, v1);
        prop_assert_eq!(base.verifier().as_secret_value(), other_selector.verifier().as_secret_value());
        let other_verifier = scripted(s1, v2);
        prop_assert_eq!(base.selector().as_lookup_value(), other_verifier.selector().as_lookup_value());
    }
}

/// Statistical sanity over the production RNG: no repeats and no detectable
/// overlap between the halves across 2048 mints.
#[test]
fn os_rng_tokens_show_no_repeats_or_selector_verifier_relation() {
    let mut selectors = std::collections::HashSet::new();
    let mut verifiers = std::collections::HashSet::new();
    for _ in 0..2048 {
        let token = MagicLinkToken::generate(&mut OsRng).expect("generate");
        let selector = token.selector().as_lookup_value().to_owned();
        let verifier = token.verifier().as_secret_value().to_owned();
        assert!(
            !verifier.contains(&selector),
            "selector embedded in verifier"
        );
        assert!(selectors.insert(selector), "selector repeated");
        assert!(verifiers.insert(verifier), "verifier repeated");
    }
}

// --- Token grammar -----------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Round trip and canonicality: rendering a parsed token returns the
    /// exact input, so one token has exactly one accepted spelling.
    #[test]
    fn token_round_trips_canonically(
        selector in prop::array::uniform16(any::<u8>()),
        verifier in prop::array::uniform32(any::<u8>()),
    ) {
        let raw = format!("mlv1.{}.{}", hex::encode(selector), hex::encode(verifier));
        let token = MagicLinkToken::parse(&raw).expect("canonical token parses");
        let rendered = token.as_secret_value();
        prop_assert_eq!(rendered.as_str(), raw.as_str());
    }

    /// Any single-character edit is either rejected or parses to a token
    /// whose rendering equals the edited string (a different token, never a
    /// second spelling of the original). Uppercase hex is always rejected.
    #[test]
    fn single_edits_never_yield_a_second_spelling(
        selector in prop::array::uniform16(any::<u8>()),
        verifier in prop::array::uniform32(any::<u8>()),
        pos in any::<prop::sample::Index>(),
        replacement in any::<char>(),
        op in 0usize..3,
    ) {
        let raw = format!("mlv1.{}.{}", hex::encode(selector), hex::encode(verifier));
        let mut chars: Vec<char> = raw.chars().collect();
        let i = pos.index(chars.len());
        match op {
            0 => chars[i] = replacement,
            1 => chars.insert(i, replacement),
            _ => {
                chars.remove(i);
            }
        }
        let edited: String = chars.into_iter().collect();
        if let Ok(token) = MagicLinkToken::parse(&edited) {
            let rendered = token.as_secret_value();
            prop_assert_eq!(rendered.as_str(), edited.as_str());
        }
        prop_assert!(MagicLinkToken::parse(&raw.to_uppercase()).is_err());
    }

    /// Totality plus the accepted-shape invariant on arbitrary strings.
    #[test]
    fn token_parse_is_total_and_accepts_only_the_exact_shape(
        raw in "\\PC{0,120}|[\\x00-\\x7f]{0,120}|mlv1\\.[0-9a-fA-F]{30,34}\\.[0-9a-fA-F]{62,66}",
    ) {
        if let Ok(token) = MagicLinkToken::parse(&raw) {
            prop_assert_eq!(raw.len(), 5 + SELECTOR_HEX_LEN + 1 + VERIFIER_HEX_LEN);
            let rendered = token.as_secret_value();
            prop_assert_eq!(rendered.as_str(), raw.as_str());
        }
        let _ = MagicLinkSelector::parse(&raw);
        let _ = MagicLinkVerifier::parse(&raw);
    }
}

// --- NormalizedEmail -----------------------------------------------------------

const LOCAL_SPECIALS: &str = "!#$%&'*+-/=?^_`{|}~";

fn local_part() -> impl Strategy<Value = String> {
    let atom = format!("[A-Za-z0-9{}]{{1,8}}", regex_escape(LOCAL_SPECIALS));
    prop::collection::vec(proptest::string::string_regex(&atom).expect("regex"), 1..4)
        .prop_map(|atoms| atoms.join("."))
}

fn domain_part() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-z0-9]([a-z0-9-]{0,6}[a-z0-9])?", 2..4).prop_map(|l| l.join("."))
}

fn regex_escape(chars: &str) -> String {
    chars
        .chars()
        .map(|c| match c {
            '-' | '^' | '[' | ']' | '\\' | '{' | '}' | '|' | '$' | '*' | '+' | '?' | '/' => {
                format!("\\{c}")
            }
            _ => c.to_string(),
        })
        .collect()
}

fn valid_email() -> impl Strategy<Value = String> {
    (local_part(), domain_part()).prop_map(|(l, d)| format!("{l}@{d}"))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Structurally valid values are accepted byte-for-byte: no trimming,
    /// lowercasing, dot folding, or plus-tag stripping.
    #[test]
    fn valid_emails_are_accepted_exactly(email in valid_email()) {
        let parsed = NormalizedEmail::parse(&email).expect("valid email");
        prop_assert_eq!(parsed.as_str(), email.as_str());
        prop_assert_eq!(format!("{parsed:?}"), "NormalizedEmail(..)");
    }

    /// Any ASCII control character (CR, LF, NUL, TAB, DEL, ...), space,
    /// list separator, angle bracket, quote, or second `@` inserted anywhere
    /// is rejected.
    #[test]
    fn injected_forbidden_bytes_are_rejected(
        email in valid_email(),
        pos in any::<prop::sample::Index>(),
        bad in prop::sample::select(
            (0u8..=0x1f).chain([0x7f, b' ', b',', b';', b'<', b'>', b'"', b'@']).collect::<Vec<_>>()
        ),
    ) {
        let mut bytes = email.into_bytes();
        bytes.insert(pos.index(bytes.len() + 1), bad);
        let edited = String::from_utf8(bytes).expect("ascii");
        prop_assert_eq!(NormalizedEmail::parse(&edited).unwrap_err(), MagicLinkError::InvalidEmail);
    }

    /// Display-name forms and multi-address lists are rejected.
    #[test]
    fn display_names_and_address_lists_are_rejected(
        a in valid_email(),
        b in valid_email(),
        name in "[A-Za-z]{1,10}",
        sep in prop::sample::select(vec![",", ";", " ", ", ", "\n", "\r\n"]),
    ) {
        for value in [
            format!("{name} <{a}>"),
            format!("<{a}>"),
            format!("\"{name}\" <{a}>"),
            format!("{a}{sep}{b}"),
        ] {
            prop_assert!(NormalizedEmail::parse(&value).is_err(), "{:?}", value);
        }
    }

    /// Any non-ASCII character anywhere is rejected (no IDN / Unicode local
    /// parts at this boundary).
    #[test]
    fn non_ascii_is_rejected(
        email in valid_email(),
        pos in any::<prop::sample::Index>(),
        ch in any::<char>().prop_filter("non-ascii", |c| !c.is_ascii()),
    ) {
        let mut chars: Vec<char> = email.chars().collect();
        chars.insert(pos.index(chars.len() + 1), ch);
        let edited: String = chars.into_iter().collect();
        prop_assert!(NormalizedEmail::parse(&edited).is_err());
    }

    /// Totality, and every accepted value satisfies the documented invariants.
    #[test]
    fn email_parse_is_total_and_accepted_values_meet_invariants(
        raw in "\\PC{0,300}|[\\x00-\\x7f]{0,300}",
    ) {
        if let Ok(email) = NormalizedEmail::parse(&raw) {
            let value = email.as_str();
            prop_assert!(value.is_ascii() && !value.is_empty() && value.len() <= 254);
            prop_assert!(!value.bytes().any(|b| b.is_ascii_control() || b == b' '));
            prop_assert_eq!(value.matches('@').count(), 1);
        }
    }
}

#[test]
fn email_length_caps_are_exact() {
    let label = |c: char, n: usize| c.to_string().repeat(n);
    let local64 = label('a', 64);
    // 64 + 1 + 189 = 254 total: the cap, accepted.
    let domain189 = format!("{}.{}.{}", label('b', 63), label('c', 63), label('d', 61));
    let at_cap = format!("{local64}@{domain189}");
    assert_eq!(at_cap.len(), 254);
    assert!(NormalizedEmail::parse(&at_cap).is_ok());
    // One more byte in the domain: 255 total, rejected.
    let domain190 = format!("{}.{}.{}", label('b', 63), label('c', 63), label('d', 62));
    assert!(NormalizedEmail::parse(&format!("{local64}@{domain190}")).is_err());
    // Local part 65 bytes, label 64 bytes: rejected.
    assert!(NormalizedEmail::parse(&format!("{}@example.com", label('a', 65))).is_err());
    assert!(NormalizedEmail::parse(&format!("a@{}.com", label('b', 64))).is_err());
    assert!(NormalizedEmail::parse(&format!("a@{}.com", label('b', 63))).is_ok());
    assert!(NormalizedEmail::parse("").is_err());
}

#[test]
fn email_identity_is_exact_match() {
    let lower = NormalizedEmail::parse("user@example.com").expect("lower");
    for variant in [
        "User@example.com",
        "user@Example.com",
        "u.ser@example.com",
        "user+x@example.com",
    ] {
        let other = NormalizedEmail::parse(variant).expect("variant");
        assert_ne!(lower, other, "{variant} must not alias");
    }
}
