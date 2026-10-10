//! Locale allowlist: hints resolve to configured locales only.

use super::*;

fn list() -> LocaleAllowlist {
    LocaleAllowlist::new("en", ["hu", "de", "de-AT"]).expect("allowlist")
}

#[test]
fn hints_resolve_exactly_then_by_language_then_to_the_default() {
    let list = list();
    for (hint, expected) in [
        (Some("hu"), "hu"),
        (Some("HU"), "hu"),
        (Some(" hu "), "hu"),
        (Some("de-AT"), "de-AT"),
        (Some("de-at"), "de-AT"),
        (Some("de-CH"), "de"),
        (Some("de_DE"), "de"),
        (Some("hu-HU"), "hu"),
        (Some("fr"), "en"),
        (Some(""), "en"),
        (None, "en"),
    ] {
        assert_eq!(list.resolve(hint).as_str(), expected, "{hint:?}");
    }
}

#[test]
fn free_text_never_comes_back() {
    let list = list();
    for hint in [
        "<script>",
        "hu\r\nBcc: x@example.com",
        "{{ evil }}",
        &"a".repeat(1000),
    ] {
        let resolved = list.resolve(Some(hint));
        assert_eq!(resolved.as_str(), "en", "{hint:?}");
    }
}

#[test]
fn malformed_or_duplicate_tags_are_refused() {
    for bad in ["", "e", "english", "EN", "en-us", "en-USA", "en_US", "en-"] {
        assert_eq!(
            LocaleAllowlist::new(bad, []).unwrap_err(),
            LocaleError::InvalidTag,
            "{bad:?}"
        );
    }
    assert_eq!(
        LocaleAllowlist::new("en", ["hu", "en"]).unwrap_err(),
        LocaleError::Duplicate
    );
}

#[test]
fn hints_are_bounded_before_they_are_kept() {
    assert_eq!(bounded_hint("de-AT").as_deref(), Some("de-AT"));
    assert_eq!(bounded_hint("hu\n"), None);
    assert_eq!(bounded_hint(&"a".repeat(MAX_LOCALE_HINT_BYTES + 1)), None);
}
