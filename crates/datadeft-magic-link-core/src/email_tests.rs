//! Normalized email tests.

use super::*;

#[test]
fn case_and_surrounding_whitespace_map_to_one_identity() {
    let canonical = NormalizedEmail::from_normalized("user+tag@example.com").expect("canonical");
    for input in [
        "user+tag@example.com",
        "User+Tag@Example.COM",
        "  USER+TAG@EXAMPLE.COM\t",
        "\nuser+tag@example.com\r\n",
    ] {
        assert_eq!(
            NormalizedEmail::normalize(input).expect("normalizes"),
            canonical,
            "{input:?}"
        );
    }
    assert_eq!(format!("{canonical:?}"), "NormalizedEmail(..)");
    assert!(!format!("{canonical:?}").contains(canonical.as_str()));
}

#[test]
fn plus_tags_dots_and_providers_are_kept_as_typed() {
    for (input, expected) in [
        ("first.last+news@gmail.com", "first.last+news@gmail.com"),
        ("F.I.R.S.T@GoogleMail.com", "f.i.r.s.t@googlemail.com"),
        ("x+y+z@example.org", "x+y+z@example.org"),
    ] {
        assert_eq!(
            NormalizedEmail::normalize(input)
                .expect("normalizes")
                .as_str(),
            expected
        );
    }
}

#[test]
fn from_normalized_only_validates() {
    for value in ["User@example.com", "user@Example.com", " user@example.com"] {
        assert_eq!(
            NormalizedEmail::from_normalized(value).unwrap_err(),
            MagicLinkError::InvalidEmail,
            "{value:?}"
        );
    }
}

#[test]
fn normalize_still_rejects_invalid_shapes_without_echoing_them() {
    for input in [
        "",
        "   ",
        "user name@example.com",
        "Display Name <user@example.com>",
        "a@example.com,b@example.com",
        "two@@example.com",
        "user@example",
        "ü@example.com",
        "user\0@example.com",
    ] {
        let error = NormalizedEmail::normalize(input).unwrap_err();
        assert_eq!(error, MagicLinkError::InvalidEmail, "{input:?}");
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains("example"), "{shown}");
    }
    let oversized = format!("{}@example.com", "a".repeat(10_000));
    assert_eq!(
        NormalizedEmail::normalize(&oversized).unwrap_err(),
        MagicLinkError::InvalidEmail
    );
}

#[test]
fn rejects_structurally_invalid_or_ambiguous_email_values() {
    for value in [
        "",
        " user@example.com",
        "user@example.com ",
        "user name@example.com",
        "user@example.com\n",
        "user\0@example.com",
        "Display Name <user@example.com>",
        "a@example.com,b@example.com",
        "a@example.com;b@example.com",
        "missing-at.example.com",
        "two@@example.com",
        "@example.com",
        "user@",
        "user@example",
        "user@example.",
        "user@.example.com",
        "user@example..com",
        ".user@example.com",
        "user.@example.com",
        "user..name@example.com",
        "ü@example.com",
        "user@exämple.com",
    ] {
        assert_eq!(
            NormalizedEmail::from_normalized(value).unwrap_err(),
            MagicLinkError::InvalidEmail,
            "{value:?}"
        );
    }
}

#[test]
fn enforces_email_length_caps() {
    let local = "a".repeat(65);
    assert_eq!(
        NormalizedEmail::from_normalized(&format!("{local}@example.com")).unwrap_err(),
        MagicLinkError::InvalidEmail
    );

    let long_label = "a".repeat(64);
    assert_eq!(
        NormalizedEmail::from_normalized(&format!("user@{long_label}.com")).unwrap_err(),
        MagicLinkError::InvalidEmail
    );
}
