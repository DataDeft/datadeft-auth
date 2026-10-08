//! Normalized email tests.

use super::*;

#[test]
fn accepts_exact_app_provided_normalized_email_without_rewriting() {
    let email = NormalizedEmail::parse("User+tag@example.com").expect("email parses");
    assert_eq!(email.as_str(), "User+tag@example.com");
    assert_eq!(format!("{email:?}"), "NormalizedEmail(..)");
    assert!(!format!("{email:?}").contains(email.as_str()));
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
            NormalizedEmail::parse(value).unwrap_err(),
            MagicLinkError::InvalidEmail,
            "{value:?}"
        );
    }
}

#[test]
fn enforces_email_length_caps() {
    let local = "a".repeat(65);
    assert_eq!(
        NormalizedEmail::parse(&format!("{local}@example.com")).unwrap_err(),
        MagicLinkError::InvalidEmail
    );

    let long_label = "a".repeat(64);
    assert_eq!(
        NormalizedEmail::parse(&format!("user@{long_label}.com")).unwrap_err(),
        MagicLinkError::InvalidEmail
    );
}
