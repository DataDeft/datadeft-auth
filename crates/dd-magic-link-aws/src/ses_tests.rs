//! Fake outbox tests.

use dd_magic_link_core::{MagicLinkToken, NormalizedEmail};
use dd_magic_link_service::{DependencyError, EmailLocale, MagicLinkEmail, MagicLinkOutbox};

use super::*;

fn email() -> MagicLinkEmail {
    MagicLinkEmail {
        email: NormalizedEmail::parse("user@example.com").expect("email"),
        token: MagicLinkToken::parse(
            "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        )
        .expect("token"),
        locale: EmailLocale::En,
        expires_at_unix: 1_600,
    }
}

#[test]
fn fake_outbox_records_email_and_redacts_debug() {
    let outbox = FakeMagicLinkOutbox::default();
    outbox.enqueue_magic_link(email()).expect("enqueue");

    let recorded = outbox.recorded().expect("recorded");
    assert_eq!(recorded.len(), 1);
    assert_eq!(format!("{outbox:?}"), "FakeMagicLinkOutbox(..)");
    assert!(!format!("{:?}", recorded[0]).contains(recorded[0].token.verifier().as_secret_value()));
}

#[test]
fn fake_outbox_can_inject_dependency_errors() {
    let outbox = FakeMagicLinkOutbox::default();
    outbox
        .set_next_error(DependencyError::Unavailable)
        .expect("set error");

    assert_eq!(
        outbox.enqueue_magic_link(email()).unwrap_err(),
        DependencyError::Unavailable
    );
    assert!(outbox.recorded().expect("recorded").is_empty());
}
