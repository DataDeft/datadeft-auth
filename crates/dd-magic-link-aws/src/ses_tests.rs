//! Fake outbox tests.

use dd_magic_link_core::{MagicLinkToken, NormalizedEmail};
use dd_magic_link_service::{DependencyError, MagicLinkEmail, MagicLinkOutbox};

use super::*;

fn email() -> MagicLinkEmail {
    MagicLinkEmail {
        email: NormalizedEmail::parse("user@example.com").expect("email"),
        token: MagicLinkToken::parse(
            "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        )
        .expect("token"),
        expires_at_unix: 1_600,
    }
}

#[test]
fn rendered_email_debug_redacts_every_field() {
    const RECIPIENT: &str = "recipient-sentinel@example.invalid";
    const SUBJECT: &str = "subject-sentinel";
    const TEXT: &str = "text-sentinel";
    const HTML: &str = "<p>html-sentinel</p>";
    const TOKEN: &str = "mlv1.token-shaped-sentinel.verifier-sentinel";
    const EMAIL: &str = "message-sentinel@example.invalid";

    let rendered = RenderedMagicLinkEmail {
        to: RECIPIENT.to_owned(),
        subject: SUBJECT.to_owned(),
        text: format!("{TEXT} {TOKEN} {EMAIL}"),
        html: Some(format!("{HTML} {TOKEN} {EMAIL}")),
    };

    let debug = format!("{rendered:?}");

    assert_eq!(debug, "RenderedMagicLinkEmail(..)");
    for sentinel in [RECIPIENT, SUBJECT, TEXT, HTML, TOKEN, EMAIL] {
        assert!(
            !debug.contains(sentinel),
            "Debug leaked sentinel: {sentinel}"
        );
    }
    assert!(!debug.contains(&rendered.to));
    assert!(!debug.contains(&rendered.subject));
    assert!(!debug.contains(&rendered.text));
    assert!(!debug.contains(rendered.html.as_deref().expect("HTML body")));
}

#[tokio::test]
async fn fake_outbox_records_email_and_redacts_debug() {
    let outbox = FakeMagicLinkOutbox::default();
    outbox.enqueue_magic_link(email()).await.expect("enqueue");

    let recorded = outbox.recorded().expect("recorded");
    assert_eq!(recorded.len(), 1);
    assert_eq!(format!("{outbox:?}"), "FakeMagicLinkOutbox(..)");
    assert!(!format!("{:?}", recorded[0]).contains(recorded[0].token.verifier().as_secret_value()));
}

#[tokio::test]
async fn fake_outbox_can_inject_dependency_errors() {
    let outbox = FakeMagicLinkOutbox::default();
    outbox
        .set_next_error(DependencyError::Unavailable)
        .expect("set error");

    assert_eq!(
        outbox.enqueue_magic_link(email()).await.unwrap_err(),
        DependencyError::Unavailable
    );
    assert!(outbox.recorded().expect("recorded").is_empty());
}
