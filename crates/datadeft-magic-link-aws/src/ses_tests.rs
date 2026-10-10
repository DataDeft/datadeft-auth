//! Fake outbox tests.

use datadeft_magic_link_core::{MagicLinkToken, NormalizedEmail};
use datadeft_magic_link_service::{DependencyError, MagicLinkEmail, MagicLinkOutbox};

use super::*;

fn email() -> MagicLinkEmail {
    MagicLinkEmail {
        email: NormalizedEmail::from_normalized("user@example.com").expect("email"),
        token: MagicLinkToken::parse(
            "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        )
        .expect("token"),
        expires_at_unix: 1_600,
        locale: None,
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

#[test]
fn reply_to_is_validated_normalized_and_bounded() {
    assert_eq!(
        validated_reply_to([" Support@Example.com "]).expect("valid"),
        ["support@example.com"]
    );
    assert!(
        validated_reply_to(Vec::<String>::new())
            .expect("empty")
            .is_empty()
    );
    for bad in [
        "not-an-address",
        "a@example.com, b@example.com",
        "Support <support@example.com>",
        "support@example.com\r\nBcc: x@example.com",
    ] {
        assert_eq!(
            validated_reply_to([bad]).unwrap_err(),
            AwsAdapterError::Internal,
            "{bad:?}"
        );
    }
    let five = ["a@example.com"; MAX_REPLY_TO_ADDRESSES + 1];
    assert_eq!(
        validated_reply_to(five).unwrap_err(),
        AwsAdapterError::Internal
    );
}

#[cfg(feature = "aws")]
mod ses_requests {
    use aws_sdk_sesv2::config::{BehaviorVersion, Credentials, Region};
    use aws_smithy_http_client::test_util::capture_request;

    use super::*;

    struct PlainRenderer;

    impl MagicLinkEmailRenderer for PlainRenderer {
        fn render(
            &self,
            email: &MagicLinkEmail,
        ) -> Result<RenderedMagicLinkEmail, DependencyError> {
            Ok(RenderedMagicLinkEmail {
                to: email.email.as_str().to_owned(),
                subject: "Sign in".to_owned(),
                text: "Open the link".to_owned(),
                html: None,
            })
        }
    }

    async fn sent_body(reply_to: Option<&[&str]>) -> String {
        let (http_client, request) = capture_request(None);
        let config = aws_sdk_sesv2::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-west-1"))
            .credentials_provider(Credentials::new("akid", "secret", None, None, "test"))
            .http_client(http_client)
            .build();
        let mut outbox = SesMagicLinkOutbox::new(
            aws_sdk_sesv2::Client::from_conf(config),
            "login@example.com".to_owned(),
            PlainRenderer,
        );
        if let Some(reply_to) = reply_to {
            outbox = outbox.with_reply_to(reply_to).expect("reply-to");
        }
        // The canned empty response does not parse; only the request matters.
        let _ = outbox.enqueue_magic_link(email()).await;
        let request = request.expect_request();
        String::from_utf8(request.body().bytes().expect("body").to_vec()).expect("utf-8")
    }

    #[tokio::test]
    async fn ses_requests_carry_reply_to_only_when_configured() {
        let body = sent_body(Some(&["support@example.com"])).await;
        assert!(
            body.contains(r#""ReplyToAddresses":["support@example.com"]"#),
            "{body}"
        );
        let body = sent_body(None).await;
        assert!(!body.contains("ReplyToAddresses"), "{body}");
    }
}
