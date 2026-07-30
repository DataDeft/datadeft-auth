//! Magic-link outbox adapters.

use core::fmt;
use std::sync::{Arc, Mutex};

use dd_magic_link_service::{DependencyError, MagicLinkEmail, MagicLinkOutbox};

#[cfg(feature = "aws")]
use crate::error::AwsAdapterError;

/// App-rendered SES message content.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedMagicLinkEmail {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

impl fmt::Debug for RenderedMagicLinkEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RenderedMagicLinkEmail(..)")
    }
}

/// App-provided renderer for magic-link emails. This keeps domain names, URLs,
/// and template copy outside the reusable adapter.
pub trait MagicLinkEmailRenderer {
    fn render(&self, email: &MagicLinkEmail) -> Result<RenderedMagicLinkEmail, DependencyError>;
}

/// In-memory outbox used by examples/tests.
#[derive(Clone, Default)]
pub struct FakeMagicLinkOutbox {
    inner: Arc<Mutex<FakeMagicLinkOutboxInner>>,
}

#[derive(Default)]
struct FakeMagicLinkOutboxInner {
    emails: Vec<MagicLinkEmail>,
    next_error: Option<DependencyError>,
}

impl FakeMagicLinkOutbox {
    pub fn recorded(&self) -> Result<Vec<MagicLinkEmail>, DependencyError> {
        Ok(self.lock_inner()?.emails.clone())
    }

    pub fn set_next_error(&self, error: DependencyError) -> Result<(), DependencyError> {
        self.lock_inner()?.next_error = Some(error);
        Ok(())
    }

    fn lock_inner(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, FakeMagicLinkOutboxInner>, DependencyError> {
        self.inner.lock().map_err(|_| DependencyError::Internal)
    }
}

impl fmt::Debug for FakeMagicLinkOutbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FakeMagicLinkOutbox(..)")
    }
}

impl MagicLinkOutbox for FakeMagicLinkOutbox {
    async fn enqueue_magic_link(&self, email: MagicLinkEmail) -> Result<(), DependencyError> {
        let mut inner = self.lock_inner()?;
        if let Some(error) = inner.next_error.take() {
            return Err(error);
        }
        inner.emails.push(email);
        Ok(())
    }
}

/// SES-backed outbox. The renderer owns URL/template details. This adapter only
/// sends the rendered content.
#[cfg(feature = "aws")]
pub struct SesMagicLinkOutbox<R> {
    client: aws_sdk_sesv2::Client,
    from_email: String,
    renderer: R,
}

#[cfg(feature = "aws")]
impl<R> SesMagicLinkOutbox<R> {
    #[must_use]
    pub fn new(client: aws_sdk_sesv2::Client, from_email: String, renderer: R) -> Self {
        Self {
            client,
            from_email,
            renderer,
        }
    }
}

#[cfg(feature = "aws")]
impl<R> fmt::Debug for SesMagicLinkOutbox<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SesMagicLinkOutbox(..)")
    }
}

#[cfg(feature = "aws")]
impl<R> MagicLinkOutbox for SesMagicLinkOutbox<R>
where
    R: MagicLinkEmailRenderer,
{
    async fn enqueue_magic_link(&self, email: MagicLinkEmail) -> Result<(), DependencyError> {
        use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};

        let rendered = self.renderer.render(&email)?;

        let destination = Destination::builder().to_addresses(rendered.to).build();
        let subject = Content::builder()
            .data(rendered.subject)
            .charset("UTF-8")
            .build()
            .map_err(|_| AwsAdapterError::Internal)?;
        let text = Content::builder()
            .data(rendered.text)
            .charset("UTF-8")
            .build()
            .map_err(|_| AwsAdapterError::Internal)?;
        let mut body_builder = Body::builder().text(text);
        if let Some(html) = rendered.html {
            let html = Content::builder()
                .data(html)
                .charset("UTF-8")
                .build()
                .map_err(|_| AwsAdapterError::Internal)?;
            body_builder = body_builder.html(html);
        }
        let body = body_builder.build();
        let message = Message::builder().subject(subject).body(body).build();
        let content = EmailContent::builder().simple(message).build();
        self.client
            .send_email()
            .from_email_address(self.from_email.clone())
            .destination(destination)
            .content(content)
            .send()
            .await
            .map_err(crate::error::map_ses_send_email_error)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "ses_tests.rs"]
mod tests;
