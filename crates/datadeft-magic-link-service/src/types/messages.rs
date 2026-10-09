//! Request, landing, and confirmation commands and outcomes, plus the outbox email.

use core::fmt;

use datadeft_magic_link_core::confirm_cookie::MintedMagicLinkConfirm;
use datadeft_magic_link_core::{MagicLinkToken, NormalizedEmail};
use zeroize::Zeroize;

use crate::error::{MagicLinkFlowError, MagicLinkServiceError};

use super::ids::{SessionId, UserId};
use super::*;

/// Request command. Debug redacts the target account.
///
/// The library is language-agnostic: the
/// [`MagicLinkOutbox`](crate::MagicLinkOutbox) implementation owns email
/// rendering (and any locale) entirely.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestMagicLinkCommand {
    email: NormalizedEmail,
    terms_accepted: bool,
    privacy_accepted: bool,
}

impl RequestMagicLinkCommand {
    pub fn new(email: NormalizedEmail, terms_accepted: bool, privacy_accepted: bool) -> Self {
        Self {
            email,
            terms_accepted,
            privacy_accepted,
        }
    }

    #[must_use]
    pub fn email(&self) -> &NormalizedEmail {
        &self.email
    }

    #[must_use]
    pub fn terms_accepted(&self) -> bool {
        self.terms_accepted
    }

    #[must_use]
    pub fn privacy_accepted(&self) -> bool {
        self.privacy_accepted
    }
}

impl fmt::Debug for RequestMagicLinkCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestMagicLinkCommand")
            .field("email", &"NormalizedEmail(..)")
            .field("terms_accepted", &self.terms_accepted)
            .field("privacy_accepted", &self.privacy_accepted)
            .finish()
    }
}

/// Scanner-safe landing command containing a bounded raw token candidate.
///
/// Construction immediately destroys oversized attacker input (`None`).
/// `Debug` never exposes the candidate.
pub struct BeginMagicLinkLandingCommand {
    raw_token: Option<String>,
}

impl BeginMagicLinkLandingCommand {
    #[must_use]
    pub fn new(mut raw_token: String) -> Self {
        let raw_token = if raw_token.len() > MAX_RAW_MAGIC_LINK_TOKEN_BYTES {
            raw_token.zeroize();
            None
        } else {
            Some(raw_token)
        };
        Self { raw_token }
    }

    pub(crate) fn raw_token(&self) -> Option<&str> {
        self.raw_token.as_deref()
    }
}

impl fmt::Debug for BeginMagicLinkLandingCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeginMagicLinkLandingCommand(..)")
    }
}

impl Drop for BeginMagicLinkLandingCommand {
    fn drop(&mut self) {
        if let Some(value) = &mut self.raw_token {
            value.zeroize();
        }
    }
}

/// Exact validated account identity deliberately displayed on confirmation pages.
pub struct MagicLinkAccountIdentity(String);

impl MagicLinkAccountIdentity {
    pub(crate) fn from_normalized_email(email: &NormalizedEmail) -> Self {
        Self(email.as_str().to_owned())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MagicLinkAccountIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkAccountIdentity(..)")
    }
}

impl Drop for MagicLinkAccountIdentity {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Successful non-mutating scanner landing result.
pub struct BeginMagicLinkLandingOutcome {
    pub(crate) flow: MintedMagicLinkConfirm,
    pub(crate) account_identity: MagicLinkAccountIdentity,
    pub(crate) cookie_max_age_secs: u64,
}

impl BeginMagicLinkLandingOutcome {
    #[must_use]
    pub fn confirm_cookie_value(&self) -> &str {
        self.flow.cookie().as_secret_value()
    }

    #[must_use]
    pub fn confirmation_value(&self) -> &str {
        self.flow.confirmation().as_value()
    }

    #[must_use]
    pub fn account_identity(&self) -> &MagicLinkAccountIdentity {
        &self.account_identity
    }

    #[must_use]
    pub fn cookie_max_age_secs(&self) -> u64 {
        self.cookie_max_age_secs
    }
}

impl fmt::Debug for BeginMagicLinkLandingOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeginMagicLinkLandingOutcome(..)")
    }
}

/// Scanner-safe confirmation command. It contains no raw magic-link token.
pub struct ConfirmMagicLinkFlowCommand {
    confirm_cookie: String,
    confirmation: String,
    request_country: Option<String>,
}

impl ConfirmMagicLinkFlowCommand {
    pub fn new(
        mut confirm_cookie: String,
        mut confirmation: String,
        request_country: Option<String>,
    ) -> Result<Self, MagicLinkFlowError> {
        if let Some(country) = request_country.as_deref()
            && let Err(error) = validate_country(country)
        {
            confirm_cookie.zeroize();
            confirmation.zeroize();
            return Err(MagicLinkFlowError::from_public_error(error));
        }
        Ok(Self {
            confirm_cookie,
            confirmation,
            request_country,
        })
    }

    pub(crate) fn confirm_cookie(&self) -> &str {
        &self.confirm_cookie
    }

    pub(crate) fn confirmation(&self) -> &str {
        &self.confirmation
    }

    pub(crate) fn request_country(&self) -> Option<&str> {
        self.request_country.as_deref()
    }
}

impl fmt::Debug for ConfirmMagicLinkFlowCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfirmMagicLinkFlowCommand(..)")
    }
}

impl Drop for ConfirmMagicLinkFlowCommand {
    fn drop(&mut self) {
        self.confirm_cookie.zeroize();
        self.confirmation.zeroize();
    }
}

/// Email outbox request. The contained token is bearer material. Debug redacts
/// it. The outbox owns URL construction, template, and language: this carries
/// only the recipient, the token, and the token's expiry.
#[derive(Clone)]
pub struct MagicLinkEmail {
    pub email: NormalizedEmail,
    pub token: MagicLinkToken,
    pub expires_at_unix: u64,
}

impl fmt::Debug for MagicLinkEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkEmail")
            .field("email", &"NormalizedEmail(..)")
            .field("token", &"MagicLinkToken(..)")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// Generic accepted request response.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RequestMagicLinkOutcome;

/// Canonical successful magic-link authentication result.
pub struct MagicLinkAuthenticationOutcome {
    pub(crate) session_cookie: String,
    pub(crate) user_id: UserId,
    pub(crate) session_id: SessionId,
    pub(crate) user_created: bool,
    pub(crate) country: Option<String>,
}

impl MagicLinkAuthenticationOutcome {
    #[must_use]
    pub fn session_cookie_value(&self) -> &str {
        &self.session_cookie
    }

    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub fn user_created(&self) -> bool {
        self.user_created
    }

    #[must_use]
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }
}

impl fmt::Debug for MagicLinkAuthenticationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkAuthenticationOutcome")
            .field("session_cookie", &"<redacted>")
            .field("user_id", &"UserId(..)")
            .field("session_id", &"SessionId(..)")
            .field("user_created", &self.user_created)
            .field("country", &self.country)
            .finish()
    }
}

impl Drop for MagicLinkAuthenticationOutcome {
    fn drop(&mut self) {
        self.session_cookie.zeroize();
    }
}

/// Successful scanner-safe confirmation result.
pub struct ConfirmMagicLinkFlowOutcome {
    pub(crate) authentication: MagicLinkAuthenticationOutcome,
}

impl ConfirmMagicLinkFlowOutcome {
    #[must_use]
    pub fn authentication(&self) -> &MagicLinkAuthenticationOutcome {
        &self.authentication
    }

    #[must_use]
    pub fn into_authentication(self) -> MagicLinkAuthenticationOutcome {
        self.authentication
    }
}

impl fmt::Debug for ConfirmMagicLinkFlowOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfirmMagicLinkFlowOutcome(..)")
    }
}

pub(crate) fn validate_country(country: &str) -> Result<(), MagicLinkServiceError> {
    if country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(MagicLinkServiceError::BadRequest)
    }
}
