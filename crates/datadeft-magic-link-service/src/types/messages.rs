//! Request, landing, and confirmation commands and outcomes, plus the outbox email.

use core::fmt;

use datadeft_magic_link_core::confirm_cookie::MintedMagicLinkConfirm;
use datadeft_magic_link_core::{MagicLinkToken, NormalizedEmail};
use zeroize::Zeroize;

use crate::error::{MagicLinkFlowError, MagicLinkServiceError};
use crate::locale::Locale;

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
    locale_hint: Option<String>,
}

impl RequestMagicLinkCommand {
    pub fn new(email: NormalizedEmail, terms_accepted: bool, privacy_accepted: bool) -> Self {
        Self {
            email,
            terms_accepted,
            privacy_accepted,
            locale_hint: None,
        }
    }

    /// Attach the request's locale hint, for example the page language. It
    /// is only a hint: the service resolves it against
    /// [`MagicLinkServiceConfig::locales`](crate::MagicLinkServiceConfig) and
    /// never passes it on as text. A hint longer than
    /// [`MAX_LOCALE_HINT_BYTES`](crate::locale::MAX_LOCALE_HINT_BYTES) or with
    /// other than ASCII letters, digits, `-` and `_` is ignored.
    #[must_use]
    pub fn with_locale_hint(mut self, hint: &str) -> Self {
        self.locale_hint = crate::locale::bounded_hint(hint);
        self
    }

    /// The kept locale hint, if any.
    #[must_use]
    pub fn locale_hint(&self) -> Option<&str> {
        self.locale_hint.as_deref()
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
            .field("locale_hint", &self.locale_hint)
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

/// How confirmation pages (and the flow-state route) show the account.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum AccountDisplay {
    /// The first character of the local part, five bullets, and the full
    /// domain: `i•••••@datadeft.eu` (default). The bullet count is fixed, so
    /// the length of the address does not leak. Anyone who holds the link,
    /// such as a scanner, a proxy cache or a forward recipient, sees only
    /// this.
    #[default]
    Masked,
    /// The full normalized address.
    Full,
}

/// Fixed mask between the first character and the domain.
const ACCOUNT_MASK: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

/// Validated account identity displayed on confirmation pages, shaped by
/// [`AccountDisplay`].
pub struct MagicLinkAccountIdentity(String);

impl MagicLinkAccountIdentity {
    pub(crate) fn new(email: &NormalizedEmail, display: AccountDisplay) -> Self {
        match display {
            AccountDisplay::Full => Self(email.as_str().to_owned()),
            AccountDisplay::Masked => Self(masked_email(email.as_str())),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `NormalizedEmail` guarantees one `@` and a non-empty local part; anything
/// else masks completely rather than failing.
fn masked_email(email: &str) -> String {
    match email.rsplit_once('@') {
        Some((local, domain)) => match local.chars().next() {
            Some(first) => format!("{first}{ACCOUNT_MASK}@{domain}"),
            None => format!("{ACCOUNT_MASK}@{domain}"),
        },
        None => ACCOUNT_MASK.to_owned(),
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
/// it. The outbox owns URL construction and templates; this carries the
/// recipient, the token, its expiry, and the resolved locale the template is
/// chosen by.
#[derive(Clone)]
pub struct MagicLinkEmail {
    pub email: NormalizedEmail,
    pub token: MagicLinkToken,
    pub expires_at_unix: u64,
    /// The resolved email locale, when
    /// [`MagicLinkServiceConfig::locales`](crate::MagicLinkServiceConfig) is
    /// set. Never stored.
    pub locale: Option<Locale>,
}

impl fmt::Debug for MagicLinkEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkEmail")
            .field("email", &"NormalizedEmail(..)")
            .field("token", &"MagicLinkToken(..)")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("locale", &self.locale)
            .finish()
    }
}

/// What a magic-link request did. Internal only: the public response is the
/// same generic accepted answer for both, so nobody can tell from outside
/// whether an email was sent. Log and count it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RequestMagicLinkOutcome {
    /// The link was stored and handed to the outbox.
    Sent,
    /// A per-email limit refused it; nothing was stored or sent.
    Throttled(RequestThrottle),
}

/// The per-email bucket that throttled a request (the first in this order).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RequestThrottle {
    /// Requests for the address in the short window.
    EmailShortWindow,
    /// Requests for the address per day.
    EmailDaily,
    /// Emails sent to the address per hour.
    OutboxHourly,
    /// Emails sent to the address per day.
    OutboxDaily,
}

impl RequestMagicLinkOutcome {
    /// Stable label for logs and metrics, never sent to the client.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Sent => "magic_link_request_sent",
            Self::Throttled(RequestThrottle::EmailShortWindow) => {
                "magic_link_request_throttled_email_short_window"
            }
            Self::Throttled(RequestThrottle::EmailDaily) => {
                "magic_link_request_throttled_email_daily"
            }
            Self::Throttled(RequestThrottle::OutboxHourly) => {
                "magic_link_request_throttled_outbox_hourly"
            }
            Self::Throttled(RequestThrottle::OutboxDaily) => {
                "magic_link_request_throttled_outbox_daily"
            }
        }
    }
}

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

    /// The country the new session is pinned to: the country itself, or
    /// its group's tag under [`CountryPolicy::Groups`](crate::CountryPolicy).
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
