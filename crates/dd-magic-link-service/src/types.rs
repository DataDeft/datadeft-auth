//! Framework-neutral service types.

use core::fmt;

use dd_auth_token_core::keyring::{KeyPurpose, SessionCookie};
use dd_magic_link_core::{LookupHmac, MagicLinkToken, NormalizedEmail, VerifierHash};
use zeroize::Zeroize;

use crate::error::MagicLinkServiceError;

/// Default magic-link bearer token lifetime: 10 minutes.
pub const DEFAULT_MAGIC_LINK_TTL_SECS: u64 = 10 * 60;
/// Default session idle lifetime: 24 hours.
pub const DEFAULT_SESSION_IDLE_SECS: u64 = 24 * 60 * 60;
/// Default session absolute lifetime, owned by the session-cookie purpose.
pub const DEFAULT_SESSION_ABSOLUTE_SECS: u64 = SessionCookie::MAX_ABSOLUTE_AGE_SECS;

/// Magic-link email locale. Adapters decide the rendered template and URL.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EmailLocale {
    En,
    Hu,
}

/// App-supplied client key used for limiter buckets.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ClientKey(String);

impl ClientKey {
    /// Parse a bounded, log-safe limiter key component.
    pub fn parse(value: &str) -> Result<Self, MagicLinkServiceError> {
        if is_valid_key_component(value, 128) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkServiceError::BadRequest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientKey(..)")
    }
}

/// Rate-limit bucket key. It is derived from keyed material or app-supplied
/// client keys and is redacted in `Debug`.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RateLimitKey(String);

impl RateLimitKey {
    pub fn parse(value: &str) -> Result<Self, MagicLinkServiceError> {
        if is_valid_key_component(value, 256) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkServiceError::Internal)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RateLimitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RateLimitKey(..)")
    }
}

/// Stable application user id. Not bearer material, but redacted by default.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct UserId(String);

impl UserId {
    pub fn parse(value: &str) -> Result<Self, MagicLinkServiceError> {
        if is_prefixed_hex_id(value, "usr_", 32) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkServiceError::Internal)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserId(..)")
    }
}

/// Server-side session id. This is bearer-equivalent while a cookie containing
/// it is valid; storage should use keyed lookup material, not raw ids.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    pub fn parse(value: &str) -> Result<Self, MagicLinkServiceError> {
        if is_prefixed_hex_id(value, "sid_", 64) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkServiceError::Internal)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId(..)")
    }
}

/// Magic-link record written at request time. It contains keyed lookup material,
/// never raw selectors or verifiers.
#[derive(Clone, Eq, PartialEq)]
pub struct MagicLinkRecord {
    pub selector_lookup_hmac: LookupHmac,
    pub email: NormalizedEmail,
    pub user_id: Option<UserId>,
    pub verifier_hash: VerifierHash,
    pub expires_at_unix: u64,
    pub consumed_at_unix: Option<u64>,
    pub terms_version: String,
    pub privacy_version: String,
    pub consented_at_unix: u64,
}

impl fmt::Debug for MagicLinkRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkRecord")
            .field("selector_lookup_hmac", &"LookupHmac(..)")
            .field("email", &"NormalizedEmail(..)")
            .field("user_id", &self.user_id.as_ref().map(|_| "UserId(..)"))
            .field("verifier_hash", &"VerifierHash(..)")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("consumed_at_unix", &self.consumed_at_unix)
            .field("terms_version", &self.terms_version)
            .field("privacy_version", &self.privacy_version)
            .field("consented_at_unix", &self.consented_at_unix)
            .finish()
    }
}

/// Consumed magic-link data returned after the atomic consume transition.
#[derive(Clone, Eq, PartialEq)]
pub struct ConsumedMagicLink {
    pub email: NormalizedEmail,
    pub user_id: Option<UserId>,
    pub terms_version: String,
    pub privacy_version: String,
    pub consented_at_unix: u64,
}

impl fmt::Debug for ConsumedMagicLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumedMagicLink")
            .field("email", &"NormalizedEmail(..)")
            .field("user_id", &self.user_id.as_ref().map(|_| "UserId(..)"))
            .field("terms_version", &self.terms_version)
            .field("privacy_version", &self.privacy_version)
            .field("consented_at_unix", &self.consented_at_unix)
            .finish()
    }
}

/// User repository record.
#[derive(Clone, Eq, PartialEq)]
pub struct UserRecord {
    pub user_id: UserId,
    pub email: NormalizedEmail,
    pub disabled: bool,
    pub terms_version: Option<String>,
    pub privacy_version: Option<String>,
    pub consented_at_unix: Option<u64>,
}

impl fmt::Debug for UserRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserRecord")
            .field("user_id", &"UserId(..)")
            .field("email", &"NormalizedEmail(..)")
            .field("disabled", &self.disabled)
            .field(
                "terms_version",
                &self.terms_version.as_deref().unwrap_or("<missing>"),
            )
            .field(
                "privacy_version",
                &self.privacy_version.as_deref().unwrap_or("<missing>"),
            )
            .field("consented_at_unix", &self.consented_at_unix)
            .finish()
    }
}

/// Server-side session record.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionRecord {
    pub session_id: SessionId,
    pub user_id: UserId,
    pub email: NormalizedEmail,
    pub created_at_unix: u64,
    pub revoked_at_unix: Option<u64>,
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecord")
            .field("session_id", &"SessionId(..)")
            .field("user_id", &"UserId(..)")
            .field("email", &"NormalizedEmail(..)")
            .field("created_at_unix", &self.created_at_unix)
            .field("revoked_at_unix", &self.revoked_at_unix)
            .finish()
    }
}

/// Request command. Debug redacts the target account.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestMagicLinkCommand {
    email: NormalizedEmail,
    locale: EmailLocale,
    terms_accepted: bool,
    privacy_accepted: bool,
    client_key: Option<ClientKey>,
}

impl RequestMagicLinkCommand {
    pub fn new(
        email: NormalizedEmail,
        locale: EmailLocale,
        terms_accepted: bool,
        privacy_accepted: bool,
        client_key: Option<ClientKey>,
    ) -> Self {
        Self {
            email,
            locale,
            terms_accepted,
            privacy_accepted,
            client_key,
        }
    }

    #[must_use]
    pub fn email(&self) -> &NormalizedEmail {
        &self.email
    }

    #[must_use]
    pub fn locale(&self) -> EmailLocale {
        self.locale
    }

    #[must_use]
    pub fn terms_accepted(&self) -> bool {
        self.terms_accepted
    }

    #[must_use]
    pub fn privacy_accepted(&self) -> bool {
        self.privacy_accepted
    }

    #[must_use]
    pub fn client_key(&self) -> Option<&ClientKey> {
        self.client_key.as_ref()
    }
}

impl fmt::Debug for RequestMagicLinkCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestMagicLinkCommand")
            .field("email", &"NormalizedEmail(..)")
            .field("locale", &self.locale)
            .field("terms_accepted", &self.terms_accepted)
            .field("privacy_accepted", &self.privacy_accepted)
            .field(
                "client_key",
                &self.client_key.as_ref().map(|_| "ClientKey(..)"),
            )
            .finish()
    }
}

/// Consume command. Debug redacts the bearer token.
#[derive(Clone, Eq, PartialEq)]
pub struct ConsumeMagicLinkCommand {
    token: MagicLinkToken,
    client_key: Option<ClientKey>,
    request_country: Option<String>,
}

impl ConsumeMagicLinkCommand {
    pub fn new(
        token: MagicLinkToken,
        client_key: Option<ClientKey>,
        request_country: Option<String>,
    ) -> Result<Self, MagicLinkServiceError> {
        if let Some(country) = request_country.as_deref() {
            validate_country(country)?;
        }
        Ok(Self {
            token,
            client_key,
            request_country,
        })
    }

    pub fn parse_token(
        token: &str,
        client_key: Option<ClientKey>,
        request_country: Option<String>,
    ) -> Result<Self, MagicLinkServiceError> {
        Self::new(MagicLinkToken::parse(token)?, client_key, request_country)
    }

    #[must_use]
    pub fn token(&self) -> &MagicLinkToken {
        &self.token
    }

    #[must_use]
    pub fn client_key(&self) -> Option<&ClientKey> {
        self.client_key.as_ref()
    }

    #[must_use]
    pub fn request_country(&self) -> Option<&str> {
        self.request_country.as_deref()
    }
}

impl fmt::Debug for ConsumeMagicLinkCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumeMagicLinkCommand")
            .field("token", &"MagicLinkToken(..)")
            .field(
                "client_key",
                &self.client_key.as_ref().map(|_| "ClientKey(..)"),
            )
            .field("request_country", &self.request_country)
            .finish()
    }
}

/// Email outbox request. The contained token is bearer material; Debug redacts it.
#[derive(Clone, Eq, PartialEq)]
pub struct MagicLinkEmail {
    pub email: NormalizedEmail,
    pub token: MagicLinkToken,
    pub locale: EmailLocale,
    pub expires_at_unix: u64,
}

impl fmt::Debug for MagicLinkEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkEmail")
            .field("email", &"NormalizedEmail(..)")
            .field("token", &"MagicLinkToken(..)")
            .field("locale", &self.locale)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// Generic accepted request response.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RequestMagicLinkOutcome;

/// Successful consume response.
#[derive(Clone, Eq, PartialEq)]
pub struct ConsumeMagicLinkOutcome {
    pub session_cookie: String,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub user_created: bool,
    pub country: Option<String>,
}

impl fmt::Debug for ConsumeMagicLinkOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumeMagicLinkOutcome")
            .field("session_cookie", &"<redacted>")
            .field("user_id", &"UserId(..)")
            .field("session_id", &"SessionId(..)")
            .field("user_created", &self.user_created)
            .field("country", &self.country)
            .finish()
    }
}

impl Drop for ConsumeMagicLinkOutcome {
    fn drop(&mut self) {
        self.session_cookie.zeroize();
    }
}

pub(crate) fn validate_country(country: &str) -> Result<(), MagicLinkServiceError> {
    if country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(MagicLinkServiceError::BadRequest)
    }
}

fn is_prefixed_hex_id(value: &str, prefix: &str, hex_len: usize) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    rest.len() == hex_len
        && rest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_valid_key_component(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
