//! Framework-neutral service types.

use core::fmt;

use datadeft_magic_link_core::confirm_cookie::MintedMagicLinkConfirm;
use datadeft_magic_link_core::{LookupHmac, MagicLinkToken, NormalizedEmail, VerifierHash};
use zeroize::Zeroize;

use crate::error::{MagicLinkFlowError, MagicLinkServiceError};
// The session-cookie purpose lives with the session-cookie framing in
// `session_body`. This module re-exports it here so `types::SessionCookie`
// paths keep working.
pub use crate::session_body::{
    DEFAULT_SESSION_ABSOLUTE_SECS, DEFAULT_SESSION_IDLE_SECS, HKDF_INFO_SESSION_COOKIE_V1,
    SessionCookie, TOKEN_TYPE_SESSION_COOKIE_V1,
};

/// Default magic-link bearer token lifetime: 10 minutes.
pub const DEFAULT_MAGIC_LINK_TTL_SECS: u64 = 10 * 60;
/// Conservative resource cap applied before parsing an untrusted raw magic-link token.
pub const MAX_RAW_MAGIC_LINK_TOKEN_BYTES: usize = 512;

/// Rate-limit bucket key derived from keyed email or selector material and
/// redacted in `Debug`.
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

    /// Wrap a key the service itself assembled from validated components,
    /// without re-scanning or re-allocating it. Debug builds re-check the
    /// canonical form. Untrusted input must go through [`Self::parse`].
    pub(crate) fn from_service_built(value: String) -> Self {
        debug_assert!(
            is_valid_key_component(&value, 256),
            "service-built rate-limit key must be canonical"
        );
        Self(value)
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

    /// Wrap an id the service generated itself (`usr_` + 32 lowercase hex),
    /// without re-scanning or re-allocating it. Debug builds re-check the
    /// canonical form. Untrusted input must go through [`Self::parse`].
    pub(crate) fn from_service_built(value: String) -> Self {
        debug_assert!(
            is_prefixed_hex_id(&value, "usr_", 32),
            "service-built user id must be canonical"
        );
        Self(value)
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
/// it is valid. Storage should use keyed lookup material, not raw ids.
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

    /// Wrap an id the service generated itself (`sid_` + 64 lowercase hex),
    /// without re-scanning or re-allocating it. Debug builds re-check the
    /// canonical form. Untrusted input must go through [`Self::parse`].
    pub(crate) fn from_service_built(value: String) -> Self {
        debug_assert!(
            is_prefixed_hex_id(&value, "sid_", 64),
            "service-built session id must be canonical"
        );
        Self(value)
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
#[derive(Clone)]
pub struct MagicLinkRecord {
    pub selector_lookup_hmac: LookupHmac,
    pub email: NormalizedEmail,
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
            .field("verifier_hash", &"VerifierHash(..)")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("consumed_at_unix", &self.consumed_at_unix)
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

/// Strongly read challenge state used to plan an atomic authentication.
///
/// The repository returns the stored verifier hash so the service, rather than
/// an adapter or database expression, owns the single constant-time comparison
/// with the presented verifier hash. All other fields are security-relevant
/// optimistic-read state that the service validates before constructing a
/// [`CommitMagicLinkAuthentication`] command.
#[derive(Clone)]
pub struct MagicLinkAuthenticationCandidate {
    pub verifier_hash: VerifierHash,
    pub email: NormalizedEmail,
    pub expires_at_unix: u64,
    pub consumed_at_unix: Option<u64>,
    pub terms_version: String,
    pub privacy_version: String,
    pub consented_at_unix: u64,
}

impl fmt::Debug for MagicLinkAuthenticationCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkAuthenticationCandidate")
            .field("verifier_hash", &"VerifierHash(..)")
            .field("email", &"NormalizedEmail(..)")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("consumed_at_unix", &self.consumed_at_unix)
            .field("terms_version", &self.terms_version)
            .field("privacy_version", &self.privacy_version)
            .field("consented_at_unix", &self.consented_at_unix)
            .finish()
    }
}

/// Immutable challenge fields that an atomic authentication commit must bind.
///
/// Challenge writers must keep these fields immutable after creation. The only
/// supported mutation is the atomic transition from unconsumed to consumed. An
/// adapter must condition the commit on exact equality for every field here,
/// require an unconsumed and unexpired challenge with nonzero consent, and must
/// not place verifier-derived material in transaction expressions or values.
#[derive(Clone, Eq, PartialEq)]
pub struct MagicLinkAuthenticationExpectation {
    pub selector_lookup_hmac: LookupHmac,
    pub email: NormalizedEmail,
    pub expires_at_unix: u64,
    pub terms_version: String,
    pub privacy_version: String,
    pub consented_at_unix: u64,
}

impl fmt::Debug for MagicLinkAuthenticationExpectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkAuthenticationExpectation")
            .field("selector_lookup_hmac", &"LookupHmac(..)")
            .field("email", &"NormalizedEmail(..)")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("terms_version", &self.terms_version)
            .field("privacy_version", &self.privacy_version)
            .field("consented_at_unix", &self.consented_at_unix)
            .finish()
    }
}

/// Planned user identity and account branch for an atomic authentication.
///
/// The repository derives all persisted user fields from this id and the
/// challenge expectation, as specified by
/// [`MagicLinkAuthenticationRepository`](crate::traits::MagicLinkAuthenticationRepository).
#[derive(Clone, Eq, PartialEq)]
pub enum MagicLinkAuthenticationUser {
    Existing { user_id: UserId },
    Create { user_id: UserId },
}

impl fmt::Debug for MagicLinkAuthenticationUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Existing { .. } => f.write_str("MagicLinkAuthenticationUser::Existing(..)"),
            Self::Create { .. } => f.write_str("MagicLinkAuthenticationUser::Create(..)"),
        }
    }
}

/// Transaction-scoped idempotency id for one exact authentication plan.
///
/// The canonical representation is `aid_` followed by 32 lowercase hexadecimal
/// characters encoding an independent 128-bit CSPRNG draw. It is not
/// authentication state and must not be persisted. See
/// [`MagicLinkAuthenticationRepository`](crate::traits::MagicLinkAuthenticationRepository)
/// for retry semantics.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct AuthenticationAttemptId(String);

impl AuthenticationAttemptId {
    /// Parse the single canonical authentication-attempt id representation.
    pub fn parse(value: &str) -> Result<Self, MagicLinkServiceError> {
        if is_prefixed_hex_id(value, "aid_", 32) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkServiceError::Internal)
        }
    }

    /// Wrap an id the service generated itself (`aid_` + 32 lowercase hex),
    /// without re-scanning or re-allocating it. Debug builds re-check the
    /// canonical form. Untrusted input must go through [`Self::parse`].
    pub(crate) fn from_service_built(value: String) -> Self {
        debug_assert!(
            is_prefixed_hex_id(&value, "aid_", 32),
            "service-built attempt id must be canonical"
        );
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthenticationAttemptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationAttemptId(..)")
    }
}

/// Complete all-or-nothing magic-link authentication transaction.
///
/// Before submitting this command, the service completes several steps. It owns
/// token parsing, presented verifier HMAC derivation, constant-time comparison,
/// and policy/consent checks. It also owns identity and session-id generation,
/// checked session expiry calculation, and complete browser-cookie minting.
/// The command contains no raw token, selector,
/// verifier, presented verifier hash, or redundant persisted record fields.
/// See [`MagicLinkAuthenticationRepository`](crate::traits::MagicLinkAuthenticationRepository)
/// for the full atomic commit and retry contract.
#[derive(Clone, Eq, PartialEq)]
pub struct CommitMagicLinkAuthentication {
    pub magic_link: MagicLinkAuthenticationExpectation,
    pub now_unix: u64,
    pub attempt_id: AuthenticationAttemptId,
    pub user: MagicLinkAuthenticationUser,
    pub session_id: SessionId,
    /// Authoritative server-side session validity expiry from validated policy.
    /// Storage may retain the record at or after this time for cleanup, but that
    /// retention must never extend session validity.
    pub session_expires_at_unix: u64,
}

impl fmt::Debug for CommitMagicLinkAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitMagicLinkAuthentication")
            .field("magic_link", &self.magic_link)
            .field("now_unix", &self.now_unix)
            .field("attempt_id", &"AuthenticationAttemptId(..)")
            .field("user", &self.user)
            .field("session_id", &"SessionId(..)")
            .field("session_expires_at_unix", &self.session_expires_at_unix)
            .finish()
    }
}

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
