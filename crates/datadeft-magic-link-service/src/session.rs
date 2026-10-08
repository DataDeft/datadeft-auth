//! Complete server-side session validation and explicit cookie refresh.
//!
//! Validation is deliberately non-sliding: it does not touch repository state or
//! re-mint the cookie. The authenticated cookie timestamp is bounded by the
//! configured idle lifetime, while its original `iat` is bounded by the absolute
//! lifetime. The repository remains authoritative for revocation and storage
//! expiry.
//!
//! Sliding is a separate, explicit step: [`refresh_session_cookie`] re-issues
//! the cookie with a fresh activity timestamp and the original `iat`, so active
//! users stay signed in up to the absolute lifetime and never beyond it.

use core::fmt;

use datadeft_auth_token_core::TokenError;
use datadeft_auth_token_core::cookie::{
    CLOCK_SKEW_TOLERANCE_SECS, mint_bound_cookie, parse_bound_cookie,
};
use datadeft_auth_token_core::keyring::KeyRing;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::config::MagicLinkServiceConfig;
use crate::error::DependencyError;
use crate::session_body::{decode_session_cookie_body, encode_session_cookie_body};
use crate::traits::{Clock, SessionRepository};
use crate::types::{SessionCookie, SessionRecord};

/// Public failure classes for incoming session authentication.
///
/// No variant carries a cookie, session identifier, email address, key id, or
/// repository detail.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionValidationError {
    /// Cookie, body, repository record, freshness, expiry, or revocation failed.
    InvalidSession,
    /// A dependency is temporarily unavailable. Callers may retry.
    Unavailable,
    /// Service configuration or a dependency invariant is invalid.
    Internal,
}

impl fmt::Display for SessionValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSession => f.write_str("invalid session"),
            Self::Unavailable => f.write_str("session validation unavailable"),
            Self::Internal => f.write_str("internal session validation error"),
        }
    }
}

impl std::error::Error for SessionValidationError {}

/// Authenticated server-side session and its cookie-bound country context.
///
/// Only [`validate_session`] constructs one, so holding a `ValidatedSession`
/// proves the cookie and the server-side record passed every check. That is
/// what makes it safe input for [`refresh_session_cookie`]. Building one by
/// hand does not compile:
///
/// ```compile_fail
/// use datadeft_magic_link_service::ValidatedSession;
/// fn forge(session: datadeft_magic_link_service::SessionRecord) -> ValidatedSession {
///     ValidatedSession { session, country: None, issued_at_unix: 0,
///         last_activity_unix: 0, validated_at_unix: 0 }
/// }
/// ```
pub struct ValidatedSession {
    session: SessionRecord,
    country: Option<String>,
    /// Authenticated first-issue time (`iat`) of the presented cookie.
    issued_at_unix: u64,
    /// Authenticated last-activity time (Branca timestamp) of the cookie.
    last_activity_unix: u64,
    /// The single clock reading the validation used.
    validated_at_unix: u64,
}

impl ValidatedSession {
    /// Server-side session record that passed lookup, expiry, and revocation checks.
    #[must_use]
    pub fn session(&self) -> &SessionRecord {
        &self.session
    }

    /// Country context authenticated inside the session cookie, when present.
    #[must_use]
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }
}

impl fmt::Debug for ValidatedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedSession(..)")
    }
}

/// Authenticate an incoming session cookie against cookie and server-side policy.
///
/// The operation validates configuration before reading the clock, reads the
/// clock exactly once, authenticates and freshness-checks the cookie, decodes its
/// body, enforces the country lock, looks up the session, and checks that its
/// user is still active (not disabled).
/// Missing, revoked, expired, future-created, malformed, and wrong-country
/// sessions all collapse to [`SessionValidationError::InvalidSession`].
///
/// # Country pinning
///
/// A session issued with a trusted-edge country locks to that country:
/// `request_country` (the current request's trusted-edge signal, never
/// client-supplied input) must match it on every validation, and an absent
/// signal does not satisfy the lock: fail closed. Sessions issued without a
/// country are unlocked and skip the check, so deployments without an edge
/// country header are unaffected.
///
/// This operation is not a sliding refresh: it never writes, revokes, touches, or
/// re-mints session state.
pub async fn validate_session<Sessions, ServiceClock>(
    cookie_value: &str,
    request_country: Option<&str>,
    session_keyring: &KeyRing<SessionCookie>,
    sessions: &Sessions,
    clock: &ServiceClock,
    config: &MagicLinkServiceConfig,
) -> Result<ValidatedSession, SessionValidationError>
where
    Sessions: SessionRepository,
    ServiceClock: Clock,
{
    let max_age = config
        .session_max_age()
        .map_err(|_| SessionValidationError::Internal)?;
    let now_unix = clock.now_unix().map_err(map_session_dependency_error)?;
    let verified =
        parse_bound_cookie::<SessionCookie>(cookie_value, session_keyring, now_unix, max_age)
            .map_err(|_| SessionValidationError::InvalidSession)?;
    let body = decode_session_cookie_body(verified.body())
        .map_err(|_| SessionValidationError::InvalidSession)?;
    if let Some(bound_country) = body.country.as_deref()
        && request_country != Some(bound_country)
    {
        return Err(SessionValidationError::InvalidSession);
    }
    let session = sessions
        .find_session(&body.session_id, now_unix)
        .await
        .map_err(map_session_dependency_error)?
        .ok_or(SessionValidationError::InvalidSession)?;

    let latest_creation = now_unix.saturating_add(CLOCK_SKEW_TOLERANCE_SECS);
    if session.revoked_at_unix.is_some()
        || session.session_id != body.session_id
        || session.created_at_unix > latest_creation
    {
        return Err(SessionValidationError::InvalidSession);
    }
    let session_age = now_unix.saturating_sub(session.created_at_unix);
    if session_age > max_age.absolute_secs {
        return Err(SessionValidationError::InvalidSession);
    }
    // A disabled (or missing) user ends every session at once, without
    // waiting for revocation to reach each one.
    if !sessions
        .is_session_owner_active(&session.user_id, session.created_at_unix)
        .await
        .map_err(map_session_dependency_error)?
    {
        return Err(SessionValidationError::InvalidSession);
    }

    Ok(ValidatedSession {
        session,
        country: body.country,
        issued_at_unix: u64::from(verified.iat()),
        last_activity_unix: u64::from(verified.timestamp()),
        validated_at_unix: now_unix,
    })
}

/// A re-issued session cookie value. Bearer material: `Debug` is redacted and
/// the value is zeroized on drop.
pub struct RefreshedSessionCookie(String);

impl RefreshedSessionCookie {
    /// The cookie value to send in `Set-Cookie`.
    #[must_use]
    pub fn as_secret_value(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RefreshedSessionCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefreshedSessionCookie(..)")
    }
}

impl Drop for RefreshedSessionCookie {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Re-issue the session cookie when it is due, so active users stay signed in.
///
/// Call it after [`validate_session`] succeeds, in the same request, and send
/// any returned value with the normal session `Set-Cookie` header on a response
/// marked `Cache-Control: no-store`, so no shared cache can store the cookie.
/// It returns `Ok(None)` while the cookie's last activity is younger than half
/// the idle lifetime, so most requests change nothing.
///
/// "Same request" is enforced: the clock is read again, and a validation older
/// than the clock-skew tolerance (or a clock that went backwards) is refused
/// with [`SessionValidationError::InvalidSession`]; validate again first.
///
/// Security properties:
///
/// - It only accepts a fresh [`ValidatedSession`], which only
///   [`validate_session`] builds.
/// - The new cookie keeps the original issue time (`iat`), session id, and
///   country binding. Only the activity timestamp moves, so the absolute
///   lifetime can never be extended; a cookie at or past it is not re-issued.
/// - It never reads or writes the repository. Revocation stays authoritative:
///   a refreshed cookie for a revoked session fails its next validation.
/// - It mints under the keyring's current active key, so refreshing also moves
///   active sessions onto a rotated key.
///
/// The trade-off is the usual one for sliding sessions: a stolen cookie that
/// keeps being used stays valid until the absolute lifetime or revocation.
pub fn refresh_session_cookie<Rng, ServiceClock>(
    validated: &ValidatedSession,
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    clock: &ServiceClock,
    config: &MagicLinkServiceConfig,
) -> Result<Option<RefreshedSessionCookie>, SessionValidationError>
where
    Rng: RngCore + CryptoRng + ?Sized,
    ServiceClock: Clock,
{
    let max_age = config
        .session_max_age()
        .map_err(|_| SessionValidationError::Internal)?;
    let now_unix = clock.now_unix().map_err(map_session_dependency_error)?;
    if now_unix < validated.validated_at_unix
        || now_unix - validated.validated_at_unix > CLOCK_SKEW_TOLERANCE_SECS
    {
        // A stale validation: revocation may have happened since.
        return Err(SessionValidationError::InvalidSession);
    }
    // A cookie stamped slightly in the future (within clock skew) is fresh.
    if validated.issued_at_unix > now_unix
        || now_unix.saturating_sub(validated.last_activity_unix) < max_age.idle_secs / 2
    {
        return Ok(None);
    }
    if now_unix.saturating_sub(validated.issued_at_unix) >= max_age.absolute_secs {
        return Ok(None);
    }
    let timestamp = u32::try_from(now_unix).map_err(|_| SessionValidationError::Internal)?;
    let iat =
        u32::try_from(validated.issued_at_unix).map_err(|_| SessionValidationError::Internal)?;
    let mut body =
        encode_session_cookie_body(&validated.session.session_id, validated.country.as_deref())
            .map_err(|_| SessionValidationError::Internal)?;
    let minted = mint_bound_cookie::<SessionCookie, _>(
        &body,
        session_keyring,
        rng,
        timestamp,
        iat,
        now_unix,
    );
    body.zeroize();
    match minted {
        Ok(cookie) => Ok(Some(RefreshedSessionCookie(cookie))),
        Err(TokenError::EntropyUnavailable) => Err(SessionValidationError::Unavailable),
        // Keyring and rotation faults stay distinct from an invalid session.
        Err(_) => Err(SessionValidationError::Internal),
    }
}

fn map_session_dependency_error(error: DependencyError) -> SessionValidationError {
    match error {
        DependencyError::Unavailable | DependencyError::RateLimited => {
            SessionValidationError::Unavailable
        }
        DependencyError::ConditionalWriteFailed | DependencyError::Internal => {
            SessionValidationError::Internal
        }
    }
}

#[cfg(test)]
mod refresh_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod validation_tests;
