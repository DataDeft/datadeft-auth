//! Session cookie authentication: strict incoming-cookie extraction and the
//! opaque redacted rejection response.

use core::fmt;
use core::future::Future;

use axum::Json;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use datadeft_magic_link_service::{SessionValidationError, ValidatedSession};
use zeroize::Zeroize;

use crate::cookie::{SessionCookieConfig, clear_session_cookie_header};
use crate::cookie_parse::extract_target_cookie;
use crate::error::{ErrorBody, MagicLinkHttpError};

/// Redacted, zeroized incoming primary session cookie.
pub struct SessionCookieValue(String);

impl SessionCookieValue {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionCookieValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionCookieValue(..)")
    }
}

impl Drop for SessionCookieValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Why [`authenticate_session`] rejected a request. Carries no cookie or
/// session data.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionRejectionKind {
    /// No usable session: the cookie is missing, malformed, duplicated,
    /// expired, revoked, or belongs to a disabled user. The client signs in
    /// again; the rejection carries a header that clears the cookie.
    Invalid,
    /// A dependency failed. The session may be fine; retry later.
    Unavailable,
    /// The server faulted.
    Internal,
}

/// Redacted rejection returned by [`authenticate_session`].
///
/// [`IntoResponse`] renders the library's own response. Apps with their own
/// error envelope read [`Self::kind`] and append [`Self::clear_cookie_header`]
/// instead.
pub struct SessionAuthRejection {
    kind: SessionRejectionKind,
    clear_cookie: Option<HeaderValue>,
}

impl SessionAuthRejection {
    /// Why the request was rejected.
    #[must_use]
    pub fn kind(&self) -> SessionRejectionKind {
        self.kind
    }

    /// The `Set-Cookie` header that clears the session cookie. Present only
    /// for [`SessionRejectionKind::Invalid`]; send it with any response you
    /// render for this rejection.
    #[must_use]
    pub fn clear_cookie_header(&self) -> Option<&HeaderValue> {
        self.clear_cookie.as_ref()
    }
}

impl fmt::Debug for SessionAuthRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionAuthRejection(..)")
    }
}

impl IntoResponse for SessionAuthRejection {
    fn into_response(self) -> Response {
        let error = match self.kind {
            SessionRejectionKind::Invalid => MagicLinkHttpError::Forbidden,
            SessionRejectionKind::Unavailable => MagicLinkHttpError::Unavailable,
            SessionRejectionKind::Internal => MagicLinkHttpError::Internal,
        };
        let status = match self.kind {
            SessionRejectionKind::Invalid => StatusCode::UNAUTHORIZED,
            SessionRejectionKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            SessionRejectionKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let mut response = (status, Json(ErrorBody::from(error))).into_response();
        if let Some(clear) = self.clear_cookie {
            response.headers_mut().append(SET_COOKIE, clear);
        }
        response
    }
}

/// Authenticate a unique, strictly parsed incoming session cookie.
///
/// Missing, empty, malformed, quoted, oversized, or duplicate cookies return the
/// same `401` response and do not invoke `validate`.
pub async fn authenticate_session<F, Fut>(
    headers: &HeaderMap,
    cookie_config: &SessionCookieConfig,
    validate: F,
) -> Result<ValidatedSession, SessionAuthRejection>
where
    F: FnOnce(SessionCookieValue) -> Fut,
    Fut: Future<Output = Result<ValidatedSession, SessionValidationError>>,
{
    let value = match extract_target_cookie(headers, cookie_config.name()) {
        Ok(value) => value,
        Err(_) => return Err(session_unauthorized(cookie_config)),
    };
    match validate(SessionCookieValue(value)).await {
        Ok(session) => Ok(session),
        Err(SessionValidationError::InvalidSession) => Err(session_unauthorized(cookie_config)),
        Err(SessionValidationError::Unavailable) => Err(SessionAuthRejection {
            kind: SessionRejectionKind::Unavailable,
            clear_cookie: None,
        }),
        Err(SessionValidationError::Internal) => Err(SessionAuthRejection {
            kind: SessionRejectionKind::Internal,
            clear_cookie: None,
        }),
    }
}

fn session_unauthorized(config: &SessionCookieConfig) -> SessionAuthRejection {
    SessionAuthRejection {
        kind: SessionRejectionKind::Invalid,
        clear_cookie: Some(clear_session_cookie_header(config)),
    }
}

#[cfg(test)]
#[path = "session_auth_tests.rs"]
mod tests;
