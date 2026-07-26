//! Encrypted session-cookie body framing owned by the service crate.

use core::fmt;

use crate::error::MagicLinkServiceError;
use crate::types::{SessionId, validate_country};

const SESSION_BODY_V1: u8 = 1;

/// Invalid authenticated session-cookie body framing.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionBodyError {
    /// The body was malformed, non-canonical, or contained invalid session data.
    Invalid,
}

impl fmt::Display for SessionBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid session cookie body")
    }
}

impl std::error::Error for SessionBodyError {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionCookieBody {
    pub session_id: SessionId,
    pub country: Option<String>,
}

pub fn encode_session_cookie_body(
    session_id: &SessionId,
    country: Option<&str>,
) -> Result<Vec<u8>, MagicLinkServiceError> {
    if let Some(country) = country {
        validate_country(country)?;
    }
    let sid = session_id.as_str().as_bytes();
    let sid_len = u8::try_from(sid.len()).map_err(|_| MagicLinkServiceError::Internal)?;
    let country_bytes = country.unwrap_or("").as_bytes();
    let country_len =
        u8::try_from(country_bytes.len()).map_err(|_| MagicLinkServiceError::Internal)?;

    let mut body = Vec::with_capacity(3 + sid.len() + country_bytes.len());
    body.push(SESSION_BODY_V1);
    body.push(sid_len);
    body.extend_from_slice(sid);
    body.push(country_len);
    body.extend_from_slice(country_bytes);
    Ok(body)
}

pub fn decode_session_cookie_body(body: &[u8]) -> Result<SessionCookieBody, SessionBodyError> {
    let Some((&version, rest)) = body.split_first() else {
        return Err(SessionBodyError::Invalid);
    };
    if version != SESSION_BODY_V1 {
        return Err(SessionBodyError::Invalid);
    }
    let Some((&sid_len, rest)) = rest.split_first() else {
        return Err(SessionBodyError::Invalid);
    };
    let sid_len = usize::from(sid_len);
    if rest.len() < sid_len + 1 {
        return Err(SessionBodyError::Invalid);
    }
    let (sid_bytes, rest) = rest.split_at(sid_len);
    let Some((&country_len, country_bytes)) = rest.split_first() else {
        return Err(SessionBodyError::Invalid);
    };
    if country_bytes.len() != usize::from(country_len) {
        return Err(SessionBodyError::Invalid);
    }

    let sid = core::str::from_utf8(sid_bytes).map_err(|_| SessionBodyError::Invalid)?;
    let country = if country_bytes.is_empty() {
        None
    } else {
        let value = core::str::from_utf8(country_bytes).map_err(|_| SessionBodyError::Invalid)?;
        validate_country(value).map_err(|_| SessionBodyError::Invalid)?;
        Some(value.to_owned())
    };

    Ok(SessionCookieBody {
        session_id: SessionId::parse(sid).map_err(|_| SessionBodyError::Invalid)?,
        country,
    })
}

#[cfg(test)]
#[path = "session_body_tests.rs"]
mod tests;
