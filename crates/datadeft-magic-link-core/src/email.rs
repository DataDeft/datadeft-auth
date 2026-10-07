//! Exact-match normalized email boundary.
//!
//! This type validates structure only. It does not trim, lowercase, fold Gmail
//! dots, strip plus tags, or apply provider-specific alias rules. The consuming
//! application supplies the normalized value and this crate compares it exactly.

use core::fmt;

use crate::error::MagicLinkError;

const MAX_EMAIL_LEN: usize = 254;
const MAX_LOCAL_LEN: usize = 64;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// App-provided normalized email value, validated before HMAC/storage use.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct NormalizedEmail(String);

impl NormalizedEmail {
    /// Validate an already-normalized email value.
    pub fn parse(value: &str) -> Result<Self, MagicLinkError> {
        if is_valid_email_shape(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkError::InvalidEmail)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NormalizedEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NormalizedEmail(..)")
    }
}

fn is_valid_email_shape(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_EMAIL_LEN
        || value.trim() != value
        || value.bytes().any(|b| {
            b.is_ascii_control()
                || b.is_ascii_whitespace()
                || matches!(b, b'\0' | b',' | b';' | b'<' | b'>' | b'"')
        })
    {
        return false;
    }

    let mut parts = value.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    is_valid_local(local) && is_valid_domain(domain)
}

fn is_valid_local(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= MAX_LOCAL_LEN
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                        | b'.'
                )
        })
}

fn is_valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= MAX_DOMAIN_LEN
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
#[path = "email_tests.rs"]
mod tests;
