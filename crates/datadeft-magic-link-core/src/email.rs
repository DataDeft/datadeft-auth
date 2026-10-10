//! Normalized email identity.
//!
//! One rule, owned here: trim surrounding whitespace, then lowercase the whole
//! address in ASCII, local part included. Lowercasing the local part is a
//! policy choice (RFC 5321 lets a host treat `Alice@` and `alice@` as two
//! mailboxes; practically none do). No other folding: Gmail dots, plus tags
//! and provider-specific alias rules are kept as typed. Identity is then an
//! exact match on the normalized value.

use core::fmt;

use crate::error::MagicLinkError;

const MAX_EMAIL_LEN: usize = 254;
const MAX_LOCAL_LEN: usize = 64;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// A validated email address in normalized form, ready for HMAC and storage
/// use. Every value of this type is normalized: build it from user input with
/// [`Self::normalize`]. `Debug` and errors never contain the address.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct NormalizedEmail(String);

impl NormalizedEmail {
    /// Normalize user input (trim, then ASCII-lowercase) and validate it.
    /// `" Alice@Example.COM "` and `"alice@example.com"` give the same value.
    pub fn normalize(input: &str) -> Result<Self, MagicLinkError> {
        let trimmed = input.trim();
        // Refuse before allocating: no valid address is longer.
        if trimmed.len() > MAX_EMAIL_LEN {
            return Err(MagicLinkError::InvalidEmail);
        }
        Self::from_normalized(&trimmed.to_ascii_lowercase())
    }

    /// Validate a value that is already normalized, such as one read back
    /// from storage. Only validates: a value with uppercase letters or
    /// surrounding whitespace is refused, not converted.
    pub fn from_normalized(value: &str) -> Result<Self, MagicLinkError> {
        if is_valid_email_shape(value) && !value.bytes().any(|byte| byte.is_ascii_uppercase()) {
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
