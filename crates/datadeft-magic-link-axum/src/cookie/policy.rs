//! One validation chokepoint for the complete cookie policy tuple: name
//! (including the opt-in `__Host-` prefix), path shape and the attribute
//! invariants. Both cookie configs validate through here, so the prefix
//! rules are carried by the invariants, not by which type is being built:
//! the default narrow-path confirm cookie fails `__Host-` naturally with
//! `HostPrefixRequiresRootPath`.

use super::{CookieConfigError, SameSite};

pub(super) fn validate_cookie_policy(
    name: &str,
    path: &str,
    secure: bool,
    same_site: SameSite,
) -> Result<(), CookieConfigError> {
    validate_cookie_path(path)?;
    if same_site == SameSite::None && !secure {
        return Err(CookieConfigError::SameSiteNoneRequiresSecure);
    }
    match name.strip_prefix("__Host-") {
        None => validate_cookie_name(name),
        Some(suffix) => {
            if name.len() > 64 {
                return Err(CookieConfigError::InvalidName);
            }
            validate_cookie_name(suffix)?;
            if !secure {
                return Err(CookieConfigError::HostPrefixRequiresSecure);
            }
            if path != "/" {
                return Err(CookieConfigError::HostPrefixRequiresRootPath);
            }
            Ok(())
        }
    }
}

fn validate_cookie_name(value: &str) -> Result<(), CookieConfigError> {
    if !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
    {
        Ok(())
    } else {
        Err(CookieConfigError::InvalidName)
    }
}

fn validate_cookie_path(value: &str) -> Result<(), CookieConfigError> {
    if value.starts_with('/')
        && value.len() <= 128
        && !value.contains(['?', '#', '%', '\\', ',', ';'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && !byte.is_ascii_whitespace())
    {
        Ok(())
    } else {
        Err(CookieConfigError::InvalidPath)
    }
}
