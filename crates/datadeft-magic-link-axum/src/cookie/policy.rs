//! Cookie name/path validation; prefix invariants apply to the complete policy.

use super::CookieConfigError;

pub(super) fn validate_cookie_name(value: &str) -> Result<(), CookieConfigError> {
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

pub(super) fn validate_cookie_path(value: &str) -> Result<(), CookieConfigError> {
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

pub(super) fn validate_session_cookie_policy(
    name: &str,
    path: &str,
    secure: bool,
) -> Result<(), CookieConfigError> {
    let Some(suffix) = name.strip_prefix("__Host-") else {
        return validate_cookie_name(name);
    };
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
