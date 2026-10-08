//! Freshness checks: clock-skew and max-age caps, mint-time, idle, and absolute bounds.

use crate::error::TokenError;
use crate::keyring::KeyPurpose;

use super::*;

/// Reject freshness bounds longer than the purpose's own maximum lifetime
/// ([`KeyPurpose::MAX_ABSOLUTE_AGE_SECS`]) with the distinct
/// [`TokenError::InvalidTimestamp`]. A caller typo such as `u64::MAX` must not
/// make old cookies valid forever.
pub(super) fn check_max_age<P: KeyPurpose>(max_age: MaxAge) -> Result<(), TokenError> {
    if max_age.idle_secs > P::MAX_ABSOLUTE_AGE_SECS
        || max_age.absolute_secs > P::MAX_ABSOLUTE_AGE_SECS
    {
        return Err(TokenError::InvalidTimestamp);
    }
    Ok(())
}

/// Reject a skew above [`MAX_CLOCK_SKEW_SECS`] with the distinct
/// [`TokenError::InvalidTimestamp`], before any token work, so a
/// misconfiguration is visible instead of collapsing into `InvalidToken`.
pub(super) fn check_clock_skew(clock_skew_secs: u64) -> Result<(), TokenError> {
    if clock_skew_secs > MAX_CLOCK_SKEW_SECS {
        return Err(TokenError::InvalidTimestamp);
    }
    Ok(())
}

pub(super) fn check_mint_timestamp(
    timestamp: u32,
    now_unix: u64,
    clock_skew_secs: u64,
) -> Result<(), TokenError> {
    let timestamp = u64::from(timestamp);
    if timestamp > now_unix.saturating_add(clock_skew_secs) {
        return Err(TokenError::InvalidTimestamp);
    }
    if now_unix > timestamp.saturating_add(clock_skew_secs) {
        return Err(TokenError::InvalidTimestamp);
    }
    Ok(())
}

/// Idle-bound freshness on the Branca timestamp (last activity). Returns
/// [`TokenError::Expired`] internally. Callers funnel it to the generic error.
pub(super) fn check_timestamp_fresh(
    timestamp: u32,
    now_unix: u64,
    max_age_secs: u64,
    clock_skew_secs: u64,
) -> Result<(), TokenError> {
    let ts = u64::from(timestamp);
    if ts > now_unix.saturating_add(clock_skew_secs) {
        return Err(TokenError::Expired); // future-dated beyond tolerance
    }
    if now_unix.saturating_sub(ts) > max_age_secs {
        return Err(TokenError::Expired); // stale
    }
    Ok(())
}

/// Absolute-bound freshness on `iat` (first issue). `iat` must not postdate the
/// last-activity timestamp, nor be future-dated beyond tolerance.
pub(super) fn check_absolute_fresh(
    iat: u32,
    timestamp: u32,
    now_unix: u64,
    absolute_secs: u64,
    clock_skew_secs: u64,
) -> Result<(), TokenError> {
    let iat = u64::from(iat);
    if iat > u64::from(timestamp) {
        return Err(TokenError::Expired); // anchor postdates activity → malformed
    }
    if iat > now_unix.saturating_add(clock_skew_secs) {
        return Err(TokenError::Expired); // future-dated beyond tolerance
    }
    if now_unix.saturating_sub(iat) > absolute_secs {
        return Err(TokenError::Expired); // beyond absolute lifetime
    }
    Ok(())
}
