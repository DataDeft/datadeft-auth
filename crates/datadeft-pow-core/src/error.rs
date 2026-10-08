//! Typed verification error. Pure data: the caller decides what to log and
//! which HTTP status to map each variant to.

/// Everything that can go wrong in [`crate::verify_solution`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowError {
    /// Tag is not valid canonical hex or does not match the framed HMAC input.
    InvalidTag,
    /// `tim` is not a parseable RFC3339 timestamp.
    InvalidTimestamp,
    /// `tim` + `max_age_secs` is in the past.
    Expired,
    /// `tim` is more than [`crate::MAX_FUTURE_SKEW_SECS`] in the future.
    FutureTimestamp,
    /// Solution difficulty is below the server's current minimum.
    DifficultyTooLow,
    /// Configured or echoed difficulty is above the 64-hex-nibble maximum.
    DifficultyTooHigh,
    /// `max_age_secs` is outside `1..=`[`crate::MAX_CHALLENGE_MAX_AGE_SECS`].
    InvalidMaxAge,
    /// Configured clock skew exceeds [`crate::MAX_CLOCK_SKEW_SECS`].
    ClockSkewTooLarge,
    /// Wrong leading zeros, or `sol != SHA-256(chg + non)`.
    InvalidSolution,
}

impl core::fmt::Display for PowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::InvalidTag => "HMAC tag verification failed",
            Self::InvalidTimestamp => "challenge timestamp has an invalid format",
            Self::Expired => "challenge has expired",
            Self::FutureTimestamp => "challenge timestamp is in the future",
            Self::DifficultyTooLow => "solution difficulty is below the required minimum",
            Self::DifficultyTooHigh => "solution difficulty exceeds the supported maximum",
            Self::InvalidMaxAge => "maximum challenge age is out of range",
            Self::ClockSkewTooLarge => "configured clock skew is too large",
            Self::InvalidSolution => "proof-of-work solution is incorrect",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for PowError {}
