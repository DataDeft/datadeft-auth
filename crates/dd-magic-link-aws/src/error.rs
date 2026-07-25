//! Adapter-local error helpers.

use core::fmt;

use dd_magic_link_service::{ConsumeMagicLinkError, DependencyError};

/// Scrubbed adapter error for fake controls and AWS error classification.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AwsAdapterError {
    /// Conditional write/check failed.
    ConditionalWriteFailed,
    /// Limiter policy denied the operation.
    RateLimited,
    /// AWS or another dependency was temporarily unavailable.
    DependencyUnavailable,
    /// Adapter configuration or stored item shape was invalid.
    Internal,
}

impl fmt::Display for AwsAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AwsAdapterError::ConditionalWriteFailed => f.write_str("conditional write failed"),
            AwsAdapterError::RateLimited => f.write_str("rate limited"),
            AwsAdapterError::DependencyUnavailable => f.write_str("dependency unavailable"),
            AwsAdapterError::Internal => f.write_str("internal adapter error"),
        }
    }
}

impl std::error::Error for AwsAdapterError {}

impl From<AwsAdapterError> for DependencyError {
    fn from(value: AwsAdapterError) -> Self {
        match value {
            AwsAdapterError::ConditionalWriteFailed => DependencyError::ConditionalWriteFailed,
            AwsAdapterError::RateLimited => DependencyError::RateLimited,
            AwsAdapterError::DependencyUnavailable => DependencyError::Unavailable,
            AwsAdapterError::Internal => DependencyError::Internal,
        }
    }
}

impl From<AwsAdapterError> for ConsumeMagicLinkError {
    fn from(value: AwsAdapterError) -> Self {
        match value {
            AwsAdapterError::ConditionalWriteFailed | AwsAdapterError::RateLimited => {
                ConsumeMagicLinkError::Unavailable
            }
            AwsAdapterError::DependencyUnavailable => ConsumeMagicLinkError::DependencyUnavailable,
            AwsAdapterError::Internal => ConsumeMagicLinkError::Internal,
        }
    }
}

#[cfg(feature = "aws")]
pub(crate) fn map_sdk_error(debug: &str) -> AwsAdapterError {
    if debug.contains("ConditionalCheckFailed") {
        AwsAdapterError::ConditionalWriteFailed
    } else {
        AwsAdapterError::DependencyUnavailable
    }
}
