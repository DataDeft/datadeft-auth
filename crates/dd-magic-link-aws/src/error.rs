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
use aws_sdk_dynamodb::error::{ProvideErrorMetadata, SdkError};
#[cfg(feature = "aws")]
use aws_sdk_dynamodb::operation::{
    get_item::GetItemError, put_item::PutItemError, transact_write_items::TransactWriteItemsError,
    update_item::UpdateItemError,
};
#[cfg(feature = "aws")]
use aws_sdk_dynamodb::types::error::TransactionCanceledException;
#[cfg(feature = "aws")]
use aws_sdk_sesv2::operation::send_email::SendEmailError;

#[cfg(feature = "aws")]
pub(crate) fn map_get_item_error(error: SdkError<GetItemError>) -> AwsAdapterError {
    classify_metadata(&error)
        .unwrap_or_else(|| fallback_debug_classification(&format!("{error:?}")))
}

#[cfg(feature = "aws")]
pub(crate) fn map_put_item_error(error: SdkError<PutItemError>) -> AwsAdapterError {
    if error
        .as_service_error()
        .is_some_and(PutItemError::is_conditional_check_failed_exception)
    {
        return AwsAdapterError::ConditionalWriteFailed;
    }
    classify_metadata(&error)
        .unwrap_or_else(|| fallback_debug_classification(&format!("{error:?}")))
}

#[cfg(feature = "aws")]
pub(crate) fn map_update_item_error(error: SdkError<UpdateItemError>) -> AwsAdapterError {
    if error
        .as_service_error()
        .is_some_and(UpdateItemError::is_conditional_check_failed_exception)
    {
        return AwsAdapterError::ConditionalWriteFailed;
    }
    classify_metadata(&error)
        .unwrap_or_else(|| fallback_debug_classification(&format!("{error:?}")))
}

#[cfg(feature = "aws")]
pub(crate) fn map_transact_write_items_error(
    error: SdkError<TransactWriteItemsError>,
) -> AwsAdapterError {
    if let Some(TransactWriteItemsError::TransactionCanceledException(exception)) =
        error.as_service_error()
    {
        return classify_transaction_canceled(exception);
    }
    classify_metadata(&error)
        .unwrap_or_else(|| fallback_debug_classification(&format!("{error:?}")))
}

#[cfg(feature = "aws")]
pub(crate) fn map_ses_send_email_error(
    error: aws_sdk_sesv2::error::SdkError<SendEmailError>,
) -> AwsAdapterError {
    if matches!(
        error.code(),
        Some(
            "AccountSuspended"
                | "BadRequestException"
                | "LimitExceededException"
                | "MailFromDomainNotVerifiedException"
                | "MessageRejected"
                | "NotFoundException"
                | "SendingPausedException"
                | "TooManyRequestsException"
        )
    ) {
        return AwsAdapterError::DependencyUnavailable;
    }
    fallback_debug_classification(&format!("{error:?}"))
}

#[cfg(feature = "aws")]
fn classify_transaction_canceled(exception: &TransactionCanceledException) -> AwsAdapterError {
    let mut saw_conditional = false;
    let mut saw_other_failure = false;
    for reason in exception.cancellation_reasons() {
        match reason.code() {
            Some("ConditionalCheckFailed") => saw_conditional = true,
            Some("None") | None => {}
            Some(_) => saw_other_failure = true,
        }
    }
    if saw_conditional && !saw_other_failure {
        AwsAdapterError::ConditionalWriteFailed
    } else {
        AwsAdapterError::DependencyUnavailable
    }
}

#[cfg(feature = "aws")]
fn classify_metadata<E, R>(error: &SdkError<E, R>) -> Option<AwsAdapterError>
where
    SdkError<E, R>: ProvideErrorMetadata,
{
    match error.code() {
        Some("ConditionalCheckFailed") | Some("ConditionalCheckFailedException") => {
            Some(AwsAdapterError::ConditionalWriteFailed)
        }
        Some("TransactionCanceledException") => Some(AwsAdapterError::DependencyUnavailable),
        Some(_) | None => None,
    }
}

#[cfg(feature = "aws")]
fn fallback_debug_classification(debug: &str) -> AwsAdapterError {
    if debug.contains("ConditionalCheckFailed") {
        AwsAdapterError::ConditionalWriteFailed
    } else {
        AwsAdapterError::DependencyUnavailable
    }
}
