//! Adapter-local error helpers.

use core::fmt;

#[cfg(feature = "aws")]
use datadeft_magic_link_service::CommitMagicLinkAuthenticationError;
use datadeft_magic_link_service::DependencyError;

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

#[cfg(feature = "aws")]
use aws_sdk_dynamodb::error::{ProvideErrorMetadata, SdkError};
#[cfg(feature = "aws")]
use aws_sdk_dynamodb::operation::{
    get_item::GetItemError, put_item::PutItemError, query::QueryError, scan::ScanError,
    transact_write_items::TransactWriteItemsError, update_item::UpdateItemError,
};
#[cfg(feature = "aws")]
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
#[cfg(feature = "aws")]
use aws_sdk_sesv2::operation::send_email::SendEmailError;

#[cfg(feature = "aws")]
pub(crate) fn map_get_item_error(error: SdkError<GetItemError>) -> AwsAdapterError {
    classify_metadata(&error)
        .unwrap_or_else(|| fallback_debug_classification(&format!("{error:?}")))
}

#[cfg(feature = "aws")]
pub(crate) fn map_scan_error(error: SdkError<ScanError>) -> AwsAdapterError {
    classify_metadata(&error)
        .unwrap_or_else(|| fallback_debug_classification(&format!("{error:?}")))
}

#[cfg(feature = "aws")]
pub(crate) fn map_query_error(error: SdkError<QueryError>) -> AwsAdapterError {
    classify_metadata(&error)
        .unwrap_or_else(|| fallback_debug_classification(&format!("{error:?}")))
}

/// Map an admin mutation transaction failure. A failed condition means the
/// target is missing or already in the requested state; the service tells the
/// two apart. Other cancellations (conflicts, throttling) are retryable.
#[cfg(feature = "aws")]
pub(crate) fn map_admin_transact_write_items_error<R>(
    error: SdkError<TransactWriteItemsError, R>,
) -> AwsAdapterError
where
    SdkError<TransactWriteItemsError, R>: ProvideErrorMetadata,
{
    if let Some(TransactWriteItemsError::TransactionCanceledException(exception)) =
        error.as_service_error()
    {
        let condition_failed = exception
            .cancellation_reasons()
            .iter()
            .any(|reason| reason.code() == Some("ConditionalCheckFailed"));
        return if condition_failed {
            AwsAdapterError::ConditionalWriteFailed
        } else {
            AwsAdapterError::DependencyUnavailable
        };
    }
    match error.code() {
        Some("ValidationException") => AwsAdapterError::Internal,
        Some(_) | None => AwsAdapterError::DependencyUnavailable,
    }
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
pub(crate) fn map_authentication_transact_write_items_error<R>(
    error: SdkError<TransactWriteItemsError, R>,
    action_count: usize,
) -> CommitMagicLinkAuthenticationError {
    if let Some(TransactWriteItemsError::TransactionCanceledException(exception)) =
        error.as_service_error()
    {
        let codes = exception
            .cancellation_reasons()
            .iter()
            .map(|reason| reason.code())
            .collect::<Vec<_>>();
        return classify_authentication_cancellation_codes(&codes, action_count);
    }
    match error.code() {
        Some("IdempotentParameterMismatchException") | Some("ValidationException") => {
            CommitMagicLinkAuthenticationError::Internal
        }
        Some(_) | None => CommitMagicLinkAuthenticationError::DependencyUnavailable,
    }
}

/// Classify cancellation reasons against the transaction layout:
/// `[challenge, user actions.., session, session index]`. `action_count` is the
/// number of actions the request was built with; reasons for any other count
/// cannot be attributed and map to `Internal`.
#[cfg(feature = "aws")]
fn classify_authentication_cancellation_codes(
    codes: &[Option<&str>],
    action_count: usize,
) -> CommitMagicLinkAuthenticationError {
    // At least one user action: the existing-user branch has two condition
    // checks, a create has the profile and one or two email rows.
    if action_count < 4 || codes.len() != action_count {
        return CommitMagicLinkAuthenticationError::Internal;
    }
    let first_session_action = action_count - 2;
    let mut challenge_conflict = false;
    let mut user_conflict = false;
    let mut session_conflict = false;
    for (index, code) in codes.iter().enumerate() {
        match code {
            Some("ConditionalCheckFailed") if index == 0 => challenge_conflict = true,
            Some("ConditionalCheckFailed") if index < first_session_action => {
                user_conflict = true;
            }
            Some("ConditionalCheckFailed") => session_conflict = true,
            Some("None") | None => {}
            Some("TransactionConflict")
            | Some("ProvisionedThroughputExceeded")
            | Some("ThrottlingError") => {
                return CommitMagicLinkAuthenticationError::DependencyUnavailable;
            }
            Some(_) => return CommitMagicLinkAuthenticationError::DependencyUnavailable,
        }
    }
    if challenge_conflict {
        CommitMagicLinkAuthenticationError::Rejected
    } else if user_conflict {
        CommitMagicLinkAuthenticationError::UserConflict
    } else if session_conflict {
        CommitMagicLinkAuthenticationError::SessionConflict
    } else {
        CommitMagicLinkAuthenticationError::Internal
    }
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
pub(crate) fn map_secretsmanager_get_secret_value_error(
    error: aws_sdk_secretsmanager::error::SdkError<GetSecretValueError>,
) -> AwsAdapterError {
    match error.code() {
        Some(
            "AccessDeniedException"
            | "DecryptionFailure"
            | "InternalServiceError"
            | "InvalidParameterException"
            | "InvalidRequestException"
            | "ResourceNotFoundException"
            | "ThrottlingException",
        ) => AwsAdapterError::DependencyUnavailable,
        Some(_) | None => fallback_debug_classification(&format!("{error:?}")),
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

#[cfg(all(test, feature = "aws"))]
#[path = "error_tests.rs"]
mod tests;
