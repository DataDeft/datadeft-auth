//! Structured authentication transaction error tests.

use std::io;

use aws_sdk_dynamodb::error::{ErrorMetadata, SdkError};
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::types::CancellationReason;
use aws_sdk_dynamodb::types::error::TransactionCanceledException;
use dd_magic_link_service::CommitMagicLinkAuthenticationError;

use super::{
    classify_authentication_cancellation_codes, map_authentication_transact_write_items_error,
};

fn cancellation_reason(code: &str) -> CancellationReason {
    CancellationReason::builder().code(code).build()
}

fn transaction_canceled(codes: &[&str]) -> SdkError<TransactWriteItemsError, ()> {
    let reasons = codes.iter().map(|code| cancellation_reason(code)).collect();
    let exception = TransactionCanceledException::builder()
        .set_cancellation_reasons(Some(reasons))
        .build();
    SdkError::service_error(
        TransactWriteItemsError::TransactionCanceledException(exception),
        (),
    )
}

fn service_error_with_code(code: &str) -> SdkError<TransactWriteItemsError, ()> {
    let metadata = ErrorMetadata::builder().code(code).build();
    SdkError::service_error(TransactWriteItemsError::generic(metadata), ())
}

#[test]
fn authentication_mapper_extracts_cancellation_reasons_and_maps_action_positions() {
    for (index, expected) in [
        (0, CommitMagicLinkAuthenticationError::Rejected),
        (1, CommitMagicLinkAuthenticationError::UserConflict),
        (2, CommitMagicLinkAuthenticationError::UserConflict),
        (3, CommitMagicLinkAuthenticationError::SessionConflict),
        (4, CommitMagicLinkAuthenticationError::SessionConflict),
    ] {
        let mut codes = ["None"; 5];
        codes[index] = "ConditionalCheckFailed";
        assert_eq!(
            map_authentication_transact_write_items_error(transaction_canceled(&codes)),
            expected
        );
    }

    assert_eq!(
        map_authentication_transact_write_items_error(transaction_canceled(&[
            "ConditionalCheckFailed",
            "ConditionalCheckFailed",
            "None",
            "None",
            "ConditionalCheckFailed",
        ])),
        CommitMagicLinkAuthenticationError::Rejected
    );
}

#[test]
fn authentication_mapper_treats_malformed_service_requests_as_internal() {
    for code in [
        "IdempotentParameterMismatchException",
        "ValidationException",
    ] {
        assert_eq!(
            map_authentication_transact_write_items_error(service_error_with_code(code)),
            CommitMagicLinkAuthenticationError::Internal
        );
    }
}

#[test]
fn authentication_mapper_treats_unknown_and_transport_failures_as_dependency_unavailable() {
    assert_eq!(
        map_authentication_transact_write_items_error(service_error_with_code(
            "UnknownProviderFailure"
        )),
        CommitMagicLinkAuthenticationError::DependencyUnavailable
    );
    assert_eq!(
        map_authentication_transact_write_items_error(
            SdkError::<TransactWriteItemsError, ()>::timeout_error(io::Error::new(
                io::ErrorKind::TimedOut,
                "synthetic transport timeout",
            ))
        ),
        CommitMagicLinkAuthenticationError::DependencyUnavailable
    );
}

#[test]
fn authentication_cancellation_mapping_uses_stable_action_positions_and_precedence() {
    let none = Some("None");
    for (index, expected) in [
        (0, CommitMagicLinkAuthenticationError::Rejected),
        (1, CommitMagicLinkAuthenticationError::UserConflict),
        (2, CommitMagicLinkAuthenticationError::UserConflict),
        (3, CommitMagicLinkAuthenticationError::SessionConflict),
        (4, CommitMagicLinkAuthenticationError::SessionConflict),
    ] {
        let mut codes = [none; 5];
        codes[index] = Some("ConditionalCheckFailed");
        assert_eq!(classify_authentication_cancellation_codes(&codes), expected);
    }

    assert_eq!(
        classify_authentication_cancellation_codes(&[
            Some("ConditionalCheckFailed"),
            Some("ConditionalCheckFailed"),
            none,
            none,
            Some("ConditionalCheckFailed"),
        ]),
        CommitMagicLinkAuthenticationError::Rejected
    );
}

#[test]
fn authentication_cancellation_mapping_rejects_impossible_and_ambiguous_layouts() {
    assert_eq!(
        classify_authentication_cancellation_codes(&[Some("None"); 4]),
        CommitMagicLinkAuthenticationError::Internal
    );
    assert_eq!(
        classify_authentication_cancellation_codes(&[Some("None"); 5]),
        CommitMagicLinkAuthenticationError::Internal
    );
    for code in [
        "TransactionConflict",
        "ProvisionedThroughputExceeded",
        "ThrottlingError",
        "UnknownProviderFailure",
    ] {
        assert_eq!(
            classify_authentication_cancellation_codes(&[
                Some("None"),
                Some(code),
                Some("None"),
                Some("None"),
                Some("None"),
            ]),
            CommitMagicLinkAuthenticationError::DependencyUnavailable
        );
    }
}
