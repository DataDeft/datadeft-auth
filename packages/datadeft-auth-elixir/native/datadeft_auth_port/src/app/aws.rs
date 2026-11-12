//! Adapter-owned AWS setup: validate before IO and bound SDK calls so a
//! stalled dependency cannot retain a job permit indefinitely. These are
//! per-SDK-call bounds, not cancellation or rollback of a transaction.
use std::time::Duration;

use aws_config::timeout::TimeoutConfig;
use datadeft_magic_link_aws::{AwsAdapterError, DynamoDbAuthStoreConfig, SesAuthEmailConfig};

use crate::protocol::{AwsPayload, ErrorCode};

pub(super) fn validate_aws(aws: &AwsPayload) -> Result<(), ErrorCode> {
    if aws.region.is_empty()
        || aws.region.len() > 128
        || !aws
            .region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ErrorCode::Configuration);
    }
    DynamoDbAuthStoreConfig::new(&aws.table)
        .validate()
        .map_err(|_| ErrorCode::Configuration)?;
    SesAuthEmailConfig::new(&aws.from_email)
        .validate()
        .map_err(|_| ErrorCode::Configuration)
}

pub(super) fn secret_load_error(error: AwsAdapterError) -> ErrorCode {
    match error {
        // A malformed stored document will not heal by refetching it forever.
        AwsAdapterError::Internal => ErrorCode::Configuration,
        _ => ErrorCode::Unavailable,
    }
}

fn timeouts() -> TimeoutConfig {
    TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(3))
        .read_timeout(Duration::from_secs(5))
        .operation_attempt_timeout(Duration::from_secs(5))
        .operation_timeout(Duration::from_secs(10))
        .build()
}

pub(super) async fn sdk_config(aws: &AwsPayload) -> aws_config::SdkConfig {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(aws.region.clone()))
        .timeout_config(timeouts());
    if let Some(endpoint) = &aws.endpoint_url {
        loader = loader.endpoint_url(endpoint);
    }
    loader.load().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AwsPayload {
        serde_json::from_value(serde_json::json!({
            "region": "eu-central-1", "table": "test-auth",
            "from_email": "login@example.test"
        }))
        .expect("AWS payload")
    }

    #[test]
    fn aws_metadata_is_validated_before_clients_or_secrets_are_loaded() {
        assert!(validate_aws(&config()).is_ok());
        for value in ["".to_owned(), "bad\nvalue".to_owned(), "x".repeat(2049)] {
            let mut table = config();
            table.table = value.clone();
            assert!(matches!(
                validate_aws(&table),
                Err(ErrorCode::Configuration)
            ));
            let mut sender = config();
            sender.from_email = value;
            assert!(matches!(
                validate_aws(&sender),
                Err(ErrorCode::Configuration)
            ));
        }
        for value in ["", "bad region", "bad\nregion"] {
            let mut region = config();
            region.region = value.to_owned();
            assert!(matches!(
                validate_aws(&region),
                Err(ErrorCode::Configuration)
            ));
        }
    }

    #[test]
    fn malformed_secret_documents_are_configuration_errors_not_retry_loops() {
        assert!(matches!(
            secret_load_error(AwsAdapterError::Internal),
            ErrorCode::Configuration
        ));
        for error in [
            AwsAdapterError::DependencyUnavailable,
            AwsAdapterError::RateLimited,
            AwsAdapterError::ConditionalWriteFailed,
        ] {
            assert!(matches!(secret_load_error(error), ErrorCode::Unavailable));
        }
    }

    #[test]
    fn all_sdk_timeout_scopes_are_bounded() {
        let config = timeouts();
        assert_eq!(config.connect_timeout(), Some(Duration::from_secs(3)));
        assert_eq!(config.read_timeout(), Some(Duration::from_secs(5)));
        assert_eq!(
            config.operation_attempt_timeout(),
            Some(Duration::from_secs(5))
        );
        assert_eq!(config.operation_timeout(), Some(Duration::from_secs(10)));
    }
}
