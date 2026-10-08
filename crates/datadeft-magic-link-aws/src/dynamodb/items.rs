//! DynamoDB attribute-value builders and strict item field readers.

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;

use crate::error::AwsAdapterError;

pub(super) fn av_s(value: impl Into<String>) -> AttributeValue {
    AttributeValue::S(value.into())
}

pub(super) fn av_n(value: impl ToString) -> AttributeValue {
    AttributeValue::N(value.to_string())
}

pub(super) fn av_bool(value: bool) -> AttributeValue {
    AttributeValue::Bool(value)
}

pub(super) fn required_s<'a>(
    item: &'a HashMap<String, AttributeValue>,
    key: &str,
) -> Result<&'a str, AwsAdapterError> {
    optional_s(item, key).ok_or(AwsAdapterError::Internal)
}

pub(super) fn optional_s<'a>(
    item: &'a HashMap<String, AttributeValue>,
    key: &str,
) -> Option<&'a str> {
    item.get(key)
        .and_then(|value| value.as_s().ok().map(String::as_str))
}

pub(super) fn required_u64(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<u64, AwsAdapterError> {
    optional_u64(item, key)?.ok_or(AwsAdapterError::Internal)
}

pub(super) fn optional_u64(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<Option<u64>, AwsAdapterError> {
    item.get(key)
        .map(|value| {
            value
                .as_n()
                .map_err(|_| AwsAdapterError::Internal)?
                .parse::<u64>()
                .map_err(|_| AwsAdapterError::Internal)
        })
        .transpose()
}

pub(super) fn optional_s_strict<'a>(
    item: &'a HashMap<String, AttributeValue>,
    key: &str,
) -> Result<Option<&'a str>, AwsAdapterError> {
    item.get(key)
        .map(|value| {
            value
                .as_s()
                .map(String::as_str)
                .map_err(|_| AwsAdapterError::Internal)
        })
        .transpose()
}

pub(super) fn required_bool(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<bool, AwsAdapterError> {
    item.get(key)
        .ok_or(AwsAdapterError::Internal)?
        .as_bool()
        .copied()
        .map_err(|_| AwsAdapterError::Internal)
}
