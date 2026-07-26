//! `dd-magic-link-aws` — optional AWS infrastructure adapters.
//!
//! DynamoDB implementations for the service traits and SES outbox helpers live
//! here and only here. The default build provides in-memory fakes useful for
//! examples/tests without pulling AWS SDK dependencies. Enable the `aws` feature
//! for DynamoDB/SES SDK-backed adapters.

#![forbid(unsafe_code)]

mod error;
mod fake;
mod hmac_key;
mod ses;

#[cfg(feature = "aws")]
mod dynamodb;

pub use error::AwsAdapterError;
pub use fake::{FakeDynamoDbAuthStore, UserSessionIndexEntry};
pub use hmac_key::{SESSION_LOOKUP_HMAC_PREFIX, STORAGE_HMAC_KEY_BYTES, StorageHmacKey};
pub use ses::{FakeMagicLinkOutbox, MagicLinkEmailRenderer, RenderedMagicLinkEmail};

#[cfg(feature = "aws")]
pub use dynamodb::{DynamoDbAuthStore, DynamoDbAuthStoreConfig};
#[cfg(feature = "aws")]
pub use ses::SesMagicLinkOutbox;
