//! `datadeft-magic-link-aws`: optional AWS infrastructure adapters.
//!
//! DynamoDB implementations for the service traits and SES outbox helpers live
//! here and only here. The default build provides in-memory fakes useful for
//! examples/tests without pulling AWS SDK dependencies. Enable the `aws` feature
//! for DynamoDB/SES SDK-backed adapters.

#![forbid(unsafe_code)]

mod config;
mod error;
mod fake;
mod hmac_key;
mod ses;
mod window;

#[cfg(feature = "aws")]
mod dynamodb;

pub use config::{
    AuthSecretDocuments, AuthSecretsConfig, AwsAuthConfig, DynamoDbAuthStoreConfig,
    LoadedAuthSecrets, SecretKeyBytes, SecretRef, SecretVersionRef, SesAuthEmailConfig,
    SupportedSecretManager,
};
#[cfg(feature = "aws")]
pub use config::{fetch_auth_secret_documents, resolve_auth_secrets};
pub use error::AwsAdapterError;
pub use fake::{FakeDynamoDbAuthStore, UserSessionIndexEntry};
pub use hmac_key::{SESSION_LOOKUP_HMAC_PREFIX, STORAGE_HMAC_KEY_BYTES, StorageHmacKey};
pub use ses::{
    FakeMagicLinkOutbox, MAX_REPLY_TO_ADDRESSES, MagicLinkEmailRenderer, RenderedMagicLinkEmail,
};

#[cfg(feature = "aws")]
pub use dynamodb::DynamoDbAuthStore;
#[cfg(feature = "aws")]
pub use ses::SesMagicLinkOutbox;
