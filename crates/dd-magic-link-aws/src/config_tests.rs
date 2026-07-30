use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use dd_magic_link_service::KeyId;

use crate::{
    AuthSecretsConfig, AwsAdapterError, AwsAuthConfig, DynamoDbAuthStoreConfig, LoadedAuthSecrets,
    SecretRef, SecretVersionRef, SesAuthEmailConfig,
};

fn key(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

fn secret_json(kid: &str, base: u8, mint_until_unix: u64, verify_until_unix: u64) -> String {
    format!(
        r#"{{
  "kid": "{kid}",
  "mint_until_unix": {mint_until_unix},
  "verify_until_unix": {verify_until_unix},
  "magic_link_lookup_hmac_b64": "{}",
  "aws_storage_hmac_b64": "{}",
  "session_cookie_root_b64": "{}",
  "magic_link_confirm_cookie_root_b64": "{}"
}}"#,
        key(base),
        key(base + 1),
        key(base + 2),
        key(base + 3),
    )
}

#[test]
fn config_is_plain_values_and_redacts_debug() {
    let config = AwsAuthConfig::new(
        DynamoDbAuthStoreConfig::new("local-auth-table"),
        AuthSecretsConfig::new(
            SecretRef::aws_secrets_manager(
                "local/auth/active",
                SecretVersionRef::stage("AWSCURRENT"),
            ),
            Some(SecretRef::aws_secrets_manager(
                "local/auth/previous",
                SecretVersionRef::stage("AWSPREVIOUS"),
            )),
        ),
        SesAuthEmailConfig::new("sender@example.invalid"),
    );

    config.validate().expect("valid config");
    let debug = format!("{config:?}");
    for sensitive in [
        "local-auth-table",
        "local/auth/active",
        "local/auth/previous",
        "sender@example.invalid",
        "AWSCURRENT",
        "AWSPREVIOUS",
    ] {
        assert!(!debug.contains(sensitive));
    }
}

#[test]
fn loaded_auth_secrets_builds_active_and_previous_cookie_keyrings() {
    let active = secret_json("active", 0x10, 1_000, 4_000_000);
    let previous = secret_json("previous", 0x20, 1, 4_000_000);
    let loaded = LoadedAuthSecrets::from_json(&active, Some(&previous)).expect("loaded secrets");

    let active_session = loaded
        .session_keyring
        .minting_key_at(1_000)
        .expect("active session key");
    assert_eq!(active_session.kid().as_str(), "active");
    let active_flow = loaded
        .confirm_keyring
        .minting_key_at(1_000)
        .expect("active flow key");
    assert_eq!(active_flow.kid().as_str(), "active");

    let previous_kid = KeyId::parse("previous").expect("previous kid");
    assert!(
        loaded
            .session_keyring
            .verification_key_at(&previous_kid, 1_000)
            .is_ok()
    );
    assert!(
        loaded
            .confirm_keyring
            .verification_key_at(&previous_kid, 1_000)
            .is_ok()
    );
}

#[test]
fn loaded_auth_secrets_rejects_malformed_payloads() {
    let mut malformed_key = secret_json("active", 0x10, 1_000, 4_000_000);
    malformed_key = malformed_key.replace(&key(0x10), "not-base64");
    assert_eq!(
        LoadedAuthSecrets::from_json(&malformed_key, None).unwrap_err(),
        AwsAdapterError::Internal
    );

    let expired_active = secret_json("active", 0x10, 1_000, 2_000);
    assert_eq!(
        LoadedAuthSecrets::from_json(&expired_active, None).unwrap_err(),
        AwsAdapterError::Internal
    );
}

#[test]
fn config_rejects_empty_or_control_metadata() {
    let bad = AwsAuthConfig::new(
        DynamoDbAuthStoreConfig::new(""),
        AuthSecretsConfig::new(
            SecretRef::aws_secrets_manager(
                "local/auth/active",
                SecretVersionRef::stage("AWSCURRENT"),
            ),
            None,
        ),
        SesAuthEmailConfig::new("sender@example.invalid"),
    );
    assert_eq!(bad.validate(), Err(AwsAdapterError::Internal));

    let bad_secret = AuthSecretsConfig::new(
        SecretRef::aws_secrets_manager(
            "local/auth/active\n",
            SecretVersionRef::stage("AWSCURRENT"),
        ),
        None,
    );
    assert_eq!(bad_secret.validate(), Err(AwsAdapterError::Internal));
}
