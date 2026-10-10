use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use datadeft_auth_token_core::keyring::KeyStatus;
use datadeft_magic_link_service::{KeyId, KeyPurpose};

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
  "magic_link_confirm_cookie_root_b64": "{}",
  "pow_challenge_secret_b64": "{}",
  "pow_proof_cookie_root_b64": "{}"
}}"#,
        key(base),
        key(base + 1),
        key(base + 2),
        key(base + 3),
        key(base + 4),
        key(base + 5),
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

#[test]
fn loaded_auth_secrets_keeps_previous_hmac_keys_only_when_rotated() {
    let active = secret_json("active", 0x10, 1_000, 4_000_000);

    let rotated = secret_json("previous", 0x20, 1, 4_000_000);
    let loaded = LoadedAuthSecrets::from_json(&active, Some(&rotated)).expect("rotated");
    assert!(loaded.previous_lookup_hmac_key.is_some());
    assert!(loaded.previous_storage_hmac_key.is_some());

    // Cookie-only rotation: identical HMAC keys need no fallback reads.
    let cookie_only = format!(
        r#"{{
  "kid": "previous",
  "mint_until_unix": 1,
  "verify_until_unix": 4000000,
  "magic_link_lookup_hmac_b64": "{}",
  "aws_storage_hmac_b64": "{}",
  "session_cookie_root_b64": "{}",
  "magic_link_confirm_cookie_root_b64": "{}",
  "pow_challenge_secret_b64": "{}",
  "pow_proof_cookie_root_b64": "{}"
}}"#,
        key(0x10),
        key(0x11),
        key(0x22),
        key(0x23),
        key(0x14),
        key(0x25),
    );
    let loaded = LoadedAuthSecrets::from_json(&active, Some(&cookie_only)).expect("cookie only");
    assert!(loaded.previous_lookup_hmac_key.is_none());
    assert!(loaded.previous_storage_hmac_key.is_none());
    assert!(loaded.previous_pow_challenge_secret.is_none());

    let loaded = LoadedAuthSecrets::from_json(&active, None).expect("no previous");
    assert!(loaded.previous_lookup_hmac_key.is_none());
    assert!(loaded.previous_storage_hmac_key.is_none());
}

/// Mirrors the PoW proof cookie's size budget (datadeft-pow-core's
/// `PowProofCookie`): its largest body leaves room for a 12-byte `kid`. The
/// real type is tested in datadeft-pow-core; this crate does not depend on it.
#[derive(Debug)]
enum ProofLikePurpose {}

impl KeyPurpose for ProofLikePurpose {
    const HKDF_INFO: &'static [u8] = b"test/proof-like-v1";
    const TOKEN_TYPE: &'static str = "pow-proof-v1";
    const MAX_BODY_BYTES: usize = 65;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 24 * 60 * 60;
    const MIN_BODY_BYTES: usize = 34;
}

#[test]
fn pow_fields_load_with_rotation_support() {
    let active = secret_json("active", 0x10, 1_000, 4_000_000);
    let previous = secret_json("previous", 0x20, 1, 4_000_000);
    let loaded = LoadedAuthSecrets::from_json(&active, Some(&previous)).expect("loaded");

    assert_eq!(loaded.pow_challenge_secret.as_bytes(), &[0x14; 32]);
    assert_eq!(
        loaded
            .previous_pow_challenge_secret
            .as_ref()
            .map(|key| *key.as_bytes()),
        Some([0x24; 32]),
        "a rotated challenge secret stays available to verify older challenges"
    );
    let ring = loaded
        .pow_proof_keyring::<ProofLikePurpose>()
        .expect("proof keyring");
    assert_eq!(
        ring.minting_key_at(1_000).expect("active").kid().as_str(),
        "active"
    );
    let previous_kid = KeyId::parse("previous").expect("kid");
    let previous_slot = ring
        .verification_key_at(&previous_kid, 1_000)
        .expect("previous root verifies");
    assert_eq!(previous_slot.status(), KeyStatus::VerifyOnly);

    let only_active = LoadedAuthSecrets::from_json(&active, None).expect("loaded");
    assert!(only_active.previous_pow_challenge_secret.is_none());
}

#[test]
fn pow_fields_are_required_and_validated() {
    let complete = secret_json("active", 0x10, 1_000, 4_000_000);
    for field in ["pow_challenge_secret_b64", "pow_proof_cookie_root_b64"] {
        // Drop the field's line, then the trailing comma it may leave behind.
        let missing = complete
            .lines()
            .filter(|line| !line.contains(field))
            .collect::<Vec<_>>()
            .join("\n")
            .replace(",\n}", "\n}");
        assert_eq!(
            LoadedAuthSecrets::from_json(&missing, None).unwrap_err(),
            AwsAdapterError::Internal,
            "{field} missing"
        );
        let short = complete.replace(
            &key(if field.starts_with("pow_challenge") {
                0x14
            } else {
                0x15
            }),
            &STANDARD.encode([1u8; 16]),
        );
        assert_eq!(
            LoadedAuthSecrets::from_json(&short, None).unwrap_err(),
            AwsAdapterError::Internal,
            "{field} with 16 bytes"
        );
    }
}

#[test]
fn pow_proof_keyring_refuses_a_kid_too_long_for_the_proof_cookie() {
    let twelve = secret_json("abcdefghijkl", 0x10, 1_000, 4_000_000);
    let loaded = LoadedAuthSecrets::from_json(&twelve, None).expect("loaded");
    assert!(loaded.pow_proof_keyring::<ProofLikePurpose>().is_ok());

    let thirteen = secret_json("abcdefghijklm", 0x10, 1_000, 4_000_000);
    let loaded = LoadedAuthSecrets::from_json(&thirteen, None).expect("loaded");
    assert_eq!(
        loaded.pow_proof_keyring::<ProofLikePurpose>().unwrap_err(),
        AwsAdapterError::Internal
    );
}

#[test]
fn secret_key_bytes_debug_is_redacted() {
    let loaded = LoadedAuthSecrets::from_json(&secret_json("active", 0x10, 1_000, 4_000_000), None)
        .expect("loaded");
    let debug = format!("{:?}", loaded.pow_challenge_secret);
    assert_eq!(debug, "SecretKeyBytes(..)");
}
