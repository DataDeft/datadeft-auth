//! Typed setup configuration and AWS Secrets Manager loading helpers.
//!
//! This module deliberately never reads process environment variables. Consuming
//! applications load their own configuration format and pass these plain Rust
//! structs into setup code.

use core::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use datadeft_magic_link_service::{
    KeyId, KeyPurpose, KeyRing, KeySlot, LookupHmacKey, MagicLinkConfirmCookie, RootSecret,
    SessionCookie,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::AwsAdapterError;
use crate::hmac_key::StorageHmacKey;

const MAX_TABLE_NAME_BYTES: usize = 1024;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_SECRET_REF_BYTES: usize = 2048;
const MAX_SECRET_VERSION_BYTES: usize = 256;
const KEY_B64_BYTES: usize = 512;
const KEY_BYTES: usize = 32;

/// V1 supported secret manager identifiers.
#[derive(Clone, Eq, PartialEq)]
pub enum SupportedSecretManager {
    /// AWS Secrets Manager.
    AwsSecretsManager,
}

impl fmt::Debug for SupportedSecretManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwsSecretsManager => f.write_str("AwsSecretsManager"),
        }
    }
}

/// Secret version selector. Values are operational metadata, and the parent
/// config `Debug` output redacts them.
#[derive(Clone, Eq, PartialEq)]
pub enum SecretVersionRef {
    /// Resolve by provider version stage, for example `AWSCURRENT` or
    /// `AWSPREVIOUS`.
    Stage(String),
    /// Resolve by provider version id.
    VersionId(String),
}

impl SecretVersionRef {
    /// Build a stage selector.
    #[must_use]
    pub fn stage(value: impl Into<String>) -> Self {
        Self::Stage(value.into())
    }

    /// Build a version-id selector.
    #[must_use]
    pub fn version_id(value: impl Into<String>) -> Self {
        Self::VersionId(value.into())
    }

    fn validate(&self) -> Result<(), AwsAdapterError> {
        match self {
            Self::Stage(value) | Self::VersionId(value) => {
                validate_metadata_value(value, MAX_SECRET_VERSION_BYTES)
            }
        }
    }
}

impl fmt::Debug for SecretVersionRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretVersionRef(..)")
    }
}

/// Reference to externally managed auth secret material.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretRef {
    pub manager: SupportedSecretManager,
    /// AWS Secrets Manager secret name or ARN. Redacted in `Debug`.
    pub name_or_arn: String,
    pub version: SecretVersionRef,
}

impl SecretRef {
    /// Build an AWS Secrets Manager reference.
    #[must_use]
    pub fn aws_secrets_manager(name_or_arn: impl Into<String>, version: SecretVersionRef) -> Self {
        Self {
            manager: SupportedSecretManager::AwsSecretsManager,
            name_or_arn: name_or_arn.into(),
            version,
        }
    }

    fn validate(&self) -> Result<(), AwsAdapterError> {
        validate_metadata_value(&self.name_or_arn, MAX_SECRET_REF_BYTES)?;
        self.version.validate()
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretRef(..)")
    }
}

/// Secret references used to load active and optional previous auth key material.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthSecretsConfig {
    pub active: SecretRef,
    pub previous: Option<SecretRef>,
}

impl AuthSecretsConfig {
    /// Build auth secret references. `previous` is verify-only/decrypt-only when
    /// present.
    #[must_use]
    pub fn new(active: SecretRef, previous: Option<SecretRef>) -> Self {
        Self { active, previous }
    }

    pub fn validate(&self) -> Result<(), AwsAdapterError> {
        self.active.validate()?;
        if let Some(previous) = &self.previous {
            previous.validate()?;
        }
        Ok(())
    }
}

impl fmt::Debug for AuthSecretsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthSecretsConfig(..)")
    }
}

/// DynamoDB auth-store setup config.
#[derive(Clone, Eq, PartialEq)]
pub struct DynamoDbAuthStoreConfig {
    pub table_name: String,
}

impl DynamoDbAuthStoreConfig {
    #[must_use]
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
        }
    }

    pub fn validate(&self) -> Result<(), AwsAdapterError> {
        validate_metadata_value(&self.table_name, MAX_TABLE_NAME_BYTES)
    }

    #[cfg(feature = "aws")]
    pub fn build_store(
        &self,
        client: aws_sdk_dynamodb::Client,
        storage_hmac_key: StorageHmacKey,
    ) -> Result<crate::DynamoDbAuthStore, AwsAdapterError> {
        self.validate()?;
        Ok(crate::DynamoDbAuthStore::new(
            client,
            self.table_name.clone(),
            storage_hmac_key,
        ))
    }
}

impl fmt::Debug for DynamoDbAuthStoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DynamoDbAuthStoreConfig(..)")
    }
}

/// SES magic-link sender setup config.
#[derive(Clone, Eq, PartialEq)]
pub struct SesAuthEmailConfig {
    /// Sender/from address configured by the consuming application.
    pub from_email: String,
}

impl SesAuthEmailConfig {
    #[must_use]
    pub fn new(from_email: impl Into<String>) -> Self {
        Self {
            from_email: from_email.into(),
        }
    }

    pub fn validate(&self) -> Result<(), AwsAdapterError> {
        validate_metadata_value(&self.from_email, MAX_EMAIL_BYTES)
    }

    #[must_use]
    pub fn from_email(&self) -> &str {
        &self.from_email
    }
}

impl fmt::Debug for SesAuthEmailConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SesAuthEmailConfig(..)")
    }
}

/// AWS-backed auth integration setup config. This is a plain config value: the
/// library does not read environment variables.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsAuthConfig {
    pub dynamodb: DynamoDbAuthStoreConfig,
    pub secrets: AuthSecretsConfig,
    pub email: SesAuthEmailConfig,
}

impl AwsAuthConfig {
    #[must_use]
    pub fn new(
        dynamodb: DynamoDbAuthStoreConfig,
        secrets: AuthSecretsConfig,
        email: SesAuthEmailConfig,
    ) -> Self {
        Self {
            dynamodb,
            secrets,
            email,
        }
    }

    pub fn validate(&self) -> Result<(), AwsAdapterError> {
        self.dynamodb.validate()?;
        self.secrets.validate()?;
        self.email.validate()
    }
}

impl fmt::Debug for AwsAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AwsAuthConfig(..)")
    }
}

/// 32 bytes of key material from the secret document, for a consumer that
/// builds its own key type, such as the PoW challenge secret:
/// `PowSecret::new(*secrets.pow_challenge_secret.as_bytes())`. `Debug` is
/// redacted; the bytes zeroize on drop.
pub struct SecretKeyBytes(Zeroizing<[u8; KEY_BYTES]>);

impl SecretKeyBytes {
    /// The raw key bytes, to hand to the consumer's own key type.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKeyBytes(..)")
    }
}

/// One document's root for a cookie keyring, with its `kid` and windows.
struct RootMaterial {
    kid: KeyId,
    root: Zeroizing<[u8; KEY_BYTES]>,
    mint_until_unix: u64,
    verify_until_unix: u64,
}

/// Active and previous roots for a cookie keyring. The keyring is built for
/// a purpose chosen later, so this crate needs no knowledge of that purpose.
struct KeyringRoots {
    active: RootMaterial,
    previous: Option<RootMaterial>,
}

impl KeyringRoots {
    fn from_documents(
        active: &AuthSecretDocument,
        previous: Option<&AuthSecretDocument>,
        root_b64: fn(&AuthSecretDocument) -> &str,
    ) -> Result<Self, AwsAdapterError> {
        let material = |document: &AuthSecretDocument| -> Result<RootMaterial, AwsAdapterError> {
            Ok(RootMaterial {
                kid: KeyId::parse(&document.kid).map_err(|_| AwsAdapterError::Internal)?,
                root: Zeroizing::new(decode_key(root_b64(document))?),
                mint_until_unix: document.mint_until_unix,
                verify_until_unix: document.verify_until_unix,
            })
        };
        Ok(Self {
            active: material(active)?,
            previous: previous.map(material).transpose()?,
        })
    }

    /// The active root mints; the previous one only verifies. Fails when a
    /// `kid` is too long for the purpose's largest body
    /// (`KeyPurpose::LARGEST_BODY_BYTES`).
    fn keyring<P: KeyPurpose>(&self) -> Result<KeyRing<P>, AwsAdapterError> {
        let derive = |material: &RootMaterial| {
            RootSecret::new(*material.root)
                .derive_key::<P>(&material.kid)
                .map_err(|_| AwsAdapterError::Internal)
        };
        let mut slots = vec![KeySlot::active_with_windows(
            self.active.kid.clone(),
            derive(&self.active)?,
            self.active.mint_until_unix,
            self.active.verify_until_unix,
        )];
        if let Some(previous) = &self.previous {
            slots.push(KeySlot::verify_only(
                previous.kid.clone(),
                derive(previous)?,
                previous.verify_until_unix,
            ));
        }
        KeyRing::new(slots).map_err(|_| AwsAdapterError::Internal)
    }
}

/// Loaded auth secret material ready to inject into service/adapters.
pub struct LoadedAuthSecrets {
    pub lookup_hmac_key: LookupHmacKey,
    pub storage_hmac_key: StorageHmacKey,
    /// The previous document's lookup key when it differs from the active
    /// one. Pass it to `MagicLinkFlowService::previous_lookup_hmac_key`.
    pub previous_lookup_hmac_key: Option<LookupHmacKey>,
    /// The previous document's storage key when it differs from the active
    /// one. Pass it to `DynamoDbAuthStore::with_previous_storage_hmac_key`.
    pub previous_storage_hmac_key: Option<StorageHmacKey>,
    pub confirm_keyring: KeyRing<MagicLinkConfirmCookie>,
    pub session_keyring: KeyRing<SessionCookie>,
    /// PoW challenge HMAC secret (`pow_challenge_secret_b64`).
    pub pow_challenge_secret: SecretKeyBytes,
    /// The previous document's PoW challenge secret when it differs from the
    /// active one, to verify challenges minted just before a rotation.
    pub previous_pow_challenge_secret: Option<SecretKeyBytes>,
    pow_proof_roots: KeyringRoots,
}

impl LoadedAuthSecrets {
    /// Parse active and optional previous secret JSON payloads. Previous cookie
    /// roots become verify-only keyring slots. Previous HMAC keys are kept only
    /// for read fallback during rotation; new values always use the active
    /// keys.
    pub fn from_json(active: &str, previous: Option<&str>) -> Result<Self, AwsAdapterError> {
        let active = AuthSecretDocument::parse(active)?;
        let previous = previous.map(AuthSecretDocument::parse).transpose()?;
        Self::from_documents(&active, previous.as_ref())
    }

    /// The PoW proof-cookie keyring (`pow_proof_cookie_root_b64`), with the
    /// previous document's root as a verify-only slot. The caller names the
    /// purpose, `secrets.pow_proof_keyring::<PowProofCookie>()`, so this crate
    /// does not depend on the PoW crates. Build it at startup: it fails there
    /// when the document's `kid` is too long for the proof cookie. Naming a
    /// purpose this crate already keys from its own root (session or confirm
    /// cookie) fails, so the PoW root never mints those cookies.
    pub fn pow_proof_keyring<P: KeyPurpose>(&self) -> Result<KeyRing<P>, AwsAdapterError> {
        if P::HKDF_INFO == SessionCookie::HKDF_INFO
            || P::HKDF_INFO == MagicLinkConfirmCookie::HKDF_INFO
        {
            return Err(AwsAdapterError::Internal);
        }
        self.pow_proof_roots.keyring()
    }

    fn from_documents(
        active: &AuthSecretDocument,
        previous: Option<&AuthSecretDocument>,
    ) -> Result<Self, AwsAdapterError> {
        let lookup_bytes = Zeroizing::new(decode_key(&active.magic_link_lookup_hmac_b64)?);
        let storage_bytes = Zeroizing::new(decode_key(&active.aws_storage_hmac_b64)?);
        let previous_lookup = previous_if_rotated(&lookup_bytes, previous, |document| {
            &document.magic_link_lookup_hmac_b64
        })?;
        let previous_storage = previous_if_rotated(&storage_bytes, previous, |document| {
            &document.aws_storage_hmac_b64
        })?;
        let confirm_keyring = KeyringRoots::from_documents(active, previous, |document| {
            &document.magic_link_confirm_cookie_root_b64
        })?
        .keyring::<MagicLinkConfirmCookie>()?;
        let session_keyring = KeyringRoots::from_documents(active, previous, |document| {
            &document.session_cookie_root_b64
        })?
        .keyring::<SessionCookie>()?;
        let pow_challenge = Zeroizing::new(decode_key(&active.pow_challenge_secret_b64)?);
        let previous_pow_challenge = previous_if_rotated(&pow_challenge, previous, |document| {
            &document.pow_challenge_secret_b64
        })?;
        let pow_proof_roots = KeyringRoots::from_documents(active, previous, |document| {
            &document.pow_proof_cookie_root_b64
        })?;
        Ok(Self {
            lookup_hmac_key: LookupHmacKey::new(*lookup_bytes),
            storage_hmac_key: StorageHmacKey::new(*storage_bytes),
            previous_lookup_hmac_key: previous_lookup.map(|bytes| LookupHmacKey::new(*bytes)),
            previous_storage_hmac_key: previous_storage.map(|bytes| StorageHmacKey::new(*bytes)),
            confirm_keyring,
            session_keyring,
            pow_challenge_secret: SecretKeyBytes(pow_challenge),
            previous_pow_challenge_secret: previous_pow_challenge.map(SecretKeyBytes),
            pow_proof_roots,
        })
    }
}

impl fmt::Debug for LoadedAuthSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoadedAuthSecrets(..)")
    }
}

/// Resolve configured AWS Secrets Manager references into loaded auth secret
/// material. Callers provide the AWS client. This function does not read global
/// config or environment variables.
#[cfg(feature = "aws")]
pub async fn resolve_auth_secrets(
    client: &aws_sdk_secretsmanager::Client,
    config: &AuthSecretsConfig,
) -> Result<LoadedAuthSecrets, AwsAdapterError> {
    config.validate()?;
    let active = load_secret_string(client, &config.active).await?;
    let previous = match &config.previous {
        Some(previous) => Some(load_secret_string(client, previous).await?),
        None => None,
    };
    LoadedAuthSecrets::from_json(&active, previous.as_deref())
}

#[cfg(feature = "aws")]
async fn load_secret_string(
    client: &aws_sdk_secretsmanager::Client,
    reference: &SecretRef,
) -> Result<String, AwsAdapterError> {
    match reference.manager {
        SupportedSecretManager::AwsSecretsManager => {}
    }
    let mut request = client.get_secret_value().secret_id(&reference.name_or_arn);
    request = match &reference.version {
        SecretVersionRef::Stage(stage) => request.version_stage(stage),
        SecretVersionRef::VersionId(version_id) => request.version_id(version_id),
    };
    let output = request
        .send()
        .await
        .map_err(crate::error::map_secretsmanager_get_secret_value_error)?;
    output
        .secret_string()
        .map(str::to_owned)
        .ok_or(AwsAdapterError::Internal)
}

#[derive(Deserialize)]
struct AuthSecretDocument {
    kid: String,
    mint_until_unix: u64,
    verify_until_unix: u64,
    magic_link_lookup_hmac_b64: String,
    aws_storage_hmac_b64: String,
    session_cookie_root_b64: String,
    magic_link_confirm_cookie_root_b64: String,
    pow_challenge_secret_b64: String,
    pow_proof_cookie_root_b64: String,
}

impl AuthSecretDocument {
    fn parse(json: &str) -> Result<Self, AwsAdapterError> {
        let parsed: Self = serde_json::from_str(json).map_err(|_| AwsAdapterError::Internal)?;
        if parsed.magic_link_lookup_hmac_b64.len() > KEY_B64_BYTES
            || parsed.aws_storage_hmac_b64.len() > KEY_B64_BYTES
            || parsed.session_cookie_root_b64.len() > KEY_B64_BYTES
            || parsed.magic_link_confirm_cookie_root_b64.len() > KEY_B64_BYTES
            || parsed.pow_challenge_secret_b64.len() > KEY_B64_BYTES
            || parsed.pow_proof_cookie_root_b64.len() > KEY_B64_BYTES
        {
            return Err(AwsAdapterError::Internal);
        }
        KeyId::parse(&parsed.kid).map_err(|_| AwsAdapterError::Internal)?;
        if parsed.mint_until_unix == 0
            || parsed.verify_until_unix == 0
            || parsed.verify_until_unix < parsed.mint_until_unix
        {
            return Err(AwsAdapterError::Internal);
        }
        parsed.ensure_distinct_keys()?;
        Ok(parsed)
    }

    /// Every key field holds its own value: one value pasted into two fields
    /// would reuse a secret across contexts, and three of them are used as
    /// raw HMAC keys with no derivation step to separate them.
    fn ensure_distinct_keys(&self) -> Result<(), AwsAdapterError> {
        let fields = [
            &self.magic_link_lookup_hmac_b64,
            &self.aws_storage_hmac_b64,
            &self.session_cookie_root_b64,
            &self.magic_link_confirm_cookie_root_b64,
            &self.pow_challenge_secret_b64,
            &self.pow_proof_cookie_root_b64,
        ];
        let mut keys = Vec::with_capacity(fields.len());
        for field in fields {
            keys.push(Zeroizing::new(decode_key(field)?));
        }
        for (index, key) in keys.iter().enumerate() {
            for other in keys.iter().skip(index + 1) {
                if bool::from(key.as_slice().ct_eq(other.as_slice())) {
                    return Err(AwsAdapterError::Internal);
                }
            }
        }
        Ok(())
    }
}

impl Drop for AuthSecretDocument {
    fn drop(&mut self) {
        self.magic_link_lookup_hmac_b64.zeroize();
        self.aws_storage_hmac_b64.zeroize();
        self.session_cookie_root_b64.zeroize();
        self.magic_link_confirm_cookie_root_b64.zeroize();
        self.pow_challenge_secret_b64.zeroize();
        self.pow_proof_cookie_root_b64.zeroize();
    }
}

/// The previous document's HMAC key, but only when it differs from the
/// active one. An unchanged key needs no fallback, so it yields `None` and
/// costs no extra reads.
fn previous_if_rotated(
    active: &[u8; KEY_BYTES],
    previous: Option<&AuthSecretDocument>,
    key_b64: fn(&AuthSecretDocument) -> &str,
) -> Result<Option<Zeroizing<[u8; KEY_BYTES]>>, AwsAdapterError> {
    let Some(previous) = previous else {
        return Ok(None);
    };
    let decoded = Zeroizing::new(decode_key(key_b64(previous))?);
    let same = bool::from(decoded.ct_eq(active));
    Ok((!same).then_some(decoded))
}

fn decode_key(value: &str) -> Result<[u8; KEY_BYTES], AwsAdapterError> {
    let mut decoded = STANDARD
        .decode(value)
        .map_err(|_| AwsAdapterError::Internal)?;
    let result = decoded
        .as_slice()
        .try_into()
        .map_err(|_| AwsAdapterError::Internal);
    decoded.zeroize();
    result
}

fn validate_metadata_value(value: &str, max_bytes: usize) -> Result<(), AwsAdapterError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(AwsAdapterError::Internal)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
