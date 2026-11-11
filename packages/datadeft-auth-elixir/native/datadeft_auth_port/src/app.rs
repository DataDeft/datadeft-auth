//! Initialized application state: the configured service policy, loaded
//! keyrings and the backing store/outbox pair. Built once per connection by
//! the init operation; jobs share it immutably. The port owns the AWS
//! clients and executor; core and service crates receive loaded material.
mod handlers;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use datadeft_magic_link_aws::{
    AuthSecretsConfig, DynamoDbAuthStore, FakeDynamoDbAuthStore, FakeMagicLinkOutbox,
    LoadedAuthSecrets, MagicLinkEmailRenderer, RenderedMagicLinkEmail, SecretRef, SecretVersionRef,
    SesMagicLinkOutbox, StorageHmacKey, resolve_auth_secrets,
};
use datadeft_magic_link_service::{
    AccountDisplay, Clock, DependencyError, KeyRing, LocaleAllowlist, LookupHmacKey,
    MagicLinkConfirmCookie, MagicLinkEmail, MagicLinkFlowService, MagicLinkServiceConfig,
    SessionCookie,
};
use datadeft_pow_core::{
    DEFAULT_POW_PROOF_TTL_SECS, MAX_DIFFICULTY, POW_PROOF_MAX_AGE_SECS, PowProofCookie, PowSecret,
    Solution, UnixMillis, Verified, validate_challenge_max_age_secs, verify_solution,
};
use rand_core::OsRng;

use crate::protocol::{
    AccountDisplayPayload, AppCommand, AwsPayload, EmailTemplatePayload, ErrorCode, InitPayload,
    Mode, PowPayload, ResultBody, SecretRefPayload, SecretsPayload, ServicePayload,
};

/// Bodies carry this marker where the rendered magic-link URL belongs.
const URL_MARKER: &str = "{magic_link_url}";

/// Default challenge lifetime: the documented 2-minute TTL baseline, matching
/// the shipped HTTP deployment.
const DEFAULT_CHALLENGE_MAX_AGE_SECS: u64 = 120;

/// Ceiling on the per-solve budget, mirroring the HTTP adapter's
/// `MAX_PROOF_BUDGET_PER_SOLVE`: beyond this the gate stops gating.
const MAX_PROOF_BUDGET_PER_SOLVE: u32 = 1_000;

/// The initialized backend; one monomorphized `App` per supported pairing.
#[derive(Clone)]
pub enum ReadyApp {
    Fake(Arc<App<FakeDynamoDbAuthStore, FakeMagicLinkOutbox>>),
    Aws(Arc<App<DynamoDbAuthStore, SesMagicLinkOutbox<TemplateRenderer>>>),
    /// AWS storage with the in-process outbox: DynamoDB Local test runs.
    AwsLocal(Arc<App<DynamoDbAuthStore, FakeMagicLinkOutbox>>),
}

impl ReadyApp {
    pub async fn handle(&self, command: AppCommand) -> ResultBody {
        match self {
            Self::Fake(app) => app.run(command).await,
            Self::Aws(app) => app.run(command).await,
            Self::AwsLocal(app) => app.run(command).await,
        }
    }

    /// Build the configured state, failing closed. `Configuration` is an
    /// application mistake and will not heal by retrying; `Unavailable`
    /// covers transient dependency failures, healed by the restart loop.
    pub async fn initialize(payload: InitPayload) -> Result<Self, ErrorCode> {
        let config = service_config(payload.service)?;
        let email = Arc::new(EmailTemplate::validate(payload.email)?);
        match payload.mode {
            Mode::Fake => {
                if payload.aws.is_some() {
                    return Err(ErrorCode::Configuration);
                }
                let secrets = inline_secrets(payload.secrets)?;
                let (shared, storage_hmac_key, _) =
                    shared_state(config, email, payload.pow, secrets)?;
                let outbox = FakeMagicLinkOutbox::default();
                Ok(Self::Fake(Arc::new(App {
                    shared,
                    // The fake store keys records with the active key only;
                    // the storage-side previous-key fallback is a DynamoDB
                    // adapter behavior exercised by that crate's tests.
                    store: FakeDynamoDbAuthStore::new(storage_hmac_key),
                    outbox: outbox.clone(),
                    dev_outbox: Some(outbox),
                })))
            }
            Mode::Aws => {
                let aws = payload.aws.ok_or(ErrorCode::Configuration)?;
                if aws.fake_outbox && aws.endpoint_url.is_none() {
                    return Err(ErrorCode::Configuration);
                }
                // Production (no endpoint override) takes Secrets Manager
                // references only, so key material never enters BEAM. Local
                // deployments (DynamoDB Local) have no Secrets Manager and
                // may pass inline documents instead.
                let inline =
                    aws.endpoint_url.is_some() && payload.secrets.active_document.is_some();
                let sdk = sdk_config(&aws).await;
                let secrets = if inline {
                    inline_secrets(payload.secrets)?
                } else {
                    let references = referenced_secrets(payload.secrets)?;
                    let secrets_client = aws_sdk_secretsmanager::Client::new(&sdk);
                    resolve_auth_secrets(&secrets_client, &references)
                        .await
                        .map_err(|_| ErrorCode::Unavailable)?
                };
                let (shared, storage_hmac_key, previous_storage_hmac_key) =
                    shared_state(config, email, payload.pow, secrets)?;
                let mut store = DynamoDbAuthStore::new(
                    aws_sdk_dynamodb::Client::new(&sdk),
                    aws.table.clone(),
                    storage_hmac_key,
                );
                if let Some(previous) = previous_storage_hmac_key {
                    store = store.with_previous_storage_hmac_key(previous);
                }
                if aws.fake_outbox {
                    let outbox = FakeMagicLinkOutbox::default();
                    return Ok(Self::AwsLocal(Arc::new(App {
                        shared,
                        store,
                        outbox: outbox.clone(),
                        dev_outbox: Some(outbox),
                    })));
                }
                let renderer = TemplateRenderer {
                    template: shared.email.clone(),
                };
                let outbox = SesMagicLinkOutbox::new(
                    aws_sdk_sesv2::Client::new(&sdk),
                    aws.from_email,
                    renderer,
                )
                .with_reply_to(&aws.reply_to)
                .map_err(|_| ErrorCode::Configuration)?;
                Ok(Self::Aws(Arc::new(App {
                    shared,
                    store,
                    outbox,
                    dev_outbox: None,
                })))
            }
        }
    }
}

/// The store-independent half of an initialized `App`, built once and
/// embedded whole so the per-backend construction sites cannot drift.
struct Shared {
    config: MagicLinkServiceConfig,
    lookup_hmac_key: LookupHmacKey,
    previous_lookup_hmac_key: Option<LookupHmacKey>,
    confirm_keyring: KeyRing<MagicLinkConfirmCookie>,
    session_keyring: KeyRing<SessionCookie>,
    /// Shared with the outbox renderer in SES mode, never duplicated.
    email: Arc<EmailTemplate>,
    /// Present only when initialization configured the PoW admission gate.
    pow: Option<PowState>,
}

/// Builds the shared state from the loaded secrets (the one destructuring
/// site) and hands back the storage keys the store constructors consume.
fn shared_state(
    config: MagicLinkServiceConfig,
    email: Arc<EmailTemplate>,
    pow: Option<PowPayload>,
    secrets: LoadedAuthSecrets,
) -> Result<(Shared, StorageHmacKey, Option<StorageHmacKey>), ErrorCode> {
    let pow = pow_state(pow, &secrets)?;
    let LoadedAuthSecrets {
        lookup_hmac_key,
        storage_hmac_key,
        previous_lookup_hmac_key,
        previous_storage_hmac_key,
        confirm_keyring,
        session_keyring,
        ..
    } = secrets;
    Ok((
        Shared {
            config,
            lookup_hmac_key,
            previous_lookup_hmac_key,
            confirm_keyring,
            session_keyring,
            email,
            pow,
        },
        storage_hmac_key,
        previous_storage_hmac_key,
    ))
}

pub struct App<Store, Outbox> {
    store: Store,
    outbox: Outbox,
    /// Present only where recorded emails may be read back (fake backends);
    /// `fake_last_magic_link` is refused when absent.
    dev_outbox: Option<FakeMagicLinkOutbox>,
    shared: Shared,
}

/// Validated proof-of-work policy plus the keys it runs on.
pub(crate) struct PowState {
    secret: PowSecret,
    /// The previous document's challenge secret, kept verify-only through a
    /// rotation so in-flight challenges still land.
    previous_secret: Option<PowSecret>,
    proof_keyring: KeyRing<PowProofCookie>,
    pub(crate) difficulty: u8,
    pub(crate) challenge_max_age_secs: u64,
    pub(crate) proof_ttl_secs: u64,
    pub(crate) budget_per_solve: u32,
}

impl PowState {
    pub(crate) fn proof_keyring(&self) -> &KeyRing<PowProofCookie> {
        &self.proof_keyring
    }

    /// Mint a challenge at the configured difficulty.
    pub(crate) fn mint(
        &self,
        now: UnixMillis,
        entropy: [u8; 16],
    ) -> Result<datadeft_pow_core::Challenge, datadeft_pow_core::PowError> {
        datadeft_pow_core::mint_challenge(&self.secret, self.difficulty, now, entropy)
    }

    /// Verify a solution against the active challenge secret, then against
    /// the rotation's previous one, collapsing every refusal into one.
    pub(crate) fn verify(&self, solution: &Solution, now: UnixMillis) -> Option<Verified> {
        let check = |secret: &PowSecret| {
            verify_solution(
                secret,
                solution,
                now,
                self.challenge_max_age_secs,
                self.difficulty,
            )
            .ok()
        };
        check(&self.secret).or_else(|| self.previous_secret.as_ref().and_then(check))
    }
}

/// Build the PoW state when the application configured the gate. Keys come
/// from the loaded secret documents; only the proof keyring is built here, so
/// deployments without PoW keep no PoW key material in memory.
fn pow_state(
    payload: Option<PowPayload>,
    secrets: &LoadedAuthSecrets,
) -> Result<Option<PowState>, ErrorCode> {
    let Some(pow) = payload else {
        return Ok(None);
    };
    let challenge_max_age_secs = pow
        .challenge_max_age_secs
        .unwrap_or(DEFAULT_CHALLENGE_MAX_AGE_SECS);
    let proof_ttl_secs = pow.proof_ttl_secs.unwrap_or(DEFAULT_POW_PROOF_TTL_SECS);
    if pow.difficulty == 0
        || pow.difficulty > MAX_DIFFICULTY
        || validate_challenge_max_age_secs(challenge_max_age_secs).is_err()
        || proof_ttl_secs == 0
        || proof_ttl_secs > POW_PROOF_MAX_AGE_SECS
        || pow.proof_budget_per_solve == 0
        || pow.proof_budget_per_solve > MAX_PROOF_BUDGET_PER_SOLVE
    {
        return Err(ErrorCode::Configuration);
    }
    let proof_keyring = secrets
        .pow_proof_keyring::<PowProofCookie>()
        .map_err(|_| ErrorCode::Configuration)?;
    Ok(Some(PowState {
        secret: PowSecret::new(*secrets.pow_challenge_secret.as_bytes()),
        previous_secret: secrets
            .previous_pow_challenge_secret
            .as_ref()
            .map(|previous| PowSecret::new(*previous.as_bytes())),
        proof_keyring,
        difficulty: pow.difficulty,
        challenge_max_age_secs,
        proof_ttl_secs,
        budget_per_solve: pow.proof_budget_per_solve,
    }))
}

impl<Store, Outbox> App<Store, Outbox> {
    fn flow_service<'a>(
        &'a self,
        rng: &'a mut OsRng,
    ) -> MagicLinkFlowService<'a, Store, Store, Store, WallClock, OsRng> {
        MagicLinkFlowService {
            authentication: &self.store,
            sessions: &self.store,
            limiter: &self.store,
            clock: &WallClock,
            rng,
            lookup_hmac_key: &self.shared.lookup_hmac_key,
            previous_lookup_hmac_key: self.shared.previous_lookup_hmac_key.as_ref(),
            confirm_keyring: &self.shared.confirm_keyring,
            session_keyring: &self.shared.session_keyring,
            config: self.shared.config.clone(),
        }
    }
}

/// Application-supplied email content, validated at initialization.
pub(crate) struct EmailTemplate {
    link_base_url: String,
    subject: String,
    text: String,
    html: Option<String>,
}

impl EmailTemplate {
    fn validate(payload: EmailTemplatePayload) -> Result<Self, ErrorCode> {
        let base_ok = !payload.link_base_url.is_empty()
            && !payload
                .link_base_url
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            && !payload.link_base_url.contains(['{', '}']);
        // The URL carries the bearer token, and Subject headers are logged
        // routinely by MTAs and delivery tooling: the marker is required in
        // the bodies and refused in the subject.
        let bodies_ok = !payload.subject.trim().is_empty()
            && !payload.subject.contains(URL_MARKER)
            && payload.text.contains(URL_MARKER)
            && payload
                .html
                .as_deref()
                .is_none_or(|html| html.contains(URL_MARKER));
        if base_ok && bodies_ok {
            Ok(Self {
                link_base_url: payload.link_base_url,
                subject: payload.subject,
                text: payload.text,
                html: payload.html,
            })
        } else {
            Err(ErrorCode::Configuration)
        }
    }

    pub(crate) fn magic_link_url(&self, token: &str) -> String {
        format!("{}{token}", self.link_base_url)
    }
}

/// Renders the application's template with the bearer landing URL. One
/// template for every locale in v1; the resolved locale is not yet used.
pub struct TemplateRenderer {
    template: Arc<EmailTemplate>,
}

impl MagicLinkEmailRenderer for TemplateRenderer {
    fn render(&self, email: &MagicLinkEmail) -> Result<RenderedMagicLinkEmail, DependencyError> {
        let url = self
            .template
            .magic_link_url(email.token.as_secret_value().as_str());
        Ok(RenderedMagicLinkEmail {
            to: email.email.as_str().to_owned(),
            subject: self.template.subject.clone(),
            text: self.template.text.replace(URL_MARKER, &url),
            html: self
                .template
                .html
                .as_ref()
                .map(|html| html.replace(URL_MARKER, &url)),
        })
    }
}

fn service_config(service: ServicePayload) -> Result<MagicLinkServiceConfig, ErrorCode> {
    let mut config = MagicLinkServiceConfig::new(service.terms_version, service.privacy_version);
    if let Some(value) = service.magic_link_ttl_secs {
        config.magic_link_ttl_secs = value;
    }
    if let Some(value) = service.magic_link_flow_ttl_secs {
        config.magic_link_flow_ttl_secs = value;
    }
    if let Some(value) = service.session_idle_secs {
        config.session_idle_secs = value;
    }
    if let Some(value) = service.session_absolute_secs {
        config.session_absolute_secs = value;
    }
    config.enforce_country = service.enforce_country;
    if let Some(display) = service.account_display {
        config.account_display = match display {
            AccountDisplayPayload::Masked => AccountDisplay::Masked,
            AccountDisplayPayload::Full => AccountDisplay::Full,
        };
    }
    match (&service.default_locale, service.locales.is_empty()) {
        (Some(default), _) => {
            let others = service.locales.iter().map(String::as_str);
            config.locales =
                Some(LocaleAllowlist::new(default, others).map_err(|_| ErrorCode::Configuration)?);
        }
        (None, true) => {}
        (None, false) => return Err(ErrorCode::Configuration),
    }
    config.validate().map_err(|_| ErrorCode::Configuration)?;
    Ok(config)
}

fn inline_secrets(secrets: SecretsPayload) -> Result<LoadedAuthSecrets, ErrorCode> {
    if secrets.active_ref.is_some() || secrets.previous_ref.is_some() {
        return Err(ErrorCode::Configuration);
    }
    let active = secrets.active_document.ok_or(ErrorCode::Configuration)?;
    LoadedAuthSecrets::from_json(&active, secrets.previous_document.as_deref())
        .map_err(|_| ErrorCode::Configuration)
}

/// AWS mode takes Secrets Manager references only, so key material never
/// crosses the BEAM boundary.
fn referenced_secrets(secrets: SecretsPayload) -> Result<AuthSecretsConfig, ErrorCode> {
    if secrets.active_document.is_some() || secrets.previous_document.is_some() {
        return Err(ErrorCode::Configuration);
    }
    let active = secret_ref(
        secrets.active_ref.ok_or(ErrorCode::Configuration)?,
        "AWSCURRENT",
    )?;
    let previous = secrets
        .previous_ref
        .map(|reference| secret_ref(reference, "AWSPREVIOUS"))
        .transpose()?;
    Ok(AuthSecretsConfig::new(active, previous))
}

fn secret_ref(payload: SecretRefPayload, default_stage: &str) -> Result<SecretRef, ErrorCode> {
    let version = match (payload.stage, payload.version_id) {
        (Some(stage), None) => SecretVersionRef::stage(stage),
        (None, Some(version_id)) => SecretVersionRef::version_id(version_id),
        (None, None) => SecretVersionRef::stage(default_stage),
        (Some(_), Some(_)) => return Err(ErrorCode::Configuration),
    };
    Ok(SecretRef::aws_secrets_manager(payload.name_or_arn, version))
}

async fn sdk_config(aws: &AwsPayload) -> aws_config::SdkConfig {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(aws.region.clone()));
    if let Some(endpoint) = &aws.endpoint_url {
        loader = loader.endpoint_url(endpoint);
    }
    loader.load().await
}

/// Wall clock supplied by this adapter; the library never reads one itself.
pub(crate) struct WallClock;

impl Clock for WallClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| DependencyError::Internal)
    }
}

/// Millisecond wall clock for the PoW freshness window and timing signal.
pub(crate) fn now_unix_millis() -> Option<UnixMillis> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .map(UnixMillis::from_millis)
}

#[cfg(test)]
#[path = "app/app_tests.rs"]
pub(crate) mod tests;
