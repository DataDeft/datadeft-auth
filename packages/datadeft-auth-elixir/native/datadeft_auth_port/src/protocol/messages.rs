//! Strict request payloads and reply results for the v1 operations. Every
//! payload denies unknown fields; every result serializes a fixed key set so
//! the Elixir side can validate exact shapes.
use serde::{Deserialize, Serialize};

/// Backing mode selected by the application at initialization.
#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Crate-shipped in-memory store and outbox; tests and local development.
    Fake,
    /// DynamoDB, SES and Secrets Manager through the supported credential
    /// chain; requires the `aws` section.
    Aws,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitPayload {
    pub mode: Mode,
    pub service: ServicePayload,
    pub email: EmailTemplatePayload,
    pub secrets: SecretsPayload,
    /// Required in AWS mode, refused in fake mode.
    #[serde(default)]
    pub aws: Option<AwsPayload>,
}

/// AWS deployment configuration. Credentials come from the supported chain
/// (deployment roles), never from this payload.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsPayload {
    pub region: String,
    pub table: String,
    pub from_email: String,
    #[serde(default)]
    pub reply_to: Vec<String>,
    /// Test/dev only (DynamoDB Local); production omits it.
    #[serde(default)]
    pub endpoint_url: Option<String>,
    /// Test-only: record emails in-process instead of SES. Refused unless
    /// endpoint_url marks this a local deployment.
    #[serde(default)]
    pub fake_outbox: bool,
}

/// Service policy; omitted lifetimes keep the library defaults.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePayload {
    pub terms_version: String,
    pub privacy_version: String,
    #[serde(default)]
    pub magic_link_ttl_secs: Option<u64>,
    #[serde(default)]
    pub magic_link_flow_ttl_secs: Option<u64>,
    #[serde(default)]
    pub session_idle_secs: Option<u64>,
    #[serde(default)]
    pub session_absolute_secs: Option<u64>,
    #[serde(default)]
    pub enforce_country: bool,
    #[serde(default)]
    pub account_display: Option<AccountDisplayPayload>,
    /// Email locales: the default plus the other allowed values. Absent means
    /// locale-free emails.
    #[serde(default)]
    pub default_locale: Option<String>,
    #[serde(default)]
    pub locales: Vec<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountDisplayPayload {
    Masked,
    Full,
}

/// Application-supplied email content. The rendered magic-link URL is the
/// base with the token appended; bodies must carry the URL marker.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailTemplatePayload {
    pub link_base_url: String,
    pub subject: String,
    pub text: String,
    #[serde(default)]
    pub html: Option<String>,
}

/// Auth secret sources. Fake mode takes inline secret documents
/// (docs/security.md "Auth secret document") that transit the private stdin
/// pipe once; AWS mode takes Secrets Manager references so key material
/// never enters BEAM. Mixing the two forms is a configuration error.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsPayload {
    #[serde(default)]
    pub active_document: Option<String>,
    #[serde(default)]
    pub previous_document: Option<String>,
    #[serde(default)]
    pub active_ref: Option<SecretRefPayload>,
    #[serde(default)]
    pub previous_ref: Option<SecretRefPayload>,
}

/// One Secrets Manager reference: a name or ARN plus exactly one of stage or
/// version id (active defaults to the AWSCURRENT stage).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRefPayload {
    pub name_or_arn: String,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default)]
    pub version_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestLinkPayload {
    pub email: String,
    pub terms_accepted: bool,
    pub privacy_accepted: bool,
    #[serde(default)]
    pub locale: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandingPayload {
    pub token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowStatePayload {
    pub confirm_cookie: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmPayload {
    pub confirm_cookie: String,
    pub confirmation: String,
    #[serde(default)]
    pub country: Option<String>,
}

/// Shared by validate_session and logout.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPayload {
    pub session_cookie: String,
    #[serde(default)]
    pub country: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxPeekPayload {
    pub email: String,
}

/// Reply result. Optional fields serialize as null so each operation has one
/// exact key set on the wire.
#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ResultBody {
    Handshake {
        build_version: &'static str,
        max_frame_bytes: usize,
    },
    Ping,
    Init,
    /// The public response is always the same generic acceptance; the reason
    /// label is internal, for the application's logs and metrics only.
    RequestLink {
        reason: &'static str,
    },
    /// Uniform for every unusable link state, per the scanner-safe contract.
    Landing {
        usable: bool,
        confirm_cookie: Option<String>,
        confirmation: Option<String>,
        account: Option<String>,
        cookie_max_age_secs: Option<u64>,
    },
    FlowState {
        usable: bool,
        account: Option<String>,
        confirmation: Option<String>,
    },
    Confirm {
        session_cookie: String,
        user_id: String,
        user_created: bool,
        country: Option<String>,
    },
    ValidateSession {
        valid: bool,
        user_id: Option<String>,
        refreshed_cookie: Option<String>,
    },
    Logout {
        revoked: bool,
    },
    FakeLastMagicLink {
        found: bool,
        magic_link_url: Option<String>,
        expires_at_unix: Option<u64>,
    },
    /// Per-request application failure; protocol faults never use this and
    /// end the process instead.
    Error {
        code: ErrorCode,
    },
}

/// Closed failure set. `rejected` clears temporary client state,
/// `unavailable` preserves it for an identical retry.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Overloaded,
    Configuration,
    BadRequest,
    Rejected,
    Unavailable,
    Internal,
}
