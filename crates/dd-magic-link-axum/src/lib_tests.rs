//! Axum adapter regression and security tests.

use std::cell::Cell;
use std::rc::Rc;

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE, COOKIE, LOCATION, ORIGIN, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use dd_auth_token_core::keyring::{KeyId, KeyPurpose, KeyRing, KeySlot, RootSecret};
use dd_magic_link_core::{LookupHmac, LookupHmacKey, MagicLinkFlowCookie, NormalizedEmail};
use dd_magic_link_service::{
    BeginMagicLinkLandingCommand, Clock, CommitMagicLinkAuthentication,
    CommitMagicLinkAuthenticationError, ConfirmMagicLinkFlowCommand, DependencyError, EmailLocale,
    MagicLinkAuthenticationCandidate, MagicLinkAuthenticationRepository, MagicLinkFlowService,
    MagicLinkServiceError, RateLimitDecision, RateLimitKey, RateLimiter, RequestMagicLinkOutcome,
    SessionCookie, SessionId, SessionRecord, SessionRepository, SessionValidationError, UserRecord,
};
use rand_core::{CryptoRng, RngCore};

use super::*;

fn policy() -> MagicLinkServiceConfig {
    MagicLinkServiceConfig::new("terms-v1", "privacy-v1")
}

fn scanner_config() -> MagicLinkScannerFlowConfig {
    MagicLinkScannerFlowConfig::new(
        SameOriginRedirect::parse("/auth/magic-link/confirm").expect("post action"),
        SameOriginRedirect::parse("/signed-in").expect("success redirect"),
        SameOriginPostConfig::parse("https://example.test").expect("origin"),
        SessionCookieConfig::production(&policy()).expect("session policy"),
        AuthFlowCookieConfig::production_defaults(),
    )
    .expect("scanner config")
}

fn post_request(content_type: &'static str, body: impl Into<Body>) -> Request {
    Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link/confirm")
        .header(CONTENT_TYPE, content_type)
        .header(ORIGIN, "https://example.test")
        .header(COOKIE, "dd_auth_flow=flow-cookie")
        .body(body.into())
        .expect("request builds")
}

async fn response_parts(response: Response) -> (StatusCode, HeaderMap, Vec<u8>) {
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads")
        .to_vec();
    (status, headers, body)
}

fn terminal_fingerprint(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Vec<u8> {
    let mut fields = Vec::new();
    for name in headers.keys() {
        for value in headers.get_all(name).iter() {
            fields.push((name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()));
        }
    }
    fields.sort();
    let mut fingerprint = format!("{status}\n").into_bytes();
    for (name, value) in fields {
        fingerprint.extend_from_slice(&name);
        fingerprint.push(b':');
        fingerprint.extend_from_slice(&value);
        fingerprint.push(b'\n');
    }
    fingerprint.extend_from_slice(body);
    fingerprint
}

fn bad_request_flow_error() -> MagicLinkFlowError {
    ConfirmMagicLinkFlowCommand::new(
        "flow".to_owned(),
        "confirmation".to_owned(),
        Some("invalid-country".to_owned()),
    )
    .expect_err("invalid country")
}

#[derive(Clone, Copy)]
enum FixtureFlowError {
    MagicLinkUnavailable,
    Unavailable,
    Internal,
}

struct FixtureRepository;

impl MagicLinkAuthenticationRepository for FixtureRepository {
    async fn find_magic_link_for_authentication(
        &self,
        _selector_lookup_hmac: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        Ok(None)
    }

    async fn find_user_for_authentication(
        &self,
        _email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        Ok(None)
    }

    async fn commit_magic_link_authentication(
        &self,
        _command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        Err(CommitMagicLinkAuthenticationError::Internal)
    }
}

impl SessionRepository for FixtureRepository {
    async fn find_session(
        &self,
        _session_id: &SessionId,
        _now_unix: u64,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        Ok(None)
    }

    async fn revoke_session(
        &self,
        _session_id: &SessionId,
        _revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        Ok(())
    }
}

struct FixtureLimiter;

impl RateLimiter for FixtureLimiter {
    async fn check_rate_limit(
        &self,
        _key: &RateLimitKey,
        _limit: u32,
        _window_secs: u64,
        _now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        Ok(RateLimitDecision::Allowed)
    }
}

struct FixtureClock {
    error: Option<DependencyError>,
}

impl Clock for FixtureClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        self.error.map_or(Ok(1_000), Err)
    }
}

struct FixtureRng(u8);

impl RngCore for FixtureRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for FixtureRng {}

fn fixture_keyring<P: KeyPurpose>() -> KeyRing<P> {
    let kid = KeyId::parse("fixture-active").expect("key id");
    let root = RootSecret::new([0x42; 32]);
    let key = root.derive_key::<P>(&kid).expect("derived key");
    KeyRing::new(
        kid.clone(),
        vec![KeySlot::active_with_windows(kid, key, 20_000, 3_000_000)],
    )
    .expect("keyring")
}

async fn fixture_flow_error(kind: FixtureFlowError) -> MagicLinkFlowError {
    let repository = FixtureRepository;
    let limiter = FixtureLimiter;
    let clock = FixtureClock {
        error: matches!(kind, FixtureFlowError::Unavailable)
            .then_some(DependencyError::Unavailable),
    };
    let mut rng = FixtureRng(0);
    let lookup_key = LookupHmacKey::new([0x24; 32]);
    let flow_keyring = fixture_keyring::<MagicLinkFlowCookie>();
    let session_keyring = fixture_keyring::<SessionCookie>();
    let mut service_config = policy();
    if matches!(kind, FixtureFlowError::Internal) {
        service_config.magic_link_flow_ttl_secs = 0;
    }
    let mut service = MagicLinkFlowService {
        authentication: &repository,
        sessions: &repository,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        flow_keyring: &flow_keyring,
        session_keyring: &session_keyring,
        config: service_config,
    };
    service
        .begin_magic_link_landing(BeginMagicLinkLandingCommand::new("malformed".to_owned()))
        .await
        .expect_err("fixture flow error")
}

#[test]
fn request_json_regression_preserves_email_and_consent() {
    let body = br#"{
        "email":"User@example.com",
        "locale":"hu",
        "terms_accepted":true,
        "privacy_accepted":true
    }"#;
    let command = parse_magic_link_request_json(body).expect("command");
    assert_eq!(command.email().as_str(), "User@example.com");
    assert_eq!(command.locale(), EmailLocale::Hu);
    assert!(command.terms_accepted());
    assert!(command.privacy_accepted());
}

#[test]
fn request_negative_regressions_reject_locale_and_forward_false_consent() {
    let bad_locale = br#"{"email":"user@example.com","locale":"de","terms_accepted":true,"privacy_accepted":true}"#;
    assert_eq!(
        parse_magic_link_request_json(bad_locale).unwrap_err(),
        MagicLinkHttpError::BadRequest
    );

    let false_consent = br#"{"email":"user@example.com","locale":"en","terms_accepted":false,"privacy_accepted":true}"#;
    let command = parse_magic_link_request_json(false_consent).expect("command");
    assert!(!command.terms_accepted());
    assert!(command.privacy_accepted());
}

#[test]
fn request_and_confirmation_dto_debug_are_redacted() {
    let request: MagicLinkRequestJson = serde_json::from_str(
        r#"{"email":"sensitive@example.test","locale":"en","terms_accepted":true,"privacy_accepted":true}"#,
    )
    .expect("request dto");
    let debug = format!("{request:?}");
    assert!(!debug.contains("sensitive@example.test"));

    let confirmation: MagicLinkConfirmationBody =
        serde_json::from_str(r#"{"confirmation":"confirmation-secret","country":"HU"}"#)
            .expect("confirmation dto");
    let debug = format!("{confirmation:?}");
    assert!(!debug.contains("confirmation-secret"));
    assert!(
        serde_json::from_str::<MagicLinkConfirmationBody>(
            r#"{"confirmation":"ok","token":"forbidden"}"#
        )
        .is_err()
    );
    let token = MagicLinkLandingToken::new("candidate-secret".to_owned()).expect("bounded");
    assert_eq!(format!("{token:?}"), "MagicLinkLandingToken(..)");
}

#[test]
fn same_origin_redirect_is_fully_prevalidated_for_location() {
    for value in [
        "/done",
        "/auth/complete?fixed=dashboard",
        "/path%20segment?value=%2F",
    ] {
        let redirect = SameOriginRedirect::parse(value).expect(value);
        assert_eq!(redirect.as_str(), value);
        assert_eq!(redirect.location_header(), value);
    }
    for value in [
        "",
        "done",
        "//evil.test/path",
        "https://evil.test/path",
        "http:relative",
        "/path with space",
        "/path\tvalue",
        "/path\\value",
        "/path%",
        "/path%2",
        "/path%GG",
        "/mlv1.selector.verifier",
        "/café",
    ] {
        assert!(
            SameOriginRedirect::parse(value).is_err(),
            "redirect {value:?}"
        );
    }
}

#[test]
fn session_cookie_uses_validated_idle_policy_and_clear_parity() {
    let mut service = policy();
    service.session_idle_secs = 1234;
    service.session_absolute_secs = 5678;
    let config = SessionCookieConfig::production(&service).expect("policy");
    assert_eq!(config.max_age_secs(), 1234);

    let set = session_set_cookie_header(&config, "v1.active.cookie")
        .expect("set")
        .to_str()
        .expect("ascii")
        .to_owned();
    let clear = clear_session_cookie_header(&config)
        .to_str()
        .expect("ascii")
        .to_owned();
    assert_eq!(
        set,
        "dd_session=v1.active.cookie; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=1234"
    );
    assert_eq!(
        clear,
        "dd_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
    assert!(!set.contains("Domain="));
}

#[test]
fn invalid_session_policy_and_insecure_samesite_none_are_rejected() {
    let mut invalid = policy();
    invalid.session_idle_secs = 0;
    assert!(SessionCookieConfig::production(&invalid).is_err());

    let local = SessionCookieConfig::local_development(&policy()).expect("local");
    assert_eq!(
        local.with_same_site(SameSite::None).unwrap_err(),
        CookieConfigError::SameSiteNoneRequiresSecure
    );
    assert_eq!(
        SessionCookieConfig::production(&policy())
            .expect("production")
            .with_name("__Host-session")
            .unwrap_err(),
        CookieConfigError::InvalidName
    );
}

#[test]
fn precomputed_clear_headers_match_freshly_built_ones() {
    // The from_static default constants and every construction path must stay
    // byte-for-byte in lockstep with cookie_header's wire format.
    let cases = [
        (AuthFlowCookieConfig::production_defaults().flow().clone()),
        (AuthFlowCookieConfig::local_development_defaults()
            .flow()
            .clone()),
        (TemporaryCookieConfig::production("custom_flow", "/custom").expect("custom flow")),
    ];
    for flow in cases {
        let fresh = cookie_header(
            flow.name(),
            "",
            flow.path(),
            flow.secure(),
            flow.same_site(),
            Some(0),
            true,
        )
        .expect("fresh clear header builds");
        assert_eq!(clear_temporary_cookie_header(&flow), fresh);
    }

    let sessions = [
        SessionCookieConfig::production(&policy()).expect("production"),
        SessionCookieConfig::local_development(&policy()).expect("local"),
        SessionCookieConfig::production(&policy())
            .expect("production")
            .with_name("custom_session")
            .expect("name")
            .with_path("/app")
            .expect("path")
            .with_same_site(SameSite::Strict)
            .expect("same-site"),
    ];
    for session in sessions {
        let fresh = cookie_header(
            session.name(),
            "",
            session.path(),
            session.secure(),
            session.same_site(),
            Some(0),
            true,
        )
        .expect("fresh clear header builds");
        assert_eq!(clear_session_cookie_header(&session), fresh);
    }
}

#[test]
fn temporary_cookie_defaults_lifetime_and_clear_are_strict() {
    let production = AuthFlowCookieConfig::production_defaults();
    let flow = production.flow();
    assert_eq!(flow.name(), "dd_auth_flow");
    assert_eq!(flow.path(), "/auth");
    assert!(flow.secure());
    assert_eq!(flow.same_site(), SameSite::Lax);

    let set = set_temporary_cookie_header(flow, "flow-value", 300)
        .expect("set")
        .to_str()
        .expect("ascii")
        .to_owned();
    let clear = clear_temporary_cookie_header(flow)
        .to_str()
        .expect("ascii")
        .to_owned();
    assert_eq!(
        set,
        "dd_auth_flow=flow-value; Path=/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=300"
    );
    assert_eq!(
        clear,
        "dd_auth_flow=; Path=/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
    assert!(set_temporary_cookie_header(flow, "flow-value", 0).is_err());
    assert!(set_temporary_cookie_header(flow, "flow-value", 301).is_err());

    let local = AuthFlowCookieConfig::local_development_defaults();
    assert!(!local.flow().secure());
}

#[test]
fn cookie_setup_rejects_invalid_paths() {
    for path in [
        "auth", "/auth?x", "/auth#x", "/auth%x", "/auth\\x", "/auth;x",
    ] {
        assert_eq!(
            TemporaryCookieConfig::production("flow", path).unwrap_err(),
            CookieConfigError::InvalidPath
        );
    }
}

#[test]
fn scanner_config_checks_every_cookie_collision_and_path_boundary() {
    let post = SameOriginRedirect::parse("/auth/confirm?fixed=1").expect("post");
    let redirect = SameOriginRedirect::parse("/done").expect("redirect");
    let origin = SameOriginPostConfig::parse("https://example.test").expect("origin");
    let session = SessionCookieConfig::production(&policy()).expect("session");

    for path in ["/auth/confirm", "/auth/", "/auth"] {
        let temporary = AuthFlowCookieConfig::new(
            TemporaryCookieConfig::production("flow", path).expect("flow"),
        );
        assert!(
            MagicLinkScannerFlowConfig::new(
                post.clone(),
                redirect.clone(),
                origin.clone(),
                session.clone(),
                temporary,
            )
            .is_ok()
        );
    }
    let false_prefix =
        AuthFlowCookieConfig::new(TemporaryCookieConfig::production("flow", "/aut").expect("flow"));
    assert_eq!(
        MagicLinkScannerFlowConfig::new(
            post.clone(),
            redirect.clone(),
            origin.clone(),
            session.clone(),
            false_prefix,
        )
        .unwrap_err(),
        MagicLinkScannerFlowConfigError::FlowCookiePathDoesNotCoverPostAction
    );

    let session_flow = session.clone().with_name("flow").expect("session name");
    let temporary = AuthFlowCookieConfig::new(
        TemporaryCookieConfig::production("flow", "/auth").expect("flow"),
    );
    assert_eq!(
        MagicLinkScannerFlowConfig::new(
            post.clone(),
            redirect.clone(),
            origin.clone(),
            session_flow,
            temporary,
        )
        .unwrap_err(),
        MagicLinkScannerFlowConfigError::DuplicateCookieName
    );
}

#[test]
fn landing_query_parser_is_raw_exact_and_bounded() {
    assert!(extract_landing_token(Some("token=canonical")).is_ok());
    for query in [
        None,
        Some(""),
        Some("canonical"),
        Some("token="),
        Some("token=a&token=b"),
        Some("token=a&other=b"),
        Some("other=a"),
        Some("token=a%2Eb"),
        Some("token=a+b"),
        Some("token=a=b"),
    ] {
        if query == Some("token=a+b") {
            // Plus is not decoded and is delegated to the sole grammar authority.
            assert!(extract_landing_token(query).is_ok());
        } else {
            assert!(extract_landing_token(query).is_err(), "query {query:?}");
        }
    }
    let over_value = format!("token={}", "a".repeat(MAX_RAW_MAGIC_LINK_TOKEN_BYTES + 1));
    assert!(extract_landing_token(Some(&over_value)).is_err());
    let over_query = "a".repeat(MAX_MAGIC_LINK_LANDING_QUERY_BYTES + 1);
    assert!(extract_landing_token(Some(&over_query)).is_err());
}

#[test]
fn origin_parser_accepts_only_narrow_canonical_grammar() {
    for origin in [
        "https://example.test",
        "http://localhost",
        "https://example.test:8443",
        "http://127.0.0.1:8080",
        "https://0.0.0.0",
    ] {
        let parsed = SameOriginPostConfig::parse(origin).expect(origin);
        assert_eq!(parsed.expected_origin(), origin);
    }
    for origin in [
        "HTTPS://example.test",
        "ftp://example.test",
        "https://Example.test",
        "https://example.test/",
        "https://example.test/path",
        "https://example.test?x",
        "https://example.test#x",
        "https://user@example.test",
        "https://[::1]",
        "https://example%2etest",
        "https://example.test,https://other.test",
        "https://example.test:443",
        "http://example.test:80",
        "https://example.test:0443",
        "https://example.test:0",
        "https://example.test:65536",
        "https://127.00.0.1",
        "https://127.0.0",
        "https://256.0.0.1",
        "https://example.test.",
        "https://-example.test",
        "https://example-.test",
        "https://exa_mple.test",
        " https://example.test",
    ] {
        assert!(
            SameOriginPostConfig::parse(origin).is_err(),
            "origin {origin}"
        );
    }
}

#[test]
fn request_origin_enforcement_requires_exact_unique_headers() {
    let config = SameOriginPostConfig::parse("https://example.test:8443").expect("origin");
    let mut headers = HeaderMap::new();
    headers.insert(
        ORIGIN,
        HeaderValue::from_static("https://example.test:8443"),
    );
    assert!(request_is_same_origin(&headers, &config));
    headers.insert(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-origin"),
    );
    assert!(request_is_same_origin(&headers, &config));

    for value in [
        "https://example.test",
        "null",
        "https://example.test:8443, https://other.test",
    ] {
        let mut rejected = HeaderMap::new();
        rejected.insert(ORIGIN, HeaderValue::from_str(value).expect("header"));
        assert!(!request_is_same_origin(&rejected, &config));
    }
    for fetch in ["same-site", "cross-site", "none", "Same-Origin"] {
        let mut rejected = HeaderMap::new();
        rejected.insert(
            ORIGIN,
            HeaderValue::from_static("https://example.test:8443"),
        );
        rejected.insert(
            HeaderName::from_static("sec-fetch-site"),
            HeaderValue::from_str(fetch).expect("header"),
        );
        assert!(!request_is_same_origin(&rejected, &config));
    }

    let mut duplicate_origin = HeaderMap::new();
    duplicate_origin.append(
        ORIGIN,
        HeaderValue::from_static("https://example.test:8443"),
    );
    duplicate_origin.append(
        ORIGIN,
        HeaderValue::from_static("https://example.test:8443"),
    );
    assert!(!request_is_same_origin(&duplicate_origin, &config));

    let mut duplicate_fetch = HeaderMap::new();
    duplicate_fetch.insert(
        ORIGIN,
        HeaderValue::from_static("https://example.test:8443"),
    );
    duplicate_fetch.append(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-origin"),
    );
    duplicate_fetch.append(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-origin"),
    );
    assert!(!request_is_same_origin(&duplicate_fetch, &config));
}

#[test]
fn cookie_parser_matrix_rejects_ambiguity_and_malformed_unrelated_pairs() {
    let cases = [
        ("other=ok; target=value", Ok("value")),
        ("target=value; other=ok", Ok("value")),
        (" target=value ", Ok("value")),
        ("target=", Err(CookieParseError::Malformed)),
        ("target=\"value\"", Err(CookieParseError::Malformed)),
        ("target=one; target=two", Err(CookieParseError::Duplicate)),
        ("target=one=two", Ok("one=two")),
        ("other=base64==; target=value", Ok("value")),
        ("other; target=value", Err(CookieParseError::Malformed)),
        (
            "other=has space; target=value",
            Err(CookieParseError::Malformed),
        ),
        ("other=ok;", Err(CookieParseError::Malformed)),
    ];
    for (raw, expected) in cases {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_str(raw).expect("header"));
        let actual = extract_target_cookie(&headers, "target");
        match expected {
            Ok(value) => assert_eq!(actual.expect(raw), value),
            Err(error) => assert_eq!(actual.unwrap_err(), error, "{raw}"),
        }
    }

    let mut duplicate_fields = HeaderMap::new();
    duplicate_fields.append(COOKIE, HeaderValue::from_static("target=one"));
    duplicate_fields.append(COOKIE, HeaderValue::from_static("target=two"));
    assert_eq!(
        extract_target_cookie(&duplicate_fields, "target").unwrap_err(),
        CookieParseError::Duplicate
    );

    let mut too_many = HeaderMap::new();
    for _ in 0..=MAX_COOKIE_HEADER_FIELDS {
        too_many.append(COOKIE, HeaderValue::from_static("other=ok"));
    }
    assert_eq!(
        extract_target_cookie(&too_many, "target").unwrap_err(),
        CookieParseError::Oversized
    );

    let mut oversized = HeaderMap::new();
    oversized.insert(
        COOKIE,
        HeaderValue::from_str(&format!(
            "target={}",
            "a".repeat(MAX_SELECTED_COOKIE_VALUE_BYTES + 1)
        ))
        .expect("header"),
    );
    assert_eq!(
        extract_target_cookie(&oversized, "target").unwrap_err(),
        CookieParseError::Oversized
    );
}

#[tokio::test]
async fn request_handler_preserves_generic_success_regression() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(
            r#"{"email":"user@example.com","locale":"en","terms_accepted":true,"privacy_accepted":true}"#,
        ))
        .expect("request");
    let response = handle_magic_link_request_json(request, |command| async move {
        assert_eq!(command.email().as_str(), "user@example.com");
        Ok(RequestMagicLinkOutcome)
    })
    .await;
    let (status, _, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, br#"{"status":"ok"}"#);
}

#[tokio::test]
async fn unknown_request_field_is_rejected_generically_without_reflection() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(
            r#"{"email":"user@example.com","locale":"en","terms_accepted":true,"privacy_accepted":true,"unexpected":"unknown-value-sentinel"}"#,
        ))
        .expect("request");
    let response = handle_magic_link_request_json(request, |_| async {
        unreachable!("unknown request fields must not reach the service")
    })
    .await;
    let (status, _, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        br#"{"error":"bad_request","message":"Invalid request."}"#
    );
    assert!(
        !body
            .windows(b"unknown-value-sentinel".len())
            .any(|window| window == b"unknown-value-sentinel")
    );
}

#[tokio::test]
async fn valid_landing_html_identifies_and_escapes_account_without_raw_token() {
    let config = scanner_config();
    let response = build_valid_landing_response(
        "user<&>\"'@example.test",
        "confirmation-handle",
        "encrypted-flow-cookie",
        123,
        &config,
    );
    let (status, headers, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get_all(SET_COOKIE).iter().count(), 1);
    let set_cookie = headers.get(SET_COOKIE).expect("flow set cookie");
    assert!(
        set_cookie
            .as_bytes()
            .starts_with(b"dd_auth_flow=encrypted-flow-cookie")
    );
    let text = String::from_utf8(body).expect("utf8");
    assert!(text.contains("user&lt;&amp;&gt;&quot;&#39;@example.test"));
    assert!(!text.contains("user<&>\"'@example.test"));
    assert!(text.contains("name=\"confirmation\" value=\"confirmation-handle\""));
    assert_eq!(text.matches("type=\"hidden\"").count(), 1);
    assert!(text.contains("Continue sign in"));
    assert!(!text.contains("name=\"token\""));
    assert!(!text.contains("raw-token-secret"));
    assert!(!text.contains("encrypted-flow-cookie"));
}

#[tokio::test]
async fn request_handler_forwards_false_consent_to_service_behavior() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(
            r#"{"email":"user@example.com","locale":"en","terms_accepted":false,"privacy_accepted":true}"#,
        ))
        .expect("request");
    let response = handle_magic_link_request_json(request, |command| async move {
        assert!(!command.terms_accepted());
        assert!(command.privacy_accepted());
        Err(MagicLinkServiceError::BadRequest)
    })
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn guarded_body_debug_redacts_all_body_bytes() {
    let secret_body = r#"{"email":"sensitive@example.test","opaque_secret":"body-secret","confirmation":"confirmation-secret"}"#;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(secret_body))
        .expect("request");
    let guarded = guarded_body(request, &[APPLICATION_JSON], MAX_MAGIC_LINK_BODY_BYTES)
        .await
        .expect("guarded");
    let debug = format!("{guarded:?}");
    assert_eq!(debug, "GuardedBody(..)");
    for sentinel in [
        "sensitive@example.test",
        "body-secret",
        "confirmation-secret",
    ] {
        assert!(!debug.contains(sentinel));
    }
}

#[tokio::test]
async fn oversized_declared_content_length_is_rejected_before_body_read() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .header(CONTENT_LENGTH, (MAX_MAGIC_LINK_BODY_BYTES + 1).to_string())
        .body(Body::empty())
        .expect("request");
    assert_eq!(
        guarded_body(request, &[APPLICATION_JSON], MAX_MAGIC_LINK_BODY_BYTES)
            .await
            .unwrap_err(),
        MagicLinkHttpError::PayloadTooLarge
    );
}

#[tokio::test]
async fn invalid_landing_is_non_actionable_and_clears_temporary_state() {
    let config = scanner_config();
    let called = Rc::new(Cell::new(false));
    let closure_called = Rc::clone(&called);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/magic-link?token=not-a-token")
        .body(Body::from("body-must-not-be-read"))
        .expect("request");
    let response = handle_magic_link_landing(request, &config, move |_command| {
        closure_called.set(true);
        async { Err(bad_request_flow_error()) }
    })
    .await;
    assert!(called.get());
    let (status, headers, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).expect("utf8");
    assert!(!text.contains("<form"));
    assert!(!text.contains("confirmation"));
    assert!(!text.contains("not-a-token"));
    assert_eq!(headers.get_all(SET_COOKIE).iter().count(), 1);
    assert!(headers.get("content-security-policy").is_some());
}

#[tokio::test]
async fn origin_rejection_precedes_cookie_body_and_service_and_does_not_clear() {
    let config = scanner_config();
    for setup in ["missing", "mismatch", "duplicate", "bad-fetch"] {
        let called = Rc::new(Cell::new(false));
        let closure_called = Rc::clone(&called);
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/auth/magic-link/confirm")
            .header(CONTENT_TYPE, "text/plain")
            .header(COOKIE, "malformed");
        builder = match setup {
            "mismatch" => builder.header(ORIGIN, "https://other.test"),
            "bad-fetch" => builder
                .header(ORIGIN, "https://example.test")
                .header("sec-fetch-site", "same-site"),
            _ => builder,
        };
        let mut request = builder
            .body(Body::from("oversized-not-read"))
            .expect("request");
        if setup == "duplicate" {
            request
                .headers_mut()
                .append(ORIGIN, HeaderValue::from_static("https://example.test"));
            request
                .headers_mut()
                .append(ORIGIN, HeaderValue::from_static("https://example.test"));
        }
        let response = handle_magic_link_confirmation(request, &config, move |_command| {
            closure_called.set(true);
            async { Err(bad_request_flow_error()) }
        })
        .await;
        assert!(!called.get(), "{setup}");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers().get_all(SET_COOKIE).iter().count(), 0);
        assert!(response.headers().get("cache-control").is_some());
    }
}

#[tokio::test]
async fn confirmation_success_is_clean_303_with_fixed_cookie_order() {
    let config = scanner_config();
    let response = build_confirmation_success_response("session-secret", &config);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(LOCATION).expect("location"),
        "/signed-in"
    );
    assert!(response.headers().get("cache-control").is_some());
    let cookies: Vec<&[u8]> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies[0].starts_with(b"dd_session=session-secret"));
    assert!(cookies[1].starts_with(b"dd_auth_flow=;"));
    let (_, headers, body) = response_parts(response).await;
    assert!(body.is_empty());
    assert!(
        !headers
            .get(LOCATION)
            .expect("location")
            .as_bytes()
            .contains(&b'?')
    );
}

#[tokio::test]
async fn handler_internal_clears_but_unavailable_preserves_temporary_state() {
    let config = scanner_config();
    for (kind, expected_status, expected_clears) in [
        (
            FixtureFlowError::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
        ),
        (
            FixtureFlowError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            0,
        ),
    ] {
        let response = handle_magic_link_confirmation(
            post_request(APPLICATION_JSON, Body::from(r#"{"confirmation":"x"}"#)),
            &config,
            move |_command| async move { Err(fixture_flow_error(kind).await) },
        )
        .await;
        assert_eq!(response.status(), expected_status);
        assert_eq!(
            response.headers().get_all(SET_COOKIE).iter().count(),
            expected_clears
        );
        assert!(response.headers().get("cache-control").is_some());
        assert!(response.headers().get("content-security-policy").is_some());
    }
}

#[tokio::test]
async fn terminal_invalid_confirmation_responses_are_byte_identical() {
    let config = scanner_config();
    let mut responses = Vec::new();

    for cookie in [
        None,
        Some("dd_auth_flow="),
        Some("malformed"),
        Some("dd_auth_flow=one; dd_auth_flow=two"),
    ] {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/auth/magic-link/confirm")
            .header(ORIGIN, "https://example.test")
            .header(CONTENT_TYPE, APPLICATION_JSON);
        if let Some(cookie) = cookie {
            builder = builder.header(COOKIE, cookie);
        }
        let request = builder
            .body(Body::from(r#"{"confirmation":"x"}"#))
            .expect("request");
        responses.push(
            handle_magic_link_confirmation(request, &config, |_| async {
                unreachable!("service must not run")
            })
            .await,
        );
    }

    for (content_type, body) in [
        ("text/plain", Body::from("bad")),
        (APPLICATION_JSON, Body::empty()),
        (APPLICATION_JSON, Body::from("{")),
        (
            APPLICATION_JSON,
            Body::from(r#"{"confirmation":"x","token":"forbidden"}"#),
        ),
        (FORM_URLENCODED, Body::from(vec![0xff])),
        (FORM_URLENCODED, Body::from("country=HU")),
    ] {
        responses.push(
            handle_magic_link_confirmation(post_request(content_type, body), &config, |_| async {
                unreachable!("service must not run")
            })
            .await,
        );
    }

    responses.push(
        handle_magic_link_confirmation(
            post_request(APPLICATION_JSON, Body::from(r#"{"confirmation":"x"}"#)),
            &config,
            |_| async { Err(bad_request_flow_error()) },
        )
        .await,
    );
    responses.push(
        handle_magic_link_confirmation(
            post_request(APPLICATION_JSON, Body::from(r#"{"confirmation":"x"}"#)),
            &config,
            |_| async { Err(fixture_flow_error(FixtureFlowError::MagicLinkUnavailable).await) },
        )
        .await,
    );

    let mut fingerprints = Vec::new();
    for response in responses {
        let (status, headers, body) = response_parts(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, TERMINAL_INVALID_BODY.as_bytes());
        assert_eq!(headers.get_all(SET_COOKIE).iter().count(), 1);
        assert!(headers.get(LOCATION).is_none());
        fingerprints.push(terminal_fingerprint(status, &headers, &body));
    }
    for fingerprint in &fingerprints[1..] {
        assert_eq!(fingerprint, &fingerprints[0]);
    }
}

#[tokio::test]
async fn body_stream_cap_applies_without_content_length() {
    let config = scanner_config();
    let body = Body::from(vec![b'a'; MAX_MAGIC_LINK_BODY_BYTES + 1]);
    let response =
        handle_magic_link_confirmation(post_request(APPLICATION_JSON, body), &config, |_| async {
            unreachable!("service must not run")
        })
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers().get_all(SET_COOKIE).iter().count(), 1);
}

#[tokio::test]
async fn session_auth_parser_skips_dependency_on_malformed_input() {
    let config = SessionCookieConfig::production(&policy()).expect("session");
    let mut malformed_headers = Vec::new();
    for cookie in [
        None,
        Some(""),
        Some("dd_session="),
        Some("dd_session=\"quoted\""),
        Some("other=x"),
    ] {
        let mut headers = HeaderMap::new();
        if let Some(cookie) = cookie
            && !cookie.is_empty()
        {
            headers.insert(COOKIE, HeaderValue::from_str(cookie).expect("cookie"));
        }
        malformed_headers.push(headers);
    }
    let mut duplicate = HeaderMap::new();
    duplicate.append(COOKIE, HeaderValue::from_static("dd_session=one"));
    duplicate.append(COOKIE, HeaderValue::from_static("dd_session=two"));
    malformed_headers.push(duplicate);

    let mut fingerprints = Vec::new();
    for headers in malformed_headers {
        let called = Rc::new(Cell::new(false));
        let closure_called = Rc::clone(&called);
        let rejection = authenticate_session(&headers, &config, move |_cookie| {
            closure_called.set(true);
            async { Err(SessionValidationError::Internal) }
        })
        .await
        .expect_err("rejection");
        assert!(!called.get());
        let (status, headers, body) = response_parts(rejection.into_response()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers.get_all(SET_COOKIE).iter().count(), 1);
        fingerprints.push((status, headers, body));
    }
    let first = &fingerprints[0];
    for fingerprint in &fingerprints[1..] {
        assert_eq!(fingerprint, first);
    }
}

#[tokio::test]
async fn session_auth_maps_invalid_unavailable_and_internal_dispositions() {
    let config = SessionCookieConfig::production(&policy()).expect("session");
    let cases = [
        (
            SessionValidationError::InvalidSession,
            StatusCode::UNAUTHORIZED,
            1,
        ),
        (
            SessionValidationError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            0,
        ),
        (
            SessionValidationError::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
            0,
        ),
    ];
    for (error, status, clear_count) in cases {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("dd_session=secret-cookie"));
        let called = Rc::new(Cell::new(false));
        let closure_called = Rc::clone(&called);
        let rejection = authenticate_session(&headers, &config, move |cookie| {
            closure_called.set(true);
            assert_eq!(cookie.as_str(), "secret-cookie");
            assert!(!format!("{cookie:?}").contains("secret-cookie"));
            async move { Err(error) }
        })
        .await
        .expect_err("rejection");
        assert!(called.get());
        assert_eq!(format!("{rejection:?}"), "SessionAuthRejection(..)");
        let response = rejection.into_response();
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get_all(SET_COOKIE).iter().count(),
            clear_count
        );
    }
}

#[tokio::test]
async fn guarded_body_and_country_regressions_remain_strict() {
    let wrong = Request::builder()
        .method(Method::POST)
        .uri("/auth")
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from("{}"))
        .expect("request");
    assert_eq!(
        guarded_body(wrong, &[APPLICATION_JSON], MAX_MAGIC_LINK_BODY_BYTES)
            .await
            .unwrap_err(),
        MagicLinkHttpError::UnsupportedMediaType
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("Application/JSON; charset=utf-8"),
    );
    headers.insert(
        HeaderName::from_static(CLOUDFRONT_VIEWER_COUNTRY),
        HeaderValue::from_static("HU"),
    );
    assert!(content_type_matches(&headers, APPLICATION_JSON));
    assert_eq!(viewer_country(&headers).as_deref(), Some("HU"));
    headers.insert(
        HeaderName::from_static(CLOUDFRONT_VIEWER_COUNTRY),
        HeaderValue::from_static("hu"),
    );
    assert_eq!(viewer_country(&headers), None);
}

#[test]
fn general_service_error_mapping_remains_stable() {
    let cases = [
        (MagicLinkServiceError::BadRequest, StatusCode::BAD_REQUEST),
        (
            MagicLinkServiceError::MagicLinkUnavailable,
            StatusCode::BAD_REQUEST,
        ),
        (
            MagicLinkServiceError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            MagicLinkServiceError::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];
    for (service, status) in cases {
        assert_eq!(MagicLinkHttpError::from(service).status(), status);
    }
}
