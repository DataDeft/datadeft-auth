use super::*;
use crate::test_fixtures::policy;

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
        (FlowCookieConfig::production_defaults()),
        (FlowCookieConfig::local_development_defaults()),
        (FlowCookieConfig::production("custom_flow", "/custom").expect("custom flow")),
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
        assert_eq!(clear_flow_cookie_header(&flow), fresh);
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
fn flow_cookie_defaults_lifetime_and_clear_are_strict() {
    let production = FlowCookieConfig::production_defaults();
    let flow = &production;
    assert_eq!(flow.name(), "dd_auth_flow");
    assert_eq!(flow.path(), "/auth");
    assert!(flow.secure());
    assert_eq!(flow.same_site(), SameSite::Lax);

    let set = set_flow_cookie_header(flow, "flow-value", 300)
        .expect("set")
        .to_str()
        .expect("ascii")
        .to_owned();
    let clear = clear_flow_cookie_header(flow)
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
    assert!(set_flow_cookie_header(flow, "flow-value", 0).is_err());
    assert!(set_flow_cookie_header(flow, "flow-value", 301).is_err());

    let local = FlowCookieConfig::local_development_defaults();
    assert!(!local.secure());
}

#[test]
fn cookie_setup_rejects_invalid_paths() {
    for path in [
        "auth", "/auth?x", "/auth#x", "/auth%x", "/auth\\x", "/auth;x",
    ] {
        assert_eq!(
            FlowCookieConfig::production("flow", path).unwrap_err(),
            CookieConfigError::InvalidPath
        );
    }
}
