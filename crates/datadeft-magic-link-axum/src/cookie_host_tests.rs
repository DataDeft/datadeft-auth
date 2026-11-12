use super::*;
use crate::test_fixtures::policy;

#[test]
fn host_session_headers_preserve_set_clear_attributes_and_selected_name() {
    let config = SessionCookieConfig::secure(&policy())
        .expect("secure")
        .with_name("__Host-dd_session")
        .expect("host name")
        .with_path("/")
        .expect("root")
        .with_same_site(SameSite::Strict)
        .expect("same-site");
    let set = session_set_cookie_header(&config, "fixture-value").expect("set");
    let clear = clear_session_cookie_header(&config);
    assert_eq!(config.name(), "__Host-dd_session");
    assert_eq!(
        set.to_str().expect("ascii"),
        "__Host-dd_session=fixture-value; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400"
    );
    assert_eq!(
        clear.to_str().expect("ascii"),
        "__Host-dd_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
    for header in [&set, &clear] {
        assert!(!header.to_str().expect("ascii").contains("Domain="));
    }
    assert_eq!(
        cookie_header(
            config.name(),
            "",
            "/",
            true,
            SameSite::Strict,
            Some(0),
            true
        )
        .expect("fresh clear"),
        clear
    );
}

#[test]
fn host_prefix_rejects_insecure_and_non_root_policies_in_both_builder_orders() {
    assert_eq!(
        SessionCookieConfig::insecure_local(&policy())
            .expect("local")
            .with_name("__Host-dd_session")
            .unwrap_err(),
        CookieConfigError::HostPrefixRequiresSecure
    );
    assert_eq!(
        SessionCookieConfig::secure(&policy())
            .expect("secure")
            .with_path("/app")
            .expect("ordinary path")
            .with_name("__Host-dd_session")
            .unwrap_err(),
        CookieConfigError::HostPrefixRequiresRootPath
    );
    assert_eq!(
        SessionCookieConfig::secure(&policy())
            .expect("secure")
            .with_name("__Host-dd_session")
            .expect("host name")
            .with_path("/app")
            .unwrap_err(),
        CookieConfigError::HostPrefixRequiresRootPath
    );
}

#[test]
fn host_names_require_exact_prefix_lower_snake_suffix_and_total_length_cap() {
    for name in [
        "__Host-",
        "__host-dd_session",
        "__HOST-dd_session",
        "__Host-DD_session",
        "__Host-1session",
        "__Host-dd-session",
        "__Host-dd_session;secure",
        "__Secure-dd_session",
        "__Host-ümlaut",
    ] {
        assert_eq!(
            SessionCookieConfig::secure(&policy())
                .expect("secure")
                .with_name(name)
                .unwrap_err(),
            CookieConfigError::InvalidName,
            "{name}"
        );
    }
    assert!(
        SessionCookieConfig::secure(&policy())
            .expect("secure")
            .with_name(format!("__Host-{}", "a".repeat(57)))
            .is_ok()
    );
    assert_eq!(
        SessionCookieConfig::secure(&policy())
            .expect("secure")
            .with_name(format!("__Host-{}", "a".repeat(58)))
            .unwrap_err(),
        CookieConfigError::InvalidName
    );
}

#[test]
fn incoming_host_name_is_exact_and_has_no_old_name_fallback() {
    use crate::cookie_parse::extract_target_cookie;
    use axum::http::{HeaderMap, header::COOKIE};

    let config = SessionCookieConfig::secure(&policy())
        .expect("secure")
        .with_name("__Host-dd_session")
        .expect("name");
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_static("dd_session=old; __Host-dd_session=current"),
    );
    assert_eq!(
        extract_target_cookie(&headers, config.name()).expect("selected"),
        "current"
    );
    for value in [
        "dd_session=old",
        "__host-dd_session=wrong-case",
        "__Host-dd_session=a; __Host-dd_session=b",
    ] {
        headers.insert(COOKIE, HeaderValue::from_static(value));
        assert!(extract_target_cookie(&headers, config.name()).is_err());
    }
}

#[test]
fn changing_host_policy_rebuilds_clear_headers_without_stale_attributes() {
    let config = SessionCookieConfig::secure(&policy())
        .expect("secure")
        .with_name("__Host-dd_session")
        .expect("host name")
        .with_same_site(SameSite::None)
        .expect("secure SameSite=None");
    assert_eq!(
        clear_session_cookie_header(&config)
            .to_str()
            .expect("ascii"),
        "__Host-dd_session=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
    let config = config
        .with_name("app_session")
        .expect("ordinary name")
        .with_path("/app")
        .expect("ordinary path");
    assert_eq!(
        clear_session_cookie_header(&config)
            .to_str()
            .expect("ascii"),
        "app_session=; Path=/app; HttpOnly; Secure; SameSite=None; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
}

#[test]
fn root_path_host_confirm_headers_preserve_set_clear_attributes() {
    let config = ConfirmCookieConfig::secure("__Host-dd_auth_confirm", "/")
        .expect("explicit root-path confirm policy");
    let set = set_confirm_cookie_header(&config, "fixture-value", 300).expect("set");
    assert_eq!(
        set.to_str().expect("ascii"),
        "__Host-dd_auth_confirm=fixture-value; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300"
    );
    assert_eq!(
        clear_confirm_cookie_header(&config)
            .to_str()
            .expect("ascii"),
        "__Host-dd_auth_confirm=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
}

#[test]
fn default_and_confirm_policies_do_not_silently_change_names() {
    assert_eq!(
        SessionCookieConfig::secure(&policy())
            .expect("secure")
            .name(),
        "dd_session"
    );
    let local = SessionCookieConfig::insecure_local(&policy()).expect("local");
    assert_eq!(local.name(), "dd_session");
    assert!(!local.is_secure());
    assert_eq!(
        ConfirmCookieConfig::secure_defaults().name(),
        "dd_auth_confirm"
    );
    // The prefix is policy-gated, not kind-gated: a confirm cookie may opt
    // in only when it satisfies the full __Host- invariants. The default
    // narrow /auth path therefore keeps confirm cookies unprefixed.
    assert!(ConfirmCookieConfig::secure("__Host-dd_auth_confirm", "/").is_ok());
    assert_eq!(
        ConfirmCookieConfig::secure("__Host-dd_auth_confirm", "/auth").unwrap_err(),
        CookieConfigError::HostPrefixRequiresRootPath
    );
    assert_eq!(
        ConfirmCookieConfig::insecure_local("__Host-dd_auth_confirm", "/").unwrap_err(),
        CookieConfigError::HostPrefixRequiresSecure
    );
}
