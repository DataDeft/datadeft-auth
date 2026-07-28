use axum::http::HeaderName;

use super::*;
use crate::test_fixtures::{policy, scanner_config};

#[test]
fn country_header_defaults_to_cloudfront_and_is_configurable() {
    let config = scanner_config();
    assert_eq!(
        config.country_header().as_str(),
        "cloudfront-viewer-country"
    );

    let cloudflare = scanner_config().with_country_header(HeaderName::from_static("cf-ipcountry"));
    assert_eq!(cloudflare.country_header().as_str(), "cf-ipcountry");
}

#[test]
fn scanner_config_checks_every_cookie_collision_and_path_boundary() {
    let post = SameOriginRedirect::parse("/auth/confirm?fixed=1").expect("post");
    let origin = SameOriginPostConfig::parse("https://example.test").expect("origin");
    let session = SessionCookieConfig::production(&policy()).expect("session");

    for path in ["/auth/confirm", "/auth/", "/auth"] {
        let temporary = TemporaryCookieConfig::production("flow", path).expect("flow");
        assert!(
            MagicLinkScannerFlowConfig::new(
                post.clone(),
                origin.clone(),
                session.clone(),
                temporary,
            )
            .is_ok()
        );
    }
    let false_prefix = TemporaryCookieConfig::production("flow", "/aut").expect("flow");
    assert_eq!(
        MagicLinkScannerFlowConfig::new(
            post.clone(),
            origin.clone(),
            session.clone(),
            false_prefix,
        )
        .unwrap_err(),
        MagicLinkScannerFlowConfigError::FlowCookiePathDoesNotCoverPostAction
    );

    let session_flow = session.clone().with_name("flow").expect("session name");
    let temporary = TemporaryCookieConfig::production("flow", "/auth").expect("flow");
    assert_eq!(
        MagicLinkScannerFlowConfig::new(post.clone(), origin.clone(), session_flow, temporary,)
            .unwrap_err(),
        MagicLinkScannerFlowConfigError::DuplicateCookieName
    );
}
