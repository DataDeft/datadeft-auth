use super::*;
use crate::test_fixtures::policy;

#[test]
fn scanner_config_checks_every_cookie_collision_and_path_boundary() {
    let post = SameOriginRedirect::parse("/auth/confirm?fixed=1").expect("post");
    let redirect = SameOriginRedirect::parse("/done").expect("redirect");
    let origin = SameOriginPostConfig::parse("https://example.test").expect("origin");
    let session = SessionCookieConfig::production(&policy()).expect("session");

    for path in ["/auth/confirm", "/auth/", "/auth"] {
        let temporary = TemporaryCookieConfig::production("flow", path).expect("flow");
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
    let false_prefix = TemporaryCookieConfig::production("flow", "/aut").expect("flow");
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
    let temporary = TemporaryCookieConfig::production("flow", "/auth").expect("flow");
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
