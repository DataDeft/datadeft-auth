//! Fully validated scanner-safe HTTP flow configuration combining redirect,
//! origin, and cookie policies.

use core::fmt;

use axum::http::HeaderName;

use crate::cookie::{ConfirmCookieConfig, SessionCookieConfig, cookie_path_covers};
use crate::extract::CLOUDFRONT_VIEWER_COUNTRY;
use crate::origin::{SameOriginPostConfig, SameOriginRedirect};

/// Typed scanner-flow setup failures.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkScannerFlowConfigError {
    DuplicateCookieName,
    ConfirmCookiePathDoesNotCoverPostAction,
    /// The confirm cookie's `Path` does not cover the flow-state route, so
    /// the browser would not send it there.
    ConfirmCookiePathDoesNotCoverFlowState,
}

impl fmt::Display for MagicLinkScannerFlowConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DuplicateCookieName => "confirm cookie names must be pairwise distinct",
            Self::ConfirmCookiePathDoesNotCoverPostAction => {
                "confirm cookie path does not cover confirmation action"
            }
            Self::ConfirmCookiePathDoesNotCoverFlowState => {
                "confirm cookie path does not cover the flow-state route"
            }
        })
    }
}

impl std::error::Error for MagicLinkScannerFlowConfigError {}

/// Fully validated scanner-safe HTTP configuration.
///
/// `post_action` is the same-origin path the confirmation form/POST targets.
/// The caller renders it, and the config validates it against the confirm-cookie
/// path. The post-login redirect is the caller's concern in the headless
/// helpers, so it is not part of this config.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MagicLinkScannerFlowConfig {
    post_action: SameOriginRedirect,
    same_origin_post: SameOriginPostConfig,
    session_cookie: SessionCookieConfig,
    confirm_cookie: ConfirmCookieConfig,
    country_header: HeaderName,
    redirect_landing: Option<RedirectLanding>,
}

/// The redirect landing mode's two routes: the static confirm page the
/// landing redirects to, and the flow-state route that page reads.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RedirectLanding {
    page: SameOriginRedirect,
    flow_state: SameOriginRedirect,
}

impl RedirectLanding {
    /// The same-origin static confirm page every landing outcome redirects to.
    #[must_use]
    pub fn page(&self) -> &SameOriginRedirect {
        &self.page
    }

    /// The same-origin flow-state route the page reads (`GET`).
    #[must_use]
    pub fn flow_state(&self) -> &SameOriginRedirect {
        &self.flow_state
    }
}

impl MagicLinkScannerFlowConfig {
    pub fn new(
        post_action: SameOriginRedirect,
        same_origin_post: SameOriginPostConfig,
        session_cookie: SessionCookieConfig,
        confirm_cookie: ConfirmCookieConfig,
    ) -> Result<Self, MagicLinkScannerFlowConfigError> {
        let flow_name = confirm_cookie.name();
        if session_cookie.name() == flow_name {
            return Err(MagicLinkScannerFlowConfigError::DuplicateCookieName);
        }
        let request_path = post_action
            .as_str()
            .split_once('?')
            .map_or(post_action.as_str(), |(path, _)| path);
        if !cookie_path_covers(confirm_cookie.path(), request_path) {
            return Err(MagicLinkScannerFlowConfigError::ConfirmCookiePathDoesNotCoverPostAction);
        }
        Ok(Self {
            post_action,
            same_origin_post,
            session_cookie,
            confirm_cookie,
            country_header: HeaderName::from_static(CLOUDFRONT_VIEWER_COUNTRY),
            redirect_landing: None,
        })
    }

    /// Enable the redirect landing mode (docs/security.md, "Redirect landing
    /// mode"): the landing answers `303` to `page` for every outcome, and the
    /// static page reads `{ account, confirmation }` from `flow_state`. The
    /// confirm cookie's `Path` must cover `flow_state` as well as the POST
    /// action.
    pub fn with_redirect_landing(
        mut self,
        page: SameOriginRedirect,
        flow_state: SameOriginRedirect,
    ) -> Result<Self, MagicLinkScannerFlowConfigError> {
        let path = flow_state
            .as_str()
            .split_once('?')
            .map_or(flow_state.as_str(), |(path, _)| path);
        if !cookie_path_covers(self.confirm_cookie.path(), path) {
            return Err(MagicLinkScannerFlowConfigError::ConfirmCookiePathDoesNotCoverFlowState);
        }
        self.redirect_landing = Some(RedirectLanding { page, flow_state });
        Ok(self)
    }

    /// The redirect landing mode's routes, when enabled.
    #[must_use]
    pub fn redirect_landing(&self) -> Option<&RedirectLanding> {
        self.redirect_landing.as_ref()
    }

    /// Use a different trusted-edge country header (for example Cloudflare's
    /// `cf-ipcountry`). Country binding is opportunistic: when the header is
    /// present, the flow validates it and binds it into the session. When it is
    /// absent, the flow proceeds without a country. The header is only
    /// trustworthy if the
    /// edge strips or overwrites it on every request and the origin is not
    /// directly reachable.
    #[must_use]
    pub fn with_country_header(mut self, name: HeaderName) -> Self {
        self.country_header = name;
        self
    }

    /// The trusted-edge header consulted for the viewer country.
    #[must_use]
    pub fn country_header(&self) -> &HeaderName {
        &self.country_header
    }

    #[must_use]
    pub fn post_action(&self) -> &SameOriginRedirect {
        &self.post_action
    }

    #[must_use]
    pub fn same_origin_post(&self) -> &SameOriginPostConfig {
        &self.same_origin_post
    }

    #[must_use]
    pub fn session_cookie(&self) -> &SessionCookieConfig {
        &self.session_cookie
    }

    #[must_use]
    pub fn confirm_cookie(&self) -> &ConfirmCookieConfig {
        &self.confirm_cookie
    }
}

#[cfg(test)]
#[path = "scanner_config_tests.rs"]
mod tests;
