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
}

impl fmt::Display for MagicLinkScannerFlowConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DuplicateCookieName => "confirm cookie names must be pairwise distinct",
            Self::ConfirmCookiePathDoesNotCoverPostAction => {
                "confirm cookie path does not cover confirmation action"
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
        })
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
