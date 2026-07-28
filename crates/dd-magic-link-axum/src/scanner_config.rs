//! Fully validated scanner-safe HTTP flow configuration combining redirect,
//! origin, and cookie policies.

use core::fmt;

use crate::cookie::{SessionCookieConfig, TemporaryCookieConfig, cookie_path_covers};
use crate::origin::{SameOriginPostConfig, SameOriginRedirect};

/// Typed scanner-flow setup failures.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkScannerFlowConfigError {
    DuplicateCookieName,
    FlowCookiePathDoesNotCoverPostAction,
}

impl fmt::Display for MagicLinkScannerFlowConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DuplicateCookieName => "scanner cookie names must be pairwise distinct",
            Self::FlowCookiePathDoesNotCoverPostAction => {
                "flow cookie path does not cover confirmation action"
            }
        })
    }
}

impl std::error::Error for MagicLinkScannerFlowConfigError {}

/// Fully validated scanner-safe HTTP configuration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MagicLinkScannerFlowConfig {
    post_action: SameOriginRedirect,
    success_redirect: SameOriginRedirect,
    same_origin_post: SameOriginPostConfig,
    session_cookie: SessionCookieConfig,
    temporary_cookies: TemporaryCookieConfig,
}

impl MagicLinkScannerFlowConfig {
    pub fn new(
        post_action: SameOriginRedirect,
        success_redirect: SameOriginRedirect,
        same_origin_post: SameOriginPostConfig,
        session_cookie: SessionCookieConfig,
        temporary_cookies: TemporaryCookieConfig,
    ) -> Result<Self, MagicLinkScannerFlowConfigError> {
        let flow_name = temporary_cookies.name();
        if session_cookie.name() == flow_name {
            return Err(MagicLinkScannerFlowConfigError::DuplicateCookieName);
        }
        let request_path = post_action
            .as_str()
            .split_once('?')
            .map_or(post_action.as_str(), |(path, _)| path);
        if !cookie_path_covers(temporary_cookies.path(), request_path) {
            return Err(MagicLinkScannerFlowConfigError::FlowCookiePathDoesNotCoverPostAction);
        }
        Ok(Self {
            post_action,
            success_redirect,
            same_origin_post,
            session_cookie,
            temporary_cookies,
        })
    }

    #[must_use]
    pub fn post_action(&self) -> &SameOriginRedirect {
        &self.post_action
    }

    #[must_use]
    pub fn success_redirect(&self) -> &SameOriginRedirect {
        &self.success_redirect
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
    pub fn temporary_cookies(&self) -> &TemporaryCookieConfig {
        &self.temporary_cookies
    }
}

#[cfg(test)]
#[path = "scanner_config_tests.rs"]
mod tests;
