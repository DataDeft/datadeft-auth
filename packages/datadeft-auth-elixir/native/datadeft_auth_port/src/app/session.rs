//! Session admission, cookie refresh and logout handlers.

use datadeft_magic_link_service::{
    MagicLinkAuthenticationRepository, RateLimiter, SessionRepository, SessionValidationError,
    refresh_session_cookie, validate_session, validate_session_for_logout,
};
use rand_core::OsRng;

use super::handlers::{error, service_error};
use super::{App, WallClock};
use crate::protocol::{ErrorCode, ResultBody, SessionPayload};

impl<Store, Outbox> App<Store, Outbox>
where
    Store: MagicLinkAuthenticationRepository + SessionRepository + RateLimiter,
{
    pub(super) async fn validate(&self, payload: SessionPayload) -> ResultBody {
        match validate_session(
            &payload.session_cookie,
            payload.country.as_deref(),
            &self.shared.session_keyring,
            &self.store,
            &WallClock,
            &self.shared.config,
        )
        .await
        {
            Ok(validated) => {
                let mut rng = OsRng;
                // Validation already checked expiry, country, owner and
                // revocation. A failed best-effort refresh (for example an
                // expired mint window) must not invalidate that session.
                let refreshed = refresh_session_cookie(
                    &validated,
                    &self.shared.session_keyring,
                    &mut rng,
                    &WallClock,
                    &self.shared.config,
                )
                .ok()
                .flatten();
                let session = validated.session();
                ResultBody::ValidateSession {
                    valid: true,
                    user_id: Some(session.user_id.as_str().to_owned()),
                    email: Some(session.email.as_str().to_owned()),
                    refreshed_cookie: refreshed.map(|cookie| cookie.as_secret_value().to_owned()),
                }
            }
            Err(SessionValidationError::InvalidSession) => ResultBody::ValidateSession {
                valid: false,
                user_id: None,
                email: None,
                refreshed_cookie: None,
            },
            Err(failure) => session_error(failure),
        }
    }

    // The country lock does not apply: any authentic, live session is revoked,
    // so logging out from another country cannot leave a copied cookie live.
    // `payload.country` is accepted for symmetry with validation and ignored.
    pub(super) async fn logout(&self, payload: SessionPayload) -> ResultBody {
        match validate_session_for_logout(
            &payload.session_cookie,
            &self.shared.session_keyring,
            &self.store,
            &WallClock,
            &self.shared.config,
        )
        .await
        {
            Ok(session) => {
                let mut rng = OsRng;
                // Revoke server state first; the application clears its
                // cookie only after this reply.
                match self
                    .flow_service(&mut rng)
                    .revoke_session(&session.session_id)
                    .await
                {
                    Ok(()) => ResultBody::Logout { revoked: true },
                    Err(failure) => service_error(failure),
                }
            }
            Err(SessionValidationError::InvalidSession) => ResultBody::Logout { revoked: false },
            Err(failure) => session_error(failure),
        }
    }
}

fn session_error(failure: SessionValidationError) -> ResultBody {
    error(match failure {
        // Stale-validation refusals cannot happen in one job; fail loud.
        SessionValidationError::InvalidSession | SessionValidationError::Internal => {
            ErrorCode::Internal
        }
        SessionValidationError::Unavailable => ErrorCode::Unavailable,
    })
}
