//! User lookup for admin callers authorized by the application.

use datadeft_magic_link_service::{AuthAdminRepository, MagicLinkServiceError, UserId};

use super::App;
use super::handlers::{error, service_error};
use crate::protocol::{ErrorCode, GetUserPayload, ResultBody};

impl<Store, Outbox> App<Store, Outbox>
where
    Store: AuthAdminRepository,
{
    /// An admin query: the account email and status of one user by id. The
    /// application authorizes the caller; a malformed id is `bad_request`,
    /// an unknown one `found: false`.
    pub(super) async fn get_user(&self, payload: GetUserPayload) -> ResultBody {
        let Ok(user_id) = UserId::parse(&payload.user_id) else {
            return error(ErrorCode::BadRequest);
        };
        match self.store.get_user(&user_id).await {
            Ok(Some(user)) => ResultBody::GetUser {
                found: true,
                email: Some(user.email.as_str().to_owned()),
                disabled: Some(user.disabled),
            },
            Ok(None) => ResultBody::GetUser {
                found: false,
                email: None,
                disabled: None,
            },
            // The service crate's own store-failure rule.
            Err(failure) => service_error(MagicLinkServiceError::from(failure)),
        }
    }
}
