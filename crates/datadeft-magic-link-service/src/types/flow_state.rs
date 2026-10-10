//! Read-only flow state of the redirect landing mode.

use core::fmt;

use datadeft_magic_link_core::confirm_cookie::MagicLinkConfirmationValue;
use zeroize::Zeroize;

use super::MagicLinkAccountIdentity;

/// Read-only flow-state request of the redirect landing mode: only the
/// confirm cookie.
pub struct ReadMagicLinkFlowStateCommand {
    confirm_cookie: String,
}

impl ReadMagicLinkFlowStateCommand {
    /// The confirm cookie's value, as read from the request.
    #[must_use]
    pub fn new(confirm_cookie: String) -> Self {
        Self { confirm_cookie }
    }

    pub(crate) fn confirm_cookie(&self) -> &str {
        &self.confirm_cookie
    }
}

impl fmt::Debug for ReadMagicLinkFlowStateCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReadMagicLinkFlowStateCommand(..)")
    }
}

impl Drop for ReadMagicLinkFlowStateCommand {
    fn drop(&mut self) {
        self.confirm_cookie.zeroize();
    }
}

/// What a same-origin confirm page needs: the account it signs in to, and the
/// confirmation value to submit with the POST.
pub struct MagicLinkFlowState {
    pub(crate) account_identity: MagicLinkAccountIdentity,
    pub(crate) confirmation: MagicLinkConfirmationValue,
}

impl MagicLinkFlowState {
    /// The account the confirmation signs in to; show it on the page.
    #[must_use]
    pub fn account_identity(&self) -> &MagicLinkAccountIdentity {
        &self.account_identity
    }

    /// The value the page submits with the confirmation `POST`.
    #[must_use]
    pub fn confirmation_value(&self) -> &str {
        self.confirmation.as_value()
    }
}

impl fmt::Debug for MagicLinkFlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkFlowState(..)")
    }
}
