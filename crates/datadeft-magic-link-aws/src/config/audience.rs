//! Startup audience binding without changing the secret-manager document shape.

use datadeft_magic_link_service::{Audience, TokenError};

use super::LoadedAuthSecrets;

impl LoadedAuthSecrets {
    /// Bind both session and confirmation keyrings to one trusted audience.
    ///
    /// Call once at startup after loading secrets, before borrowing either
    /// keyring for the auth service. Active and previous slots are scoped
    /// together. HMAC lookup/storage keys and independent PoW secrets are
    /// unchanged. A second call is a setup error, not another derivation.
    ///
    /// All nodes and mint/validation/refresh/logout paths must use the same
    /// audience. Enabling or changing it invalidates existing session and flow
    /// cookies; unscoped verification is never attempted. Shared root-secret
    /// holders are still trusted, and this does not replace authorization.
    pub fn with_audience(mut self, audience: &Audience) -> Result<Self, TokenError> {
        // Startup-only builder: the core error keeps its signal (for example
        // KeyringMisconfigured on rebinding) instead of collapsing to an
        // opaque adapter-internal failure.
        self.session_keyring = self.session_keyring.with_audience(audience)?;
        self.confirm_keyring = self.confirm_keyring.with_audience(audience)?;
        Ok(self)
    }
}
