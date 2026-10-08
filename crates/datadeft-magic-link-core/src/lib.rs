//! `datadeft-magic-link-core`: IO-free magic-link primitives.
//!
//! Owns the token grammar, selector/verifier types, parsing, generation,
//! normalized-email boundary, keyed lookup/verifier HMAC helpers, the
//! scanner-safe confirmation cookie, and redacted `Debug`. Lookup keys are
//! keyed HMACs, and raw token parts are never stored. Core APIs
//! receive entropy/key material as inputs and never read the clock,
//! environment, filesystem, network, or OS RNG directly.

#![forbid(unsafe_code)]

pub mod confirm_cookie;
pub mod email;
pub mod error;
pub mod hmac_lookup;
pub mod magic_link;

pub use confirm_cookie::{
    ConfirmAccountBinding, ConfirmSelectorBinding, ConfirmVerifierBinding,
    MAGIC_LINK_CONFIRM_BINDING_BYTES, MAGIC_LINK_CONFIRM_MAX_AGE_SECS, MagicLinkConfirmBindings,
    MagicLinkConfirmCookie, MagicLinkConfirmCookieValue, MagicLinkConfirmationValue,
    MintedMagicLinkConfirm, VerifiedMagicLinkConfirm, mint_magic_link_confirm,
    verify_magic_link_confirm,
};
pub use email::NormalizedEmail;
pub use error::MagicLinkError;
pub use hmac_lookup::{
    EMAIL_LOOKUP_PREFIX, HMAC_KEY_BYTES, LookupHmac, LookupHmacKey, SELECTOR_LOOKUP_PREFIX,
    VERIFIER_HASH_PREFIX, VerifierHash, confirm_account_binding, confirm_selector_binding,
    confirm_verifier_binding, domain_separated_lookup_hmac, email_lookup_hmac,
    selector_lookup_hmac, selector_lookup_hmac_from_confirm_binding, verifier_hash,
    verifier_hash_from_confirm_binding,
};
pub use magic_link::{
    MAGIC_LINK_TOKEN_VERSION_PREFIX, MagicLinkSelector, MagicLinkToken, MagicLinkVerifier,
    SELECTOR_BYTES, SELECTOR_HEX_LEN, VERIFIER_BYTES, VERIFIER_HEX_LEN,
    contains_magic_link_token_marker,
};
