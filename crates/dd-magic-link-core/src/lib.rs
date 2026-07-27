//! `dd-magic-link-core` — IO-free magic-link primitives.
//!
//! Owns the token grammar, selector/verifier types, parsing, generation,
//! normalized-email boundary, keyed lookup/verifier HMAC helpers, the
//! scanner-safe confirmation flow cookie, and redacted `Debug`. Stores only
//! keyed lookup material, never raw token parts or raw emails. Core APIs
//! receive entropy/key material as inputs and never read the clock,
//! environment, filesystem, network, or OS RNG directly.

#![forbid(unsafe_code)]

pub mod email;
pub mod error;
pub mod flow_cookie;
pub mod hmac_lookup;
pub mod magic_link;

pub use email::NormalizedEmail;
pub use error::MagicLinkError;
pub use flow_cookie::{
    FlowAccountBinding, FlowSelectorBinding, FlowVerifierBinding, MAGIC_LINK_FLOW_BINDING_BYTES,
    MAGIC_LINK_FLOW_MAX_AGE_SECS, MagicLinkFlowBindings, MagicLinkFlowConfirmation,
    MagicLinkFlowCookie, MagicLinkFlowCookieValue, MintedMagicLinkFlow, VerifiedMagicLinkFlow,
    mint_magic_link_flow, verify_magic_link_flow,
};
pub use hmac_lookup::{
    EMAIL_LOOKUP_PREFIX, HMAC_KEY_BYTES, LookupHmac, LookupHmacKey, SELECTOR_LOOKUP_PREFIX,
    VERIFIER_HASH_PREFIX, VerifierHash, email_lookup_hmac, flow_account_binding,
    flow_selector_binding, flow_verifier_binding, selector_lookup_hmac,
    selector_lookup_hmac_from_flow_binding, verifier_hash, verifier_hash_from_flow_binding,
};
pub use magic_link::{
    MAGIC_LINK_TOKEN_VERSION_PREFIX, MagicLinkSelector, MagicLinkToken, MagicLinkVerifier,
    SELECTOR_BYTES, SELECTOR_HEX_LEN, VERIFIER_BYTES, VERIFIER_HEX_LEN,
};
