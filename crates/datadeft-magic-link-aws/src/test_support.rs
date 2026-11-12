//! Deterministic fixtures shared by the AWS adapter test suites.
//!
//! Available under `cfg(test)` and the explicit `test-support` feature only.
//! Never use it in default production builds: every key here is a fixed,
//! public test vector. Production documents come from the configured secret
//! manager with CSPRNG-generated keys.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Standard-base64 encoding of a 32-byte key whose bytes are all `byte`: the
/// workspace's deterministic test key scheme.
#[must_use]
pub fn deterministic_key_b64(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

/// Auth secret document JSON (docs/security.md, "Auth secret document") with
/// caller-supplied base64 key values.
///
/// `keys_b64` is the six key fields in the documented order: magic-link
/// lookup HMAC, storage HMAC, session cookie root, confirm cookie root, PoW
/// challenge secret, PoW proof cookie root.
#[must_use]
pub fn auth_secret_document_with_keys(
    kid: &str,
    mint_until_unix: u64,
    verify_until_unix: u64,
    keys_b64: &[String; 6],
) -> String {
    format!(
        r#"{{
  "kid": "{kid}",
  "mint_until_unix": {mint_until_unix},
  "verify_until_unix": {verify_until_unix},
  "magic_link_lookup_hmac_b64": "{}",
  "storage_hmac_b64": "{}",
  "session_cookie_root_b64": "{}",
  "magic_link_confirm_cookie_root_b64": "{}",
  "pow_challenge_secret_b64": "{}",
  "pow_proof_cookie_root_b64": "{}"
}}"#,
        keys_b64[0], keys_b64[1], keys_b64[2], keys_b64[3], keys_b64[4], keys_b64[5],
    )
}

/// Auth secret document JSON with deterministic keys: the six key fields are
/// [`deterministic_key_b64`] of `key_base` through `key_base + 5`, in the
/// documented field order (see [`auth_secret_document_with_keys`]).
#[must_use]
pub fn auth_secret_document(
    kid: &str,
    key_base: u8,
    mint_until_unix: u64,
    verify_until_unix: u64,
) -> String {
    auth_secret_document_with_keys(
        kid,
        mint_until_unix,
        verify_until_unix,
        &[
            deterministic_key_b64(key_base),
            deterministic_key_b64(key_base + 1),
            deterministic_key_b64(key_base + 2),
            deterministic_key_b64(key_base + 3),
            deterministic_key_b64(key_base + 4),
            deterministic_key_b64(key_base + 5),
        ],
    )
}
