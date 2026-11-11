use super::*;

pub(crate) fn secret_document(verify_until_unix: u64) -> String {
    use base64::Engine;
    let key = |byte: u8| base64::engine::general_purpose::STANDARD.encode([byte; 32]);
    serde_json::json!({
        "kid": "test-active",
        "mint_until_unix": 4_102_444_800_u64,
        "verify_until_unix": verify_until_unix,
        "magic_link_lookup_hmac_b64": key(1),
        "storage_hmac_b64": key(2),
        "session_cookie_root_b64": key(3),
        "magic_link_confirm_cookie_root_b64": key(4),
        "pow_challenge_secret_b64": key(5),
        "pow_proof_cookie_root_b64": key(6),
    })
    .to_string()
}

#[test]
fn the_test_secret_document_loads_and_requires_a_verify_window() {
    assert!(LoadedAuthSecrets::from_json(&secret_document(4_202_444_800), None).is_ok());
    // The loader requires the verify window to extend past the mint window;
    // the configuration error must fire at init, not at first use.
    assert!(LoadedAuthSecrets::from_json(&secret_document(4_102_444_800), None).is_err());
}
