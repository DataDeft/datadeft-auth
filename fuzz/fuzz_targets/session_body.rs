#![no_main]

use libfuzzer_sys::fuzz_target;
use datadeft_magic_link_service::{decode_session_cookie_body, encode_session_cookie_body};
fuzz_target!(|input: &[u8]| {
    // Canonical framing: an accepted body re-encodes to the same bytes.
    if let Ok(body) = decode_session_cookie_body(input) {
        let again = encode_session_cookie_body(&body.session_id, body.country.as_deref())
            .expect("re-encode");
        assert_eq!(again, input);
    }
});
