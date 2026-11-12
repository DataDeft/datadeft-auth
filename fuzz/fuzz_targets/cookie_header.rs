#![no_main]

use datadeft_auth_token_core::cookie_header::{
    MAX_COOKIE_VALUE_BYTES, is_cookie_octet, select_cookie,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|fields: Vec<Vec<u8>>| {
    // Never panics; a selected value always satisfies the target grammar.
    let fields = fields.iter().map(Vec::as_slice);
    if let Ok(value) = select_cookie(fields, "target") {
        assert!(!value.is_empty() && value.len() <= MAX_COOKIE_VALUE_BYTES);
        assert!(!value.starts_with('"'));
        assert!(value.bytes().all(is_cookie_octet));
    }
});
