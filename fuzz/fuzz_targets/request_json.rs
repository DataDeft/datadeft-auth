#![no_main]

use datadeft_magic_link_axum::parse_magic_link_request_json;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &[u8]| {
    let _ = parse_magic_link_request_json(input);
});
