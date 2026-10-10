#![no_main]

use libfuzzer_sys::fuzz_target;
use datadeft_magic_link_axum::parse_magic_link_request_json;
fuzz_target!(|input: &[u8]| {
    let _ = parse_magic_link_request_json(input);
});
