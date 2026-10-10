#![no_main]

use libfuzzer_sys::fuzz_target;
use datadeft_auth_token_core::branca;
fuzz_target!(|input: &str| {
    let _ = branca::decode(input, &[7u8; 32]);
});
