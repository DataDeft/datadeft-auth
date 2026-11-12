#![no_main]

use datadeft_auth_token_core::branca;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &str| {
    let _ = branca::decode(input, &[7u8; 32]);
});
