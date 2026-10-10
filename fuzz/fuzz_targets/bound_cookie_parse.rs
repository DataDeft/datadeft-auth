#![no_main]

use libfuzzer_sys::fuzz_target;
use datadeft_auth_token_core::cookie::{MaxAge, parse_bound_cookie, parse_cookie_wrapper};
use datadeft_auth_token_core::test_support::test_keyring;
use datadeft_magic_link_service::SessionCookie;
fuzz_target!(|input: &str| {
    let _ = parse_cookie_wrapper(input);
    let keyring = test_keyring::<SessionCookie>(9, "fuzz");
    let _ = parse_bound_cookie(input, &keyring, 1_800_000_000, MaxAge::new(86_400, 2_592_000));
});
