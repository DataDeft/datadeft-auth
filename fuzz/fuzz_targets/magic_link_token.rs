#![no_main]

use libfuzzer_sys::fuzz_target;
use datadeft_magic_link_core::MagicLinkToken;
fuzz_target!(|input: &str| {
    // One spelling per token: an accepted token is returned unchanged.
    if let Ok(token) = MagicLinkToken::parse(input) {
        assert_eq!(token.as_secret_value().as_str(), input);
    }
});
