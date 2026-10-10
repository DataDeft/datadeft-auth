#![no_main]

use libfuzzer_sys::fuzz_target;
use datadeft_magic_link_core::NormalizedEmail;
fuzz_target!(|input: &str| {
    // Validation only: an accepted address is returned unchanged.
    if let Ok(email) = NormalizedEmail::parse(input) {
        assert_eq!(email.as_str(), input);
    }
});
