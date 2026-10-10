#![no_main]

use libfuzzer_sys::fuzz_target;
use datadeft_magic_link_core::NormalizedEmail;
fuzz_target!(|input: &str| {
    // from_normalized only validates: an accepted address is unchanged.
    if let Ok(email) = NormalizedEmail::from_normalized(input) {
        assert_eq!(email.as_str(), input);
    }
    // normalize is idempotent and its output is accepted as normalized.
    if let Ok(email) = NormalizedEmail::normalize(input) {
        let again = NormalizedEmail::normalize(email.as_str()).expect("idempotent");
        assert_eq!(again, email);
        assert!(NormalizedEmail::from_normalized(email.as_str()).is_ok());
        assert!(!email.as_str().bytes().any(|byte| byte.is_ascii_uppercase()));
    }
});
