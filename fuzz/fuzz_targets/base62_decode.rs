#![no_main]

use datadeft_auth_token_core::base62;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &str| {
    // Never panics; an accepted string round-trips through the decoded bytes.
    if let Ok(bytes) = base62::decode(input) {
        let again = base62::decode(&base62::encode(&bytes)).expect("re-decode");
        assert_eq!(again, bytes);
    }
});
