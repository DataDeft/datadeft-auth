#![no_main]

use libfuzzer_sys::fuzz_target;
use datadeft_auth_token_core::test_support::test_keyring;
use datadeft_pow_core::{PowProofCookie, verify_pow_proof_cookie};
fuzz_target!(|input: &str| {
    let keyring = test_keyring::<PowProofCookie>(11, "fuzz");
    let _ = verify_pow_proof_cookie(input, &keyring, 1_800_000_000, 10_800);
});
