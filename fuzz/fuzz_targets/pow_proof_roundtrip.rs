#![no_main]

use arbitrary::Arbitrary;
use datadeft_auth_token_core::test_support::{CountingRng, test_keyring};
use datadeft_pow_core::{PowProofCookie, mint_pow_proof_cookie, verify_pow_proof_cookie};
use libfuzzer_sys::fuzz_target;
const MAX_AGE_SECS: u64 = 10_800;
#[derive(Arbitrary, Debug)]
struct Input {
    tid: [u8; 32],
    solve_class: Option<u8>,
    now: u32,
    age: u16,
    seed: u8,
}
fuzz_target!(|input: Input| {
    let keyring = test_keyring::<PowProofCookie>(11, "fuzz");
    let tid = hex::encode(input.tid);
    let mut rng = CountingRng::starting_at(input.seed);
    let minted_at = u64::from(input.now);
    let cookie = mint_pow_proof_cookie(&tid, input.solve_class, &keyring, &mut rng, minted_at)
        .expect("canonical tid mints");
    let fresh_at = minted_at + u64::from(input.age) % (MAX_AGE_SECS + 1);
    let verified =
        verify_pow_proof_cookie(cookie.as_secret_value(), &keyring, fresh_at, MAX_AGE_SECS)
            .expect("fresh proof verifies");
    assert_eq!(verified.tid(), tid);
    assert_eq!(verified.solve_class(), input.solve_class);
    // One second past the configured lifetime must refuse.
    let expired_at = minted_at + MAX_AGE_SECS + 1;
    assert!(
        verify_pow_proof_cookie(cookie.as_secret_value(), &keyring, expired_at, MAX_AGE_SECS)
            .is_err()
    );
});
