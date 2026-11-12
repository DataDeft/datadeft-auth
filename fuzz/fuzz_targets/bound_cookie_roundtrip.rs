#![no_main]

use arbitrary::Arbitrary;
use datadeft_auth_token_core::cookie::{MaxAge, mint_bound_cookie, parse_bound_cookie};
use datadeft_auth_token_core::test_support::{CountingRng, test_keyring};
use datadeft_magic_link_service::SessionCookie;
use libfuzzer_sys::fuzz_target;
#[derive(Arbitrary, Debug)]
struct Input {
    body: Vec<u8>,
    now: u32,
    iat_back: u16,
    seed: u8,
}
fuzz_target!(|input: Input| {
    let keyring = test_keyring::<SessionCookie>(9, "fuzz");
    let now = u64::from(input.now);
    // iat_back stays far below both MaxAge bounds, so an accepted mint is fresh.
    let iat = input.now.saturating_sub(u32::from(input.iat_back));
    let mut rng = CountingRng::starting_at(input.seed);
    if let Ok(cookie) =
        mint_bound_cookie::<SessionCookie, _>(&input.body, &keyring, &mut rng, input.now, iat, now)
    {
        let verified = parse_bound_cookie(&cookie, &keyring, now, MaxAge::new(86_400, 2_592_000))
            .expect("minted cookie verifies");
        assert_eq!(verified.body(), input.body.as_slice());
        assert_eq!(verified.timestamp(), input.now);
        assert_eq!(verified.iat(), iat);
    }
});
