#![no_main]

use arbitrary::Arbitrary;
use datadeft_auth_token_core::test_support::{CountingRng, test_keyring};
use datadeft_magic_link_core::{
    ConfirmAccountBinding, ConfirmSelectorBinding, ConfirmVerifierBinding,
    MagicLinkConfirmBindings, MagicLinkConfirmCookie, mint_magic_link_confirm,
    verify_magic_link_confirm,
};
use libfuzzer_sys::fuzz_target;
#[derive(Arbitrary, Debug)]
struct Input {
    selector: [u8; 32],
    verifier: [u8; 32],
    account: [u8; 32],
    now: u32,
    expiry_ahead: u16,
    seed: u8,
}
fuzz_target!(|input: Input| {
    let Some(expires_at) = input.now.checked_add(u32::from(input.expiry_ahead) % 301) else {
        return;
    };
    let keyring = test_keyring::<MagicLinkConfirmCookie>(13, "fuzz");
    let bindings = MagicLinkConfirmBindings::new(
        ConfirmSelectorBinding::new(input.selector),
        ConfirmVerifierBinding::new(input.verifier),
        ConfirmAccountBinding::new(input.account),
        expires_at,
    );
    let mut rng = CountingRng::starting_at(input.seed);
    let now = u64::from(input.now);
    let minted = mint_magic_link_confirm(bindings, &keyring, &mut rng, now).expect("mint");
    let verified = verify_magic_link_confirm(
        minted.cookie().as_secret_value(),
        minted.confirmation().as_value(),
        &keyring,
        now,
        300,
    )
    .expect("matching confirmation verifies");
    assert_eq!(verified.expires_at_unix(), expires_at);
    let same_selector = ConfirmSelectorBinding::new(input.selector);
    let same_verifier = ConfirmVerifierBinding::new(input.verifier);
    let same_account = ConfirmAccountBinding::new(input.account);
    assert!(verified.selector().matches_constant_time(&same_selector));
    assert!(verified.verifier().matches_constant_time(&same_verifier));
    assert!(verified.account().matches_constant_time(&same_account));

    // Still-canonical confirmation hex with one digit changed must be refused.
    let mut mutated = minted.confirmation().as_value().as_bytes().to_vec();
    mutated[0] = if mutated[0] == b'0' { b'1' } else { b'0' };
    let mutated = String::from_utf8(mutated).expect("hex stays ascii");
    let refused = verify_magic_link_confirm(
        minted.cookie().as_secret_value(),
        &mutated,
        &keyring,
        now,
        300,
    );
    assert!(refused.is_err());
});
