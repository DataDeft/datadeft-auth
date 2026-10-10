#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use datadeft_auth_token_core::test_support::test_keyring;
use datadeft_magic_link_core::{MagicLinkConfirmCookie, verify_magic_link_confirm};
#[derive(Arbitrary, Debug)]
struct Input<'a> {
    cookie: &'a str,
    confirmation: &'a str,
}
fuzz_target!(|input: Input| {
    let keyring = test_keyring::<MagicLinkConfirmCookie>(13, "fuzz");
    let _ = verify_magic_link_confirm(input.cookie, input.confirmation, &keyring, 1_800_000_000, 300);
});
