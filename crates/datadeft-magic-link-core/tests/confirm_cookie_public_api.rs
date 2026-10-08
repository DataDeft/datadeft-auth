use datadeft_magic_link_core::confirm_cookie::{
    ConfirmAccountBinding, ConfirmSelectorBinding, ConfirmVerifierBinding,
    MAGIC_LINK_CONFIRM_BINDING_BYTES, MagicLinkConfirmBindings,
};

#[test]
fn confirm_cookie_binding_api_is_available_with_default_features() {
    let selector = ConfirmSelectorBinding::new([0x11; MAGIC_LINK_CONFIRM_BINDING_BYTES]);
    let verifier = ConfirmVerifierBinding::new([0x22; MAGIC_LINK_CONFIRM_BINDING_BYTES]);
    let account = ConfirmAccountBinding::new([0x33; MAGIC_LINK_CONFIRM_BINDING_BYTES]);
    let bindings = MagicLinkConfirmBindings::new(selector, verifier, account, 300);

    assert_eq!(format!("{bindings:?}"), "MagicLinkConfirmBindings(..)");
}
