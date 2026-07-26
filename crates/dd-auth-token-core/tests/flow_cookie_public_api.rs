use dd_auth_token_core::flow_cookie::{
    FlowAccountBinding, FlowSelectorBinding, FlowVerifierBinding, MAGIC_LINK_FLOW_BINDING_BYTES,
    MagicLinkFlowBindings,
};

#[test]
fn flow_cookie_binding_api_is_available_with_default_features() {
    let selector = FlowSelectorBinding::new([0x11; MAGIC_LINK_FLOW_BINDING_BYTES]);
    let verifier = FlowVerifierBinding::new([0x22; MAGIC_LINK_FLOW_BINDING_BYTES]);
    let account = FlowAccountBinding::new([0x33; MAGIC_LINK_FLOW_BINDING_BYTES]);
    let bindings = MagicLinkFlowBindings::new(selector, verifier, account, 300);

    assert_eq!(format!("{bindings:?}"), "MagicLinkFlowBindings(..)");
}
