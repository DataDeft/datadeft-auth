use super::*;

#[test]
fn parses_the_bootstrap_operations() {
    let request =
        parse_request(br#"{"version":1,"id":1,"operation":"handshake","payload":{}}"#).unwrap();
    assert!(request.id == 1 && matches!(request.command, Command::Handshake));
    let request =
        parse_request(br#"{"version":1,"id":7,"operation":"ping","payload":{}}"#).unwrap();
    assert!(request.id == 7 && matches!(request.command, Command::Ping));
}

#[test]
fn parses_operation_payloads_strictly() {
    let request = parse_request(
        br#"{"version":1,"id":3,"operation":"request_link","payload":{"email":"a@b.test","terms_accepted":true,"privacy_accepted":true}}"#,
    )
    .unwrap();
    match request.command {
        Command::RequestLink(payload) => {
            assert_eq!(payload.email, "a@b.test");
            assert!(payload.terms_accepted && payload.privacy_accepted);
            assert!(payload.locale.is_none());
        }
        _ => panic!("expected request_link"),
    }
    for request in [
        // Unknown payload field.
        r#"{"version":1,"id":3,"operation":"request_link","payload":{"email":"a@b.test","terms_accepted":true,"privacy_accepted":true,"x":1}}"#,
        // Missing required field.
        r#"{"version":1,"id":3,"operation":"request_link","payload":{"email":"a@b.test","terms_accepted":true}}"#,
        // Wrong payload for the operation.
        r#"{"version":1,"id":3,"operation":"logout","payload":{"token":"x"}}"#,
        // Bootstrap operations take an exactly empty payload.
        r#"{"version":1,"id":3,"operation":"ping","payload":{"x":1}}"#,
    ] {
        assert!(parse_request(request.as_bytes()).is_err());
    }
}

#[test]
fn strict_envelope_rejects_forged_shapes() {
    for request in [
        r#"{"version":2,"id":1,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":-1,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":4294967296,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":1,"operation":"handshake","payload":{"extra":1}}"#,
        r#"{"version":1,"id":1,"operation":"handshake","payload":{},"extra":1}"#,
        r#"{"version":1,"version":1,"id":1,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":1,"operation":"other","payload":{}}"#,
        r#"{"version":1,"id":1,"operation":"handshake","payload":{}} {}"#,
        r#"{"version":1,"id":1,"operation":"handshake"}"#,
        "[]",
    ] {
        assert!(parse_request(request.as_bytes()).is_err());
    }
    assert!(parse_request(&[0xFF, 0xFE]).is_err());
}

#[test]
fn response_encoding_is_canonical() {
    assert_eq!(
        encode_response(
            3,
            ResultBody::Error {
                code: ErrorCode::Overloaded
            }
        )
        .unwrap(),
        br#"{"version":1,"id":3,"result":{"operation":"error","code":"overloaded"}}"#
    );
    assert_eq!(
        encode_response(2, ResultBody::Ping).unwrap(),
        br#"{"version":1,"id":2,"result":{"operation":"ping"}}"#
    );
    assert_eq!(
        encode_response(4, ResultBody::Logout { revoked: false }).unwrap(),
        br#"{"version":1,"id":4,"result":{"operation":"logout","revoked":false}}"#
    );
}
