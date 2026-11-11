use super::*;

#[test]
fn parses_the_two_bootstrap_operations() {
    let request =
        parse_request(br#"{"version":1,"id":1,"operation":"handshake","payload":{}}"#).unwrap();
    assert!(request.id == 1 && request.operation == Operation::Handshake);
    let request =
        parse_request(br#"{"version":1,"id":7,"operation":"ping","payload":{}}"#).unwrap();
    assert!(request.id == 7 && request.operation == Operation::Ping);
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
}
