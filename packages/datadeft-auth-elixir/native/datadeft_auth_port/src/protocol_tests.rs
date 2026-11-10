use super::*;
use std::io::Cursor;

fn input(requests: &[&str]) -> Cursor<Vec<u8>> {
    let mut bytes = Vec::new();
    for request in requests {
        framing::write_frame(&mut bytes, request.as_bytes()).unwrap();
    }
    Cursor::new(bytes)
}

const HELLO: &str = r#"{"version":1,"id":1,"operation":"handshake","payload":{}}"#;

#[test]
fn handshake_and_ping_golden() {
    let mut output = Vec::new();
    serve(
        &mut input(&[
            HELLO,
            r#"{"version":1,"id":2,"operation":"ping","payload":{}}"#,
        ]),
        &mut output,
    )
    .unwrap();
    let mut output = Cursor::new(output);
    let first = framing::read_frame(&mut output).unwrap().unwrap();
    assert_eq!(
        String::from_utf8(first).unwrap(),
        format!(
            r#"{{"version":1,"id":1,"result":{{"operation":"handshake","build_version":"{}","max_frame_bytes":4096}}}}"#,
            env!("CARGO_PKG_VERSION")
        )
    );
    assert_eq!(
        framing::read_frame(&mut output).unwrap().unwrap(),
        br#"{"version":1,"id":2,"result":{"operation":"ping"}}"#
    );
    assert!(framing::read_frame(&mut output).unwrap().is_none());
}

#[test]
fn strict_requests_and_handshake_order() {
    for request in [
        r#"{"version":2,"id":1,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":1,"operation":"ping","payload":{}}"#,
        r#"{"version":1,"id":0,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":-1,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":4294967296,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":1,"operation":"handshake","payload":{"extra":1}}"#,
        r#"{"version":1,"id":1,"operation":"handshake","payload":{},"extra":1}"#,
        r#"{"version":1,"version":1,"id":1,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":1,"operation":"other","payload":{}}"#,
        r#"{"version":1,"id":1,"operation":"handshake","payload":{}} {}"#,
    ] {
        assert!(serve(&mut input(&[request]), &mut Vec::new()).is_err());
    }
    for second in [
        HELLO,
        r#"{"version":1,"id":1,"operation":"ping","payload":{}}"#,
        r#"{"version":1,"id":2,"operation":"handshake","payload":{}}"#,
    ] {
        assert!(serve(&mut input(&[HELLO, second]), &mut Vec::new()).is_err());
    }
    assert!(serve(&mut input(&[]), &mut Vec::new()).is_ok());
}
