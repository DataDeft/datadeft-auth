use super::*;
use std::collections::BTreeSet;
use std::io::Cursor;
use std::sync::Mutex;

#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const HELLO: &str = r#"{"version":1,"id":1,"operation":"handshake","payload":{}}"#;

fn input(requests: &[String]) -> Cursor<Vec<u8>> {
    let mut bytes = Vec::new();
    for request in requests {
        framing::write_frame(&mut bytes, request.as_bytes()).unwrap();
    }
    Cursor::new(bytes)
}

fn ping(id: u32) -> String {
    format!(r#"{{"version":1,"id":{id},"operation":"ping","payload":{{}}}}"#)
}

fn run(requests: &[String], job_limit: usize) -> Result<Vec<Vec<u8>>, FrameError> {
    let output = SharedBuffer::default();
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(serve_with(input(requests), output.clone(), job_limit));
    result.map(|()| {
        let bytes = output.0.lock().expect("buffer lock").clone();
        let mut frames = Vec::new();
        let mut reader = Cursor::new(bytes);
        while let Some(frame) = framing::read_frame(&mut reader).unwrap() {
            frames.push(frame);
        }
        frames
    })
}

#[test]
fn handshake_and_ping_golden() {
    let frames = run(&[HELLO.to_string(), ping(2)], MAX_IN_FLIGHT_JOBS).unwrap();
    assert_eq!(
        String::from_utf8(frames[0].clone()).unwrap(),
        format!(
            r#"{{"version":1,"id":1,"result":{{"operation":"handshake","build_version":"{}","max_frame_bytes":4096}}}}"#,
            env!("CARGO_PKG_VERSION")
        )
    );
    assert_eq!(
        frames[1],
        br#"{"version":1,"id":2,"result":{"operation":"ping"}}"#
    );
    assert_eq!(frames.len(), 2);
}

#[test]
fn concurrent_pings_each_get_exactly_one_reply() {
    let mut requests = vec![HELLO.to_string()];
    requests.extend((2..=50).map(ping));
    let frames = run(&requests, MAX_IN_FLIGHT_JOBS).unwrap();
    let ids: BTreeSet<u64> = frames
        .iter()
        .skip(1)
        .map(|frame| {
            let value: serde_json::Value = serde_json::from_slice(frame).unwrap();
            assert_eq!(value["result"]["operation"], "ping");
            value["id"].as_u64().unwrap()
        })
        .collect();
    assert_eq!(frames.len(), 50);
    assert_eq!(ids, (2..=50).collect());
}

#[test]
fn exhausted_job_capacity_fails_the_request_not_the_process() {
    let frames = run(&[HELLO.to_string(), ping(2)], 0).unwrap();
    assert_eq!(
        frames[1],
        br#"{"version":1,"id":2,"result":{"operation":"error","code":"overloaded"}}"#
    );
}

#[test]
fn strict_requests_and_handshake_order_stay_fatal() {
    for request in [
        r#"{"version":2,"id":1,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":1,"operation":"ping","payload":{}}"#,
        r#"{"version":1,"id":0,"operation":"handshake","payload":{}}"#,
        r#"{"version":1,"id":1,"operation":"handshake","payload":{"extra":1}}"#,
        r#"{"version":1,"id":1,"operation":"other","payload":{}}"#,
    ] {
        assert!(run(&[request.to_string()], MAX_IN_FLIGHT_JOBS).is_err());
    }
    for second in [
        HELLO.to_string(),
        ping(1),
        r#"{"version":1,"id":2,"operation":"handshake","payload":{}}"#.to_string(),
    ] {
        assert!(run(&[HELLO.to_string(), second], MAX_IN_FLIGHT_JOBS).is_err());
    }
    assert!(run(&[], MAX_IN_FLIGHT_JOBS).is_ok());
}
