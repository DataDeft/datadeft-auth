//! A stalled local Secrets Manager fixture must not keep a child alive after
//! its owner closes stdin. No live AWS resources or credentials are used.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn send(stdin: &mut impl Write, id: u32, operation: &str, payload: serde_json::Value) {
    let frame = serde_json::json!({
        "version": 1,
        "id": id,
        "operation": operation,
        "payload": payload,
    })
    .to_string();
    stdin
        .write_all(
            &u32::try_from(frame.len())
                .expect("small fixture")
                .to_be_bytes(),
        )
        .expect("prefix");
    stdin.write_all(frame.as_bytes()).expect("body");
    stdin.flush().expect("flush");
}

#[test]
fn eof_cancels_a_stalled_secret_fetch_during_initialization() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("local listener");
    listener.set_nonblocking(true).expect("nonblocking accept");
    let endpoint = format!("http://{}", listener.local_addr().expect("local address"));
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_datadeft-auth-port"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("AWS_ACCESS_KEY_ID", "local")
            .env("AWS_SECRET_ACCESS_KEY", "local")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env_remove("AWS_DEFAULT_PROFILE")
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .spawn()
            .expect("spawn child"),
    );
    let mut stdin = child.0.stdin.take().expect("stdin");
    send(&mut stdin, 1, "handshake", serde_json::json!({}));
    send(
        &mut stdin,
        2,
        "init",
        serde_json::json!({
            "mode": "aws",
            "service": { "terms_version": "t", "privacy_version": "p" },
            "email": {
                "link_base_url": "https://auth.example.test/auth/magic-link/landing?token=",
                "subject": "Sign in",
                "text": "Open {magic_link_url}"
            },
            "secrets": { "active_ref": { "name_or_arn": "fixture-secret" } },
            "aws": {
                "region": "eu-central-1",
                "table": "fixture-table",
                "from_email": "login@example.test",
                "endpoint_url": endpoint,
                "fake_outbox": true
            }
        }),
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut connection = loop {
        match listener.accept() {
            Ok((connection, _)) => break connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "secret fetch did not connect");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => panic!("local accept failed"),
        }
    };
    // Accepted sockets may inherit the listener's nonblocking mode (macOS).
    // Use a genuinely blocking, bounded read rather than racing the sender.
    connection
        .set_nonblocking(false)
        .expect("blocking fixture read");
    connection
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read bound");
    // Observe a request byte, but never send an HTTP response. The SDK future
    // remains pending while the owner closes stdin.
    connection.read_exact(&mut [0_u8; 1]).expect("HTTP request");
    drop(stdin);

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.0.try_wait().expect("poll child") {
            assert!(status.success(), "EOF is a clean exit");
            break;
        }
        assert!(Instant::now() < deadline, "initializing child ignored EOF");
        std::thread::sleep(Duration::from_millis(10));
    }
}
