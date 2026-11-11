//! End-to-end proof against real storage: drives the built executable over
//! its pipes with DynamoDB Local as the store (`mise run dynamodb-local-test`).
//! AWS-local mode: endpoint override, inline secret documents and the
//! in-process outbox; SES and Secrets Manager stay out of local runs.
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::{Credentials, Region};
use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
};
use base64::Engine;

fn endpoint() -> String {
    std::env::var("DYNAMODB_LOCAL_ENDPOINT").unwrap_or_else(|_| "http://localhost:18000".to_owned())
}

async fn client() -> Client {
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version_latest()
        .region(Region::new("eu-central-1"))
        .credentials_provider(Credentials::new("local", "local", None, None, "test"))
        .endpoint_url(endpoint())
        .build();
    Client::from_conf(config)
}

async fn table(client: &Client) -> String {
    let table = format!(
        "port-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("e2e")
            .as_nanos(),
    );
    let attribute = |name: &str| {
        AttributeDefinition::builder()
            .attribute_name(name)
            .attribute_type(ScalarAttributeType::S)
            .build()
            .expect("e2e")
    };
    let key = |name: &str, kind| {
        KeySchemaElement::builder()
            .attribute_name(name)
            .key_type(kind)
            .build()
            .expect("e2e")
    };
    client
        .create_table()
        .table_name(&table)
        .attribute_definitions(attribute("pk"))
        .attribute_definitions(attribute("sk"))
        .key_schema(key("pk", KeyType::Hash))
        .key_schema(key("sk", KeyType::Range))
        .billing_mode(BillingMode::PayPerRequest)
        .send()
        .await
        .expect("create table (is DynamoDB Local running?)");
    table
}

struct Port {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    next_id: u32,
}

impl Port {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_datadeft-auth-port"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // The supported credential chain reads these for DynamoDB Local.
            .env("AWS_ACCESS_KEY_ID", "local")
            .env("AWS_SECRET_ACCESS_KEY", "local")
            .spawn()
            .expect("spawn port executable");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
        }
    }

    fn call(&mut self, operation: &str, payload: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let request = serde_json::json!({
            "version": 1,
            "id": self.next_id,
            "operation": operation,
            "payload": payload,
        })
        .to_string();
        let frame = request.as_bytes();
        let length = u32::try_from(frame.len()).expect("e2e");
        self.stdin.write_all(&length.to_be_bytes()).expect("e2e");
        self.stdin.write_all(frame).expect("e2e");
        self.stdin.flush().expect("e2e");

        let mut prefix = [0_u8; 4];
        self.stdout.read_exact(&mut prefix).expect("e2e");
        let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
        self.stdout.read_exact(&mut body).expect("e2e");
        let reply: serde_json::Value = serde_json::from_slice(&body).expect("e2e");
        assert_eq!(reply["id"], self.next_id, "replies arrive per request here");
        reply["result"].clone()
    }

    fn shutdown(mut self) {
        drop(self.stdin);
        let status = self.child.wait().expect("wait");
        assert!(status.success(), "clean EOF exits 0");
    }
}

fn secret_document() -> String {
    let key = |byte: u8| base64::engine::general_purpose::STANDARD.encode([byte; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("e2e")
        .as_secs();
    serde_json::json!({
        "kid": "test-active",
        "mint_until_unix": now + 90 * 24 * 60 * 60,
        "verify_until_unix": now + 121 * 24 * 60 * 60,
        "magic_link_lookup_hmac_b64": key(1),
        "storage_hmac_b64": key(2),
        "session_cookie_root_b64": key(3),
        "magic_link_confirm_cookie_root_b64": key(4),
        "pow_challenge_secret_b64": key(5),
        "pow_proof_cookie_root_b64": key(6),
    })
    .to_string()
}

#[tokio::test]
#[ignore = "needs DynamoDB Local (mise run dynamodb-local-test)"]
async fn full_flow_against_real_storage_through_the_pipe() {
    let client = client().await;
    let table = table(&client).await;

    let mut port = Port::spawn();
    let handshake = port.call("handshake", serde_json::json!({}));
    assert_eq!(handshake["operation"], "handshake");

    let init = port.call(
        "init",
        serde_json::json!({
            "mode": "aws",
            "service": { "terms_version": "t1", "privacy_version": "p1" },
            "email": {
                "link_base_url": "https://auth.test/magic?token=",
                "subject": "Sign in",
                "text": "Open {magic_link_url}"
            },
            "secrets": { "active_document": secret_document() },
            "aws": {
                "region": "eu-central-1",
                "table": table,
                "from_email": "login@auth.test",
                "endpoint_url": endpoint(),
                "fake_outbox": true
            }
        }),
    );
    assert_eq!(init["operation"], "init", "init failed: {init}");

    let email = "port-e2e@example.test";
    let requested = port.call(
        "request_link",
        serde_json::json!({ "email": email, "terms_accepted": true, "privacy_accepted": true }),
    );
    assert_eq!(requested["reason"], "magic_link_request_sent");

    let last = port.call(
        "fake_last_magic_link",
        serde_json::json!({ "email": email }),
    );
    assert_eq!(last["found"], true);
    let url = last["magic_link_url"].as_str().expect("e2e");
    let token = url.split("?token=").nth(1).expect("e2e");

    let landing = port.call("landing", serde_json::json!({ "token": token }));
    assert_eq!(landing["usable"], true, "landing failed: {landing}");
    let confirm_cookie = landing["confirm_cookie"].as_str().expect("e2e").to_owned();
    let confirmation = landing["confirmation"].as_str().expect("e2e").to_owned();

    let confirmed = port.call(
        "confirm",
        serde_json::json!({ "confirm_cookie": confirm_cookie, "confirmation": confirmation }),
    );
    assert_eq!(
        confirmed["operation"], "confirm",
        "confirm failed: {confirmed}"
    );
    assert_eq!(confirmed["user_created"], true);
    let session_cookie = confirmed["session_cookie"]
        .as_str()
        .expect("e2e")
        .to_owned();

    // One-time consumption holds through the real conditional transaction.
    let replay = port.call(
        "confirm",
        serde_json::json!({ "confirm_cookie": confirm_cookie, "confirmation": confirmation }),
    );
    assert_eq!(
        replay,
        serde_json::json!({ "operation": "error", "code": "rejected" })
    );

    let validated = port.call(
        "validate_session",
        serde_json::json!({ "session_cookie": session_cookie }),
    );
    assert_eq!(validated["valid"], true);

    let logout = port.call(
        "logout",
        serde_json::json!({ "session_cookie": session_cookie }),
    );
    assert_eq!(logout["revoked"], true);

    let invalid = port.call(
        "validate_session",
        serde_json::json!({ "session_cookie": session_cookie }),
    );
    assert_eq!(invalid["valid"], false);

    port.shutdown();
}
