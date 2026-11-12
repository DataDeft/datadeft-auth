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
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env_remove("AWS_DEFAULT_PROFILE")
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
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

fn secret_document(seed: u8, kid: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("e2e")
        .as_secs();
    datadeft_magic_link_aws::test_support::auth_secret_document(
        kid,
        seed + 1,
        now + 90 * 24 * 60 * 60,
        now + 121 * 24 * 60 * 60,
    )
}

#[tokio::test]
#[ignore = "needs DynamoDB Local (mise run dynamodb-local-test)"]
async fn full_flow_against_real_storage_through_the_pipe() {
    let client = client().await;
    let table = table(&client).await;

    let mut port = Port::spawn();
    let handshake = port.call("handshake", serde_json::json!({}));
    assert_eq!(handshake["operation"], "handshake");

    let document = secret_document(0, "test-active");
    let init = port.call("init", init_payload(&table, &document));
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
    let (destination, token) = url.split_once("?token=").expect("e2e");
    assert!(
        destination == "https://auth.test/auth/magic-link/landing",
        "email must target the reference landing route"
    );

    let landing = port.call("landing", serde_json::json!({ "token": token }));
    assert_eq!(landing["usable"], true);
    let confirm_cookie = landing["confirm_cookie"].as_str().expect("e2e").to_owned();
    let confirmation = landing["confirmation"].as_str().expect("e2e").to_owned();

    let mut second = Port::spawn();
    second.call("handshake", serde_json::json!({}));
    let mut rotated = init_payload(&table, &secret_document(10, "test-next"));
    rotated["secrets"]["previous_document"] = serde_json::json!(document);
    let init = second.call("init", rotated);
    assert_eq!(init["operation"], "init");

    // Two independent processes race the same flow against the same table.
    // Only one conditional authentication transaction may succeed.
    let command =
        serde_json::json!({ "confirm_cookie": confirm_cookie, "confirmation": confirmation });
    let barrier = std::sync::Barrier::new(2);
    let (first, other) = std::thread::scope(|scope| {
        let job = scope.spawn(|| {
            barrier.wait();
            port.call("confirm", command.clone())
        });
        barrier.wait();
        let other = second.call("confirm", command.clone());
        (job.join().expect("confirmation thread"), other)
    });
    let (confirmed, refused) = if first["operation"] == "confirm" {
        (first, other)
    } else {
        (other, first)
    };
    assert_eq!(confirmed["operation"], "confirm");
    assert_eq!(refused["operation"], "error");
    assert_eq!(refused["code"], "rejected");
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
    assert_eq!(replay["operation"], "error");
    assert_eq!(replay["code"], "rejected");

    // The rotated node accepts cookies from either the active or previous
    // issuer and performs the storage-HMAC fallback when needed.
    let validated = second.call(
        "validate_session",
        serde_json::json!({ "session_cookie": session_cookie }),
    );
    assert_eq!(validated["valid"], true);

    let logout = second.call(
        "logout",
        serde_json::json!({ "session_cookie": session_cookie }),
    );
    assert_eq!(logout["revoked"], true);

    let invalid = second.call(
        "validate_session",
        serde_json::json!({ "session_cookie": session_cookie }),
    );
    assert_eq!(invalid["valid"], false);

    // PoW through real storage: one solve buys its lifetime budget shared
    // across processes (nodes) counting in the same table.
    let challenge = port.call("pow_challenge", serde_json::json!({}));
    let chg = challenge["chg"].as_str().expect("e2e");
    let dif = u8::try_from(challenge["dif"].as_u64().expect("e2e")).expect("e2e");
    let (non, sol) = solve(chg, dif);
    let verified = port.call(
        "pow_verify",
        serde_json::json!({
            "chg": chg,
            "sol": sol,
            "non": non,
            "tim": challenge["tim"],
            "tag": challenge["tag"]
        }),
    );
    assert_eq!(verified["admitted"], true);
    let proof_cookie = verified["proof_cookie"].as_str().expect("e2e").to_owned();
    // The previous challenge key also verifies on the rotated node. Minting
    // another proof for the same solve must not create another budget.
    let rotated_proof = second.call(
        "pow_verify",
        serde_json::json!({
            "chg": chg, "sol": sol, "non": non,
            "tim": challenge["tim"], "tag": challenge["tag"]
        }),
    );
    assert_eq!(rotated_proof["admitted"], true);
    let rotated_cookie = rotated_proof["proof_cookie"].as_str().expect("proof");

    // Budget 3: two spends on the minting node, one on the other, then both
    // nodes refuse the fourth — the counter lives in the table, not a node.
    assert_eq!(
        port.call("pow_admit", admit(&proof_cookie))["admitted"],
        true
    );
    assert_eq!(
        port.call("pow_admit", admit(&proof_cookie))["admitted"],
        true
    );
    assert_eq!(
        second.call("pow_admit", admit(&proof_cookie))["admitted"],
        true,
        "the proof cookie and budget must carry across processes"
    );
    assert_eq!(
        second.call("pow_admit", admit(&proof_cookie))["admitted"],
        false
    );
    assert_eq!(
        port.call("pow_admit", admit(&proof_cookie))["admitted"],
        false
    );

    assert_eq!(
        second.call("pow_admit", admit(rotated_cookie))["admitted"],
        false,
        "rotation and re-verification must not refill a solve budget"
    );

    // Dependency loss must not become either an admission or an ordinary
    // invalid-session result. Only the local fixture table is removed.
    client
        .delete_table()
        .table_name(&table)
        .send()
        .await
        .expect("delete local table");
    let unavailable = second.call("pow_admit", admit(&proof_cookie));
    assert_eq!(unavailable["operation"], "error");
    assert_eq!(unavailable["code"], "unavailable");
    let unavailable = second.call(
        "validate_session",
        serde_json::json!({ "session_cookie": session_cookie }),
    );
    assert_eq!(unavailable["operation"], "error");
    assert_eq!(unavailable["code"], "unavailable");

    second.shutdown();
    port.shutdown();
}

fn init_payload(table: &str, document: &str) -> serde_json::Value {
    serde_json::json!({
        "mode": "aws",
        "service": { "terms_version": "t1", "privacy_version": "p1" },
        "email": {
            "link_base_url": "https://auth.test/auth/magic-link/landing?token=",
            "subject": "Sign in",
            "text": "Open {magic_link_url}"
        },
        "secrets": { "active_document": document },
        "aws": {
            "region": "eu-central-1",
            "table": table,
            "from_email": "login@auth.test",
            "endpoint_url": endpoint(),
            "fake_outbox": true
        },
        "pow": { "difficulty": 2, "proof_budget_per_solve": 3 }
    })
}

fn admit(proof_cookie: &str) -> serde_json::Value {
    serde_json::json!({ "proof_cookie": proof_cookie })
}

use datadeft_pow_core::test_support::solve;
