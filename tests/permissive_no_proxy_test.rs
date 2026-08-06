//! Tests for permissive mode behaving "as if there were no proxy".
//!
//! Beyond letting unmatched requests through (covered in `permissive_mode_test.rs`),
//! permissive mode must NOT block for any traffic-filtering reason: branch
//! restrictions, LFS operation checks, the body-inspection-requires-HTTPS block,
//! and unsupported CONNECT ports all become allow-through. The one exception is
//! proxy authentication, which still blocks. Each block point is exercised here.

mod common;

use common::{
    ReportingClient, TestCa, TestProxy, TestUpstream, git_rule, git_rule_with_branches, ok_handler,
    read_audit_entries,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

/// Helper to build an LFS batch JSON body (mirrors the one in `git_lfs_test.rs`).
fn lfs_batch_body(operation: &str) -> String {
    format!(
        r#"{{"operation":"{}","transfers":["basic"],"objects":[{{"oid":"abc123","size":42}}]}}"#,
        operation
    )
}

// ---------------------------------------------------------------------------
// Block point 3: body-inspection-requires-HTTPS (plain HTTP git/LFS bodies)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_permissive_forwards_plain_http_body_inspection() {
    let t = test_report!(
        "Permissive mode forwards plain-HTTP git push (would need HTTPS to inspect body)"
    );
    let ca = TestCa::generate();

    // Real upstream over plain HTTP — the request must actually be forwarded.
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("forwarded"))
        .mount(&upstream)
        .await;
    let port = upstream.address().port();
    t.setup("Started plain-HTTP upstream");

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    // A push rule with branch restrictions. Over plain HTTP the body can't be
    // inspected, so non-permissive mode blocks (451). Permissive forwards anyway.
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "push",
            &format!("http://localhost:{}/*", port),
            &["feature/*"],
        )],
        port,
    )
    .permissive(true)
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let resp = client
        .post_with_body(
            &format!("http://localhost:{}/repo.git/git-receive-pack", port),
            b"anything".to_vec(),
        )
        .await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("upstream was reached", &body.as_str(), &"forwarded");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "event",
        &entries[0]["event"].as_str().unwrap(),
        &"request_permitted",
    );
    t.assert_eq(
        "decision",
        &entries[0]["decision"].as_str().unwrap(),
        &"allowed",
    );
    t.assert_eq(
        "reason",
        &entries[0]["reason"].as_str().unwrap(),
        &"body_inspection_requires_https",
    );

    proxy.shutdown();
}

// ---------------------------------------------------------------------------
// Block point 2: Git-LFS operation check (HTTPS)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_permissive_forwards_lfs_op_check_failure() {
    let t = test_report!("Permissive mode forwards LFS batch op that fails the operation check");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("lfs-forwarded"))
        .report(&t, "LFS batch mock")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    // fetch rule ⇒ download-only. An upload batch fails the op check; non-permissive
    // would return 451, permissive forwards it.
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .permissive(true)
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("upload"))
        .send()
        .await
        .unwrap();
    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("upstream was reached", &body.as_str(), &"lfs-forwarded");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "event",
        &entries[0]["event"].as_str().unwrap(),
        &"request_permitted",
    );
    t.assert_eq(
        "decision",
        &entries[0]["decision"].as_str().unwrap(),
        &"allowed",
    );
    t.assert_eq(
        "reason",
        &entries[0]["reason"].as_str().unwrap(),
        &"lfs_operation_not_allowed",
    );

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Block point 4: Unsupported CONNECT port → blind raw-TCP tunnel
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_permissive_blind_tunnels_unsupported_connect_port() {
    let t = test_report!("Permissive mode blind-tunnels an unsupported CONNECT port (raw TCP)");
    let ca = TestCa::generate();

    // Plain TCP echo server — the point of a blind tunnel is no MITM, so bytes
    // must arrive verbatim.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        }
    });
    t.setup("Started plain TCP echo server");

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    // No rules needed: an unsupported CONNECT port is decided before filtering.
    // The builder wires `echo_port` as the upstream-port override, so the blind
    // tunnel dials the echo server.
    let proxy = TestProxy::builder(&ca, vec![], echo_port)
        .permissive(true)
        .audit_log(audit_path_str)
        .report(&t)
        .start()
        .await;

    // Open a CONNECT tunnel to an unsupported port (not 443/80).
    let mut stream = TcpStream::connect(proxy.addr()).await.unwrap();
    let target = "127.0.0.1:2222";
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();

    // Read the CONNECT response head.
    let mut head = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "proxy closed tunnel before CONNECT response");
        head.extend_from_slice(&tmp[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head_str = String::from_utf8_lossy(&head).to_string();
    t.assert_starts_with("CONNECT response", &head_str, "HTTP/1.1 200");

    // Send raw bytes through the tunnel and confirm they echo back verbatim.
    let payload = b"ping blind tunnel";
    stream.write_all(payload).await.unwrap();
    let mut echoed = [0u8; 17];
    stream.read_exact(&mut echoed).await.unwrap();
    t.assert_eq("echoed bytes match", &&echoed[..], &&payload[..]);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "event",
        &entries[0]["event"].as_str().unwrap(),
        &"request_permitted",
    );
    t.assert_eq(
        "decision",
        &entries[0]["decision"].as_str().unwrap(),
        &"allowed",
    );
    t.assert_eq(
        "reason",
        &entries[0]["reason"].as_str().unwrap(),
        &"unsupported_connect_port",
    );

    proxy.shutdown();
}

// ---------------------------------------------------------------------------
// Control: proxy authentication still blocks even in permissive mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_permissive_still_enforces_proxy_auth() {
    let t = test_report!("Permissive mode still returns 407 when proxy auth fails");
    let ca = TestCa::generate();

    // Plain-HTTP upstream so a missing-auth 407 comes back as a normal response
    // (reqwest surfaces 407 on a CONNECT as a connection error instead).
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("should not reach"))
        .mount(&upstream)
        .await;
    let port = upstream.address().port();

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", &format!("http://localhost:{}/*", port))],
        port,
    )
    .permissive(true)
    .auth("user", "pass")
    .report(&t)
    .start()
    .await;

    // Client with NO proxy credentials — auth is access control to the proxy, not
    // traffic filtering, so it must still be enforced in permissive mode.
    let client = ReportingClient::new_plain(&t, proxy.addr());
    let resp = client.get(&format!("http://localhost:{}/test", port)).await;
    t.assert_eq("status", &resp.status().as_u16(), &407u16);

    proxy.shutdown();
}
