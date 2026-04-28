mod common;

use common::{
    ok_handler, read_audit_entries, rule, test_client, ReportingClient, TestCa, TestProxy,
    TestUpstream,
};

#[tokio::test]
async fn test_audit_log_allowed_https() {
    let t = test_report!("Audit log records allowed HTTPS request");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello"))
        .report(&t, "returns 'hello'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);

    // Small delay to ensure audit write completes
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let raw = std::fs::read_to_string(audit_path_str).unwrap();
    t.output("audit_log", &raw);

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "event",
        &entries[0]["event"].as_str().unwrap(),
        &"request_allowed",
    );
    t.assert_eq(
        "decision",
        &entries[0]["decision"].as_str().unwrap(),
        &"allowed",
    );
    t.assert_eq(
        "reason",
        &entries[0]["reason"].as_str().unwrap(),
        &"rule_matched",
    );
    t.assert_eq("method", &entries[0]["method"].as_str().unwrap(), &"GET");
    t.assert_contains("url", entries[0]["url"].as_str().unwrap(), "localhost");
    t.assert_eq("scheme", &entries[0]["scheme"].as_str().unwrap(), &"https");
    t.assert_eq(
        "protocol",
        &entries[0]["protocol"].as_str().unwrap(),
        &"https",
    );
    t.assert_true("has timestamp", entries[0]["timestamp"].as_str().is_some());

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_audit_log_blocked_request() {
    let t = test_report!("Audit log records blocked request");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello"))
        .report(&t, "returns 'hello'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    // No rules → everything blocked
    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .audit_log(audit_path_str)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/blocked").await;
    t.assert_eq("status", &resp.status().as_u16(), &451u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let raw = std::fs::read_to_string(audit_path_str).unwrap();
    t.output("audit_log", &raw);

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "event",
        &entries[0]["event"].as_str().unwrap(),
        &"request_blocked",
    );
    t.assert_eq(
        "decision",
        &entries[0]["decision"].as_str().unwrap(),
        &"blocked",
    );
    t.assert_eq(
        "reason",
        &entries[0]["reason"].as_str().unwrap(),
        &"no_matching_rule",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_audit_log_auth_failure() {
    let t = test_report!("Audit log records auth failure");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello"))
        .report(&t, "returns 'hello'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .auth("user", "pass")
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    // Send a plain HTTP request without auth (avoids reqwest CONNECT error)
    let client = ReportingClient::new_plain(&t, proxy.addr());
    let resp = client.get("http://example.com/test").await;
    t.assert_eq("status", &resp.status().as_u16(), &407u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let raw = std::fs::read_to_string(audit_path_str).unwrap();
    t.output("audit_log", &raw);

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "event",
        &entries[0]["event"].as_str().unwrap(),
        &"auth_failed",
    );
    t.assert_eq(
        "reason",
        &entries[0]["reason"].as_str().unwrap(),
        &"auth_failed",
    );
    t.assert_eq(
        "decision",
        &entries[0]["decision"].as_str().unwrap(),
        &"blocked",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_audit_log_http_blocked() {
    let t = test_report!("Audit log records blocked HTTP (non-HTTPS) request with http scheme");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello"))
        .report(&t, "returns 'hello'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    // No rules matching http:// → blocked
    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .audit_log(audit_path_str)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let resp = client.get("http://example.com/test").await;
    t.assert_eq("status", &resp.status().as_u16(), &451u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let raw = std::fs::read_to_string(audit_path_str).unwrap();
    t.output("audit_log", &raw);

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq("scheme", &entries[0]["scheme"].as_str().unwrap(), &"http");
    t.assert_eq(
        "protocol",
        &entries[0]["protocol"].as_str().unwrap(),
        &"http",
    );
    t.assert_eq(
        "event",
        &entries[0]["event"].as_str().unwrap(),
        &"request_blocked",
    );
    t.assert_eq(
        "reason",
        &entries[0]["reason"].as_str().unwrap(),
        &"no_matching_rule",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_audit_log_credential_info() {
    let t = test_report!("Audit log includes credential info for HTTPS requests");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello"))
        .report(&t, "returns 'hello'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let cred = pyloros::config::Credential::Header {
        url: "https://localhost/*".to_string(),
        header: "x-api-key".to_string(),
        value: "test-secret".to_string(),
        local: pyloros::config::LocalHeaderConfig::Value("test-local".to_string()),
    };

    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .credentials(vec![cred])
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = test_client(proxy.addr(), &ca);
    t.action("GET `https://localhost/api` with x-api-key: test-local");
    let resp = client
        .get("https://localhost/api")
        .header("x-api-key", "test-local")
        .send()
        .await
        .unwrap();
    t.assert_eq("status", &resp.status().as_u16(), &200u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let raw = std::fs::read_to_string(audit_path_str).unwrap();
    t.output("audit_log", &raw);

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_true("has credential", entries[0]["credential"].is_object());
    t.assert_eq(
        "credential type",
        &entries[0]["credential"]["type"].as_str().unwrap(),
        &"header",
    );
    t.assert_eq(
        "credential url_pattern",
        &entries[0]["credential"]["url_pattern"].as_str().unwrap(),
        &"https://localhost/*",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// On a local-credential mismatch the audit entry must identify which
/// credential rule the sandbox failed to satisfy — operators need this to
/// debug without grepping through every credential block.
#[tokio::test]
async fn test_audit_log_local_credential_mismatch_includes_credential() {
    let t = test_report!("Audit log includes credential info on local mismatch (403)");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello"))
        .report(&t, "returns 'hello'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let cred = pyloros::config::Credential::Header {
        url: "https://localhost/*".to_string(),
        header: "x-api-key".to_string(),
        value: "real-secret".to_string(),
        local: pyloros::config::LocalHeaderConfig::Value("expected-local".to_string()),
    };

    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .credentials(vec![cred])
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = test_client(proxy.addr(), &ca);
    t.action("GET `https://localhost/api` with WRONG local credential");
    let resp = client
        .get("https://localhost/api")
        .header("x-api-key", "wrong-value")
        .send()
        .await
        .unwrap();
    t.assert_eq("status", &resp.status().as_u16(), &403u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = read_audit_entries(audit_path_str);
    let mismatch = entries
        .iter()
        .find(|e| e["reason"].as_str() == Some("local_credential_mismatch"))
        .expect("expected a local_credential_mismatch entry");
    t.assert_true("has credential", mismatch["credential"].is_object());
    t.assert_eq(
        "credential type",
        &mismatch["credential"]["type"].as_str().unwrap(),
        &"header",
    );
    t.assert_eq(
        "credential url_pattern",
        &mismatch["credential"]["url_pattern"].as_str().unwrap(),
        &"https://localhost/*",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_audit_log_disabled_by_default() {
    let t = test_report!("Audit log file not created when disabled");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello"))
        .report(&t, "returns 'hello'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");

    // No audit_log set
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    t.assert_true("audit file not created", !audit_path.exists());

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_audit_log_multiple_requests() {
    let t = test_report!("Audit log records multiple requests as independent JSON lines");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello"))
        .report(&t, "returns 'hello'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Send 3 requests
    let resp = client.get("https://localhost/first").await;
    t.assert_eq("first status", &resp.status().as_u16(), &200u16);
    let resp = client.get("https://localhost/second").await;
    t.assert_eq("second status", &resp.status().as_u16(), &200u16);
    let resp = client.get("https://localhost/third").await;
    t.assert_eq("third status", &resp.status().as_u16(), &200u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let raw = std::fs::read_to_string(audit_path_str).unwrap();
    t.output("audit_log", &raw);

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &3usize);

    // Each entry is independently valid JSON (already verified by read_audit_entries)
    // Verify each has distinct URLs
    let urls: Vec<&str> = entries.iter().map(|e| e["url"].as_str().unwrap()).collect();
    t.assert_true("contains /first", urls.iter().any(|u| u.contains("/first")));
    t.assert_true(
        "contains /second",
        urls.iter().any(|u| u.contains("/second")),
    );
    t.assert_true("contains /third", urls.iter().any(|u| u.contains("/third")));

    proxy.shutdown();
    upstream.shutdown();
}
