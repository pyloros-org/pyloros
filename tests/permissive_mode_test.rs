//! Tests for permissive mode: unmatched requests are allowed through
//! with distinct audit logging instead of being blocked.

mod common;

use common::{
    ReportingClient, TestCa, TestProxy, TestUpstream, git_rule_with_branches, ok_handler,
    read_audit_entries, rule,
};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

// ---------------------------------------------------------------------------
// Test 1: Permissive mode allows unmatched HTTPS requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_permissive_allows_unmatched_https() {
    let t = test_report!("Permissive mode allows unmatched HTTPS request");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello permissive"))
        .report(&t, "returns 'hello permissive'")
        .start()
        .await;

    // No rules + permissive = should allow through
    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .permissive(true)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("body", &body.as_str(), &"hello permissive");

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Test 2: Permissive mode emits correct audit log for HTTPS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_permissive_audit_log_https() {
    let t = test_report!("Permissive mode audit log has request_permitted event");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("audit"))
        .report(&t, "returns 'audit'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .permissive(true)
        .audit_log(audit_path_str)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);

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
        &"no_matching_rule",
    );

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Test 3: Permissive mode allows unmatched plain HTTP requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_permissive_allows_unmatched_http() {
    let t = test_report!("Permissive mode allows unmatched plain HTTP request");
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("hello plain"))
        .mount(&upstream)
        .await;
    let port = upstream.address().port();

    // No rules + permissive
    let proxy = TestProxy::builder(&ca, vec![], port)
        .permissive(true)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let url = format!("http://localhost:{}/test", port);
    let resp = client.get(&url).await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("body", &body.as_str(), &"hello plain");

    proxy.shutdown();
}

// ---------------------------------------------------------------------------
// Test 4: Request matching a rule still logs as request_allowed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_permissive_matched_rule_logged_as_allowed() {
    let t = test_report!("Matched rule in permissive mode logs as request_allowed");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("matched"))
        .report(&t, "returns 'matched'")
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
    .permissive(true)
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "event",
        &entries[0]["event"].as_str().unwrap(),
        &"request_allowed",
    );
    t.assert_eq(
        "reason",
        &entries[0]["reason"].as_str().unwrap(),
        &"rule_matched",
    );

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Test 5: Permissive=false blocks normally (control test)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_permissive_off_blocks_normally() {
    let t = test_report!("Permissive=false blocks unmatched requests as usual");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("should not reach"))
        .report(&t, "returns 'should not reach'")
        .start()
        .await;

    // No rules, permissive=false (default)
    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("status", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Test 6: Permissive mode forwards branch restriction failures (no-proxy)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_permissive_forwards_branch_restriction() {
    let t = test_report!("Permissive mode forwards branch-restricted pushes (as if no proxy)");
    let ca = TestCa::generate();

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    // A push to a disallowed ref comes through AllowedWithBranchCheck (not
    // FilterResult::Blocked). In permissive mode the proxy must behave as if it
    // weren't there: forward the push to the upstream instead of returning a
    // git-protocol rejection, while still recording a request_permitted audit
    // entry that keeps the branch_restriction reason and the blocked refs.

    let upstream = TestUpstream::builder(&ca, ok_handler("push-forwarded"))
        .report(&t, "git upstream")
        .start()
        .await;

    // Push rule with branch restriction: only feature/* allowed
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "push",
            "https://localhost/*",
            &["feature/*"],
        )],
        upstream.port(),
    )
    .permissive(true)
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    // Simulate a git-receive-pack POST with a pkt-line pushing to refs/heads/main
    // (which would be blocked by the branch restriction in enforcing mode)
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Build a minimal pkt-line payload pushing to refs/heads/main
    // Format: <old-sha> <new-sha> refs/heads/main\0 report-status
    let zero_sha = "0000000000000000000000000000000000000000";
    let fake_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let ref_line = format!(
        "{} {} refs/heads/main\0 report-status side-band-64k",
        zero_sha, fake_sha
    );
    let pkt_len = ref_line.len() + 4; // 4 bytes for the length prefix itself
    let pkt_line = format!("{:04x}{}", pkt_len, ref_line);
    let body = format!("{}0000", pkt_line); // flush-pkt to end

    let resp = client
        .post_with_body(
            "https://localhost/repo.git/git-receive-pack",
            body.into_bytes(),
        )
        .await;

    // The push is forwarded to the upstream, which returns 200 with its body.
    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let resp_body = resp.text().await.unwrap();
    t.assert_eq(
        "upstream was reached",
        &resp_body.as_str(),
        &"push-forwarded",
    );

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
        &"branch_restriction",
    );
    t.assert_eq(
        "blocked ref recorded",
        &entries[0]["git"]["blocked_refs"][0].as_str().unwrap(),
        &"refs/heads/main",
    );

    proxy.shutdown();
    upstream.shutdown();
}
