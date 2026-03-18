//! Tests for Git-LFS batch endpoint filtering and locks API.
//!
//! These tests verify that git rules automatically generate LFS batch endpoint
//! rules and that the proxy correctly inspects the JSON body to allow/block
//! LFS download and upload operations. Also tests LFS locks API endpoints.

mod common;

use common::{
    create_test_repo_with_lfs, git_http_backend_path, git_lfs_available, git_rule,
    git_rule_with_branches, lfs_git_handler, ok_handler, rule, ReportingClient, RequestLog, TestCa,
    TestProxy, TestUpstream,
};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// Helper to build an LFS batch JSON body.
fn lfs_batch_body(operation: &str) -> String {
    format!(
        r#"{{"operation":"{}","transfers":["basic"],"objects":[{{"oid":"abc123","size":42}}]}}"#,
        operation
    )
}

// ---------------------------------------------------------------------------
// Manual HTTP tests (crafted JSON, no real git-lfs binary needed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_lfs_download_allowed_by_fetch_rule() {
    let t = test_report!("LFS download allowed by git=fetch rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("lfs-batch-ok"))
        .report(&t, "LFS batch mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("download"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with operation=download");

    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("upstream reached", &body.as_str(), &"lfs-batch-ok");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_upload_blocked_by_fetch_rule() {
    let t = test_report!("LFS upload blocked by git=fetch rule (download only)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("should-not-reach"))
        .report(&t, "LFS mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
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
    t.action("POST LFS batch with operation=upload (should be blocked)");

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_upload_allowed_by_push_rule() {
    let t = test_report!("LFS upload allowed by git=push rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("lfs-upload-ok"))
        .report(&t, "LFS mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", "https://localhost/org/repo")],
        upstream.port(),
    )
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
    t.action("POST LFS batch with operation=upload");

    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_download_blocked_by_push_rule() {
    let t = test_report!("LFS download blocked by git=push rule (upload only)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("should-not-reach"))
        .report(&t, "LFS mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("download"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with operation=download (should be blocked)");

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_both_ops_allowed_by_star_rule() {
    let t = test_report!("Both LFS operations allowed by git=* rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("lfs-ok"))
        .report(&t, "LFS mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("*", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp_dl = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("download"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with operation=download");
    t.assert_eq("download status 200", &resp_dl.status().as_u16(), &200u16);

    let resp_ul = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("upload"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with operation=upload");
    t.assert_eq("upload status 200", &resp_ul.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_blocked_on_plain_http() {
    let t = test_report!("LFS batch blocked on plain HTTP (body inspection requires HTTPS)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("should-not-reach"))
        .report(&t, "LFS mock")
        .start()
        .await;

    // Use an http:// URL in the rule so it matches plain HTTP requests
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("*", "http://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let resp = client
        .inner()
        .post("http://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("download"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch over plain HTTP (should be blocked)");

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_invalid_json_blocked() {
    let t = test_report!("LFS batch with invalid JSON body is blocked");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("should-not-reach"))
        .report(&t, "LFS mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("*", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body("not valid json")
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with invalid JSON (should be blocked)");

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_missing_operation_blocked() {
    let t = test_report!("LFS batch with missing operation field is blocked");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("should-not-reach"))
        .report(&t, "LFS mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("*", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(r#"{"objects":[{"oid":"abc","size":42}]}"#)
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch without operation field (should be blocked)");

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_get_to_batch_blocked() {
    let t = test_report!("GET to LFS batch endpoint is blocked (only POST)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("should-not-reach"))
        .report(&t, "LFS mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("*", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .get("https://localhost/org/repo/info/lfs/objects/batch")
        .await;

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_branch_restricted_push_allows_lfs_upload() {
    let t =
        test_report!("Branch-restricted push rule allows LFS upload (branches don't apply to LFS)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("lfs-ok"))
        .report(&t, "LFS mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "push",
            "https://localhost/org/repo",
            &["feature/*"],
        )],
        upstream.port(),
    )
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
    t.action("POST LFS batch upload with branch-restricted push rule");

    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_merged_scan_fetch_plus_push() {
    let t = test_report!("Separate fetch+push rules merge to allow both LFS operations");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("lfs-ok"))
        .report(&t, "LFS mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![
            git_rule("fetch", "https://localhost/org/repo"),
            git_rule("push", "https://localhost/org/repo"),
        ],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp_dl = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("download"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch download (merged fetch+push rules)");
    t.assert_eq("download status 200", &resp_dl.status().as_u16(), &200u16);

    let resp_ul = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("upload"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch upload (merged fetch+push rules)");
    t.assert_eq("upload status 200", &resp_ul.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_transfer_url_requires_separate_rule() {
    let t = test_report!("LFS transfer URLs on different paths require separate HTTP rules");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("object-data"))
        .report(&t, "LFS object store mock")
        .start()
        .await;

    // Only git rule — no separate rule for /lfs/objects/*
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // GET to a transfer URL should be blocked (not covered by git rule)
    let resp = client
        .get("https://localhost/org/repo/lfs/objects/abc123def456")
        .await;
    t.action("GET transfer URL without separate rule (should be blocked)");
    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_transfer_url_allowed_with_separate_rule() {
    let t = test_report!("LFS transfer URLs allowed when separate HTTP rule is present");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("object-data"))
        .report(&t, "LFS object store mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![
            git_rule("fetch", "https://localhost/org/repo"),
            rule("GET", "https://localhost/*/lfs/objects/*"),
        ],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client
        .get("https://localhost/org/repo/lfs/objects/abc123def456")
        .await;
    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// LFS Locks API tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_lfs_locks_list_allowed_by_fetch_rule() {
    let t = test_report!("LFS lock list (GET) allowed by git=fetch rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("locks-list-ok"))
        .report(&t, "LFS locks mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .get("https://localhost/org/repo/info/lfs/locks")
        .await;
    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_locks_verify_allowed_by_fetch_rule() {
    let t = test_report!("LFS lock verify (POST) allowed by git=fetch rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("locks-verify-ok"))
        .report(&t, "LFS locks mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/locks/verify")
        .body("{}")
        .send()
        .await
        .unwrap();
    t.action("POST /info/lfs/locks/verify");
    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_locks_create_blocked_by_fetch_rule() {
    let t = test_report!("LFS lock create (POST) blocked by git=fetch rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("should-not-reach"))
        .report(&t, "LFS locks mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/locks")
        .body(r#"{"path":"test.bin"}"#)
        .send()
        .await
        .unwrap();
    t.action("POST /info/lfs/locks (create, should be blocked)");
    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_locks_unlock_blocked_by_fetch_rule() {
    let t = test_report!("LFS lock unlock blocked by git=fetch rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("should-not-reach"))
        .report(&t, "LFS locks mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/locks/123/unlock")
        .body(r#"{"force":false}"#)
        .send()
        .await
        .unwrap();
    t.action("POST /info/lfs/locks/123/unlock (should be blocked)");
    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_locks_all_allowed_by_push_rule() {
    let t = test_report!("All LFS lock endpoints allowed by git=push rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("locks-ok"))
        .report(&t, "LFS locks mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client
        .get("https://localhost/org/repo/info/lfs/locks")
        .await;
    t.assert_eq("GET list status 200", &resp.status().as_u16(), &200u16);

    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/locks")
        .body(r#"{"path":"test.bin"}"#)
        .send()
        .await
        .unwrap();
    t.action("POST /info/lfs/locks (create)");
    t.assert_eq("POST create status 200", &resp.status().as_u16(), &200u16);

    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/locks/verify")
        .body("{}")
        .send()
        .await
        .unwrap();
    t.action("POST /info/lfs/locks/verify");
    t.assert_eq("POST verify status 200", &resp.status().as_u16(), &200u16);

    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/locks/42/unlock")
        .body(r#"{"force":false}"#)
        .send()
        .await
        .unwrap();
    t.action("POST /info/lfs/locks/42/unlock");
    t.assert_eq("POST unlock status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_locks_all_allowed_by_star_rule() {
    let t = test_report!("All LFS lock endpoints allowed by git=* rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("locks-ok"))
        .report(&t, "LFS locks mock")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("*", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client
        .get("https://localhost/org/repo/info/lfs/locks")
        .await;
    t.assert_eq("GET list status 200", &resp.status().as_u16(), &200u16);

    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/locks")
        .body(r#"{"path":"test.bin"}"#)
        .send()
        .await
        .unwrap();
    t.action("POST /info/lfs/locks (create)");
    t.assert_eq("POST create status 200", &resp.status().as_u16(), &200u16);

    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/locks/verify")
        .body("{}")
        .send()
        .await
        .unwrap();
    t.action("POST /info/lfs/locks/verify");
    t.assert_eq("POST verify status 200", &resp.status().as_u16(), &200u16);

    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/locks/42/unlock")
        .body(r#"{"force":false}"#)
        .send()
        .await
        .unwrap();
    t.action("POST /info/lfs/locks/42/unlock");
    t.assert_eq("POST unlock status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// E2e tests with real git-lfs binary
// ---------------------------------------------------------------------------

// Use a non-localhost hostname for LFS e2e tests. Go's HTTP client (used by
// git-lfs) has a hard-coded exclusion that never proxies requests to "localhost"
// or loopback IPs. Using a non-resolvable hostname is fine because the CONNECT
// proxy handles all connections — the client never resolves the hostname itself.
const LFS_TEST_HOST: &str = "gitserver.test";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_lfs_clone_downloads_content() {
    let t = test_report!("Git clone with LFS downloads actual content (not pointer)");

    if !git_lfs_available() {
        t.skip("git-lfs not installed");
        return;
    }

    let backend_path = git_http_backend_path();
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let (repos_dir, lfs_store) = create_test_repo_with_lfs(tmp.path(), "repo.git");
    t.setup(format!(
        "Created test git repo with LFS at {:?} ({} LFS objects)",
        repos_dir,
        lfs_store.lock().unwrap().len()
    ));

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        lfs_git_handler(backend_path, repos_dir, request_log.clone(), lfs_store),
    )
    .hostname(LFS_TEST_HOST)
    .report(&t, "git http-backend + LFS mock")
    .start()
    .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![
            git_rule("fetch", &format!("https://{}/*", LFS_TEST_HOST)),
            rule("GET", &format!("https://{}/*/lfs/objects/*", LFS_TEST_HOST)),
        ],
        upstream.port(),
    )
    .upstream_host("127.0.0.1")
    .report(&t)
    .start()
    .await;

    let clone_dir = tmp.path().join("cloned");
    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());
    let clone_url = format!("https://{}/repo.git", LFS_TEST_HOST);

    let output = common::run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["clone", &clone_url, clone_dir.to_str().unwrap()])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );

    t.assert_eq("git clone exit code", &output.status.code().unwrap(), &0);

    // The LFS-tracked file should contain actual content, not a pointer
    let lfs_file = clone_dir.join("test-data.bin");
    t.assert_true("LFS file exists", lfs_file.exists());

    let content = std::fs::read_to_string(&lfs_file).unwrap();
    t.assert_contains(
        "LFS file has actual content (not pointer)",
        &content,
        "Hello from LFS!",
    );
    t.assert_not_contains(
        "LFS file is not a pointer",
        &content,
        "version https://git-lfs",
    );

    // Verify traffic actually went through the proxy to upstream
    let logged = request_log.lock().unwrap();
    let saw_lfs_batch = logged.iter().any(|r| r.contains("info/lfs/objects/batch"));
    t.assert_true(
        "LFS batch request reached upstream via proxy",
        saw_lfs_batch,
    );
    let saw_lfs_download = logged
        .iter()
        .any(|r| r.contains("lfs/objects/") && r.starts_with("GET"));
    t.assert_true(
        "LFS object download reached upstream via proxy",
        saw_lfs_download,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_lfs_push_uploads_content() {
    let t = test_report!("Git push with LFS uploads objects to server");

    if !git_lfs_available() {
        t.skip("git-lfs not installed");
        return;
    }

    let backend_path = git_http_backend_path();
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let (repos_dir, lfs_store) = create_test_repo_with_lfs(tmp.path(), "repo.git");
    let initial_lfs_count = lfs_store.lock().unwrap().len();
    t.setup(format!(
        "Created test git repo with LFS ({} initial LFS objects)",
        initial_lfs_count
    ));

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        lfs_git_handler(
            backend_path,
            repos_dir,
            request_log.clone(),
            lfs_store.clone(),
        ),
    )
    .hostname(LFS_TEST_HOST)
    .report(&t, "git http-backend + LFS mock")
    .start()
    .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![
            git_rule("fetch", &format!("https://{}/*", LFS_TEST_HOST)),
            git_rule("push", &format!("https://{}/*", LFS_TEST_HOST)),
            rule("GET", &format!("https://{}/*/lfs/objects/*", LFS_TEST_HOST)),
            rule("PUT", &format!("https://{}/*/lfs/objects/*", LFS_TEST_HOST)),
        ],
        upstream.port(),
    )
    .upstream_host("127.0.0.1")
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());
    let clone_url = format!("https://{}/repo.git", LFS_TEST_HOST);

    // Step 1: Clone through proxy
    let clone_dir = tmp.path().join("cloned");
    let output = common::run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["clone", &clone_url, clone_dir.to_str().unwrap()])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone exit code", &output.status.code().unwrap(), &0);

    // Step 2: Create a new LFS-tracked file and commit
    let run_git = |args: &[&str], cwd: &std::path::Path| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };

    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);

    let new_content = b"New LFS content pushed through proxy!\n";
    std::fs::write(clone_dir.join("pushed-data.bin"), new_content).unwrap();
    run_git(&["add", "pushed-data.bin"], &clone_dir);
    run_git(&["commit", "-m", "Add pushed-data.bin via LFS"], &clone_dir);
    t.action("Created new commit with LFS-tracked pushed-data.bin");

    // Step 3: Push through proxy
    let output = common::run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git push exit code", &output.status.code().unwrap(), &0);

    // Step 4: Verify the LFS store received the new object
    let final_lfs_count = lfs_store.lock().unwrap().len();
    t.assert_true(
        "LFS store has more objects after push",
        final_lfs_count > initial_lfs_count,
    );

    // Verify the uploaded content matches what we wrote
    let store = lfs_store.lock().unwrap();
    let found = store.values().any(|v| v == new_content);
    t.assert_true("LFS store contains pushed content", found);

    // Verify traffic actually went through the proxy to upstream
    let logged = request_log.lock().unwrap();
    let saw_lfs_batch = logged.iter().any(|r| r.contains("info/lfs/objects/batch"));
    t.assert_true(
        "LFS batch request reached upstream via proxy",
        saw_lfs_batch,
    );
    let saw_lfs_upload = logged
        .iter()
        .any(|r| r.contains("lfs/objects/") && r.starts_with("PUT"));
    t.assert_true(
        "LFS object upload reached upstream via proxy",
        saw_lfs_upload,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_lfs_clone_blocked_without_fetch_rule() {
    let t = test_report!("Git clone blocked with push-only rule (no fetch endpoints)");

    if !git_lfs_available() {
        t.skip("git-lfs not installed");
        return;
    }

    let backend_path = git_http_backend_path();
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let (repos_dir, lfs_store) = create_test_repo_with_lfs(tmp.path(), "repo.git");
    t.setup("Created test git repo with LFS");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        lfs_git_handler(backend_path, repos_dir, request_log.clone(), lfs_store),
    )
    .hostname(LFS_TEST_HOST)
    .report(&t, "git http-backend + LFS mock")
    .start()
    .await;

    // Push-only rule: no fetch endpoints, no LFS download
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", &format!("https://{}/*", LFS_TEST_HOST))],
        upstream.port(),
    )
    .upstream_host("127.0.0.1")
    .report(&t)
    .start()
    .await;

    let clone_dir = tmp.path().join("cloned");
    let clone_url = format!("https://{}/repo.git", LFS_TEST_HOST);

    let output = common::run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["clone", &clone_url, clone_dir.to_str().unwrap()])
            .env(
                "HTTPS_PROXY",
                format!("http://127.0.0.1:{}", proxy.addr().port()),
            )
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );

    // Clone should fail — push-only rule doesn't allow git-upload-pack endpoints
    t.assert_true("git clone failed (no fetch rule)", !output.status.success());

    // Verify proxy blocked the requests — upstream should not have seen git-upload-pack
    let logged = request_log.lock().unwrap();
    let saw_upload_pack = logged.iter().any(|r| r.contains("git-upload-pack"));
    t.assert_true(
        "No git-upload-pack reached upstream (proxy blocked it)",
        !saw_upload_pack,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_lfs_locks_verify_via_git_client() {
    let t = test_report!("git lfs locks --verify works through proxy (no 'locking API' warning)");

    if !git_lfs_available() {
        t.skip("git-lfs not installed");
        return;
    }

    let backend_path = git_http_backend_path();
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let (repos_dir, lfs_store) = create_test_repo_with_lfs(tmp.path(), "repo.git");
    t.setup("Created test git repo with LFS");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        lfs_git_handler(backend_path, repos_dir, request_log.clone(), lfs_store),
    )
    .hostname(LFS_TEST_HOST)
    .report(&t, "git http-backend + LFS mock (with locks)")
    .start()
    .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![
            git_rule("fetch", &format!("https://{}/*", LFS_TEST_HOST)),
            rule("GET", &format!("https://{}/*/lfs/objects/*", LFS_TEST_HOST)),
        ],
        upstream.port(),
    )
    .upstream_host("127.0.0.1")
    .report(&t)
    .start()
    .await;

    // Clone through proxy first to get a working repo
    let clone_dir = tmp.path().join("cloned");
    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());
    let clone_url = format!("https://{}/repo.git", LFS_TEST_HOST);

    let output = common::run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["clone", &clone_url, clone_dir.to_str().unwrap()])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone exit code", &output.status.code().unwrap(), &0);

    // Run `git lfs locks --verify` — this hits /info/lfs/locks/verify
    let output = common::run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["lfs", "locks", "--verify"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq(
        "git lfs locks --verify exit code",
        &output.status.code().unwrap(),
        &0,
    );

    // Verify the stderr doesn't contain the "locking API" warning
    let stderr = String::from_utf8_lossy(&output.stderr);
    t.assert_not_contains(
        "no locking API warning",
        &stderr,
        "does not support the Git LFS locking API",
    );

    // Verify lock-related requests actually went through the proxy
    let logged = request_log.lock().unwrap();
    let saw_locks = logged.iter().any(|r| r.contains("info/lfs/locks"));
    t.assert_true("LFS locks request reached upstream via proxy", saw_locks);

    proxy.shutdown();
    upstream.shutdown();
}
