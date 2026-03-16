//! Tests for git-specific rule filtering: repo-level and branch-level restrictions.
//!
//! These tests verify that git rules correctly control which operations are
//! allowed based on git operation type, repo URL matching, and branch patterns.

mod common;

use common::{
    create_test_repo, git_cgi_handler, git_http_backend_path, git_rule, git_rule_with_branches,
    ok_handler, run_command_reported, ReportingClient, RequestLog, TestCa, TestProxy, TestUpstream,
};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// Helper: run a git command, assert it succeeds.
fn run_git(args: &[&str], cwd: &Path) {
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_fetch_rule_blocks_push() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Fetch-only rule blocks push");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    let bare_repo = repos_dir.join("repo.git");
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Created test repo with receivepack enabled");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Only allow fetch, not push
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone should succeed
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone succeeds", &output.status.code().unwrap(), &0);

    // Make a commit and try to push — should fail
    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);
    std::fs::write(clone_dir.join("newfile.txt"), "should not arrive\n").unwrap();
    run_git(&["add", "newfile.txt"], &clone_dir);
    run_git(&["commit", "-m", "Should be blocked"], &clone_dir);
    t.action("Created commit to push");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_true(
        "git push fails (blocked)",
        output.status.code().unwrap() != 0,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_rule_blocks_fetch() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Push-only rule blocks fetch/clone");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    t.setup("Created test repo");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Only allow push, not fetch
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone should fail (fetch not allowed)
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_true(
        "git clone fails (fetch blocked)",
        output.status.code().unwrap() != 0,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_rule_repo_filtering() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Git rule filters by repo URL");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();

    // Create two repos in the same GIT_PROJECT_ROOT
    let repos_dir = create_test_repo(tmp.path(), "allowed.git");
    // Create a second repo
    let source2 = tmp.path().join("source2");
    std::fs::create_dir_all(&source2).unwrap();
    run_git(&["init"], &source2);
    run_git(&["config", "user.email", "test@test.com"], &source2);
    run_git(&["config", "user.name", "Test User"], &source2);
    std::fs::write(source2.join("file.txt"), "other repo\n").unwrap();
    run_git(&["add", "file.txt"], &source2);
    run_git(&["commit", "-m", "Init other"], &source2);
    run_git(
        &[
            "clone",
            "--bare",
            source2.to_str().unwrap(),
            repos_dir.join("other.git").to_str().unwrap(),
        ],
        tmp.path(),
    );
    t.setup("Created allowed.git and other.git repos");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Only allow operations on allowed.git
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("*", "https://localhost/allowed.git")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone allowed.git should succeed
    let clone_allowed = tmp.path().join("clone-allowed");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/allowed.git",
                clone_allowed.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq(
        "clone allowed.git succeeds",
        &output.status.code().unwrap(),
        &0,
    );

    // Clone other.git should fail
    let clone_other = tmp.path().join("clone-other");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/other.git",
                clone_other.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_true(
        "clone other.git fails (blocked)",
        output.status.code().unwrap() != 0,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_branch_allowed() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Branch-restricted push allows matching branch");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    let bare_repo = repos_dir.join("repo.git");
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Created test repo with receivepack enabled");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Allow all git ops, but push only to feature/* branches
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "*",
            "https://localhost/*",
            &["feature/*"],
        )],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone succeeds", &output.status.code().unwrap(), &0);

    // Create and push to feature/test branch
    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);
    run_git(&["checkout", "-b", "feature/test"], &clone_dir);
    std::fs::write(clone_dir.join("feature.txt"), "feature work\n").unwrap();
    run_git(&["add", "feature.txt"], &clone_dir);
    run_git(&["commit", "-m", "Feature commit"], &clone_dir);
    t.action("Created commit on feature/test branch");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push", "origin", "feature/test"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq(
        "git push to feature/test succeeds",
        &output.status.code().unwrap(),
        &0,
    );

    // Verify the bare repo received the push
    let verify = std::process::Command::new("git")
        .args(["show", "feature/test:feature.txt"])
        .current_dir(&bare_repo)
        .output()
        .unwrap();
    let content = String::from_utf8_lossy(&verify.stdout);
    t.assert_contains("bare repo has feature file", &content, "feature work");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_branch_blocked() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Branch-restricted push blocks non-matching branch");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    let bare_repo = repos_dir.join("repo.git");
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Created test repo with receivepack enabled");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Allow all git ops, but push only to feature/* branches
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "*",
            "https://localhost/*",
            &["feature/*"],
        )],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone succeeds", &output.status.code().unwrap(), &0);

    // Commit on main and try to push — should be blocked
    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);
    std::fs::write(clone_dir.join("blocked.txt"), "should not arrive\n").unwrap();
    run_git(&["add", "blocked.txt"], &clone_dir);
    run_git(
        &["commit", "-m", "Push to main (should be blocked)"],
        &clone_dir,
    );
    t.action("Created commit on main branch");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push", "origin", "main"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_true(
        "git push to main fails (branch blocked)",
        output.status.code().unwrap() != 0,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_branch_blocked_shows_error_message() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Branch-restricted push shows clear error message via git protocol");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    let bare_repo = repos_dir.join("repo.git");
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Created test repo with receivepack enabled");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Allow all git ops, but push only to feature/* branches
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "*",
            "https://localhost/*",
            &["feature/*"],
        )],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone succeeds", &output.status.code().unwrap(), &0);

    // Commit on main and try to push — should be blocked with clear message
    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);
    std::fs::write(clone_dir.join("blocked.txt"), "should not arrive\n").unwrap();
    run_git(&["add", "blocked.txt"], &clone_dir);
    run_git(
        &["commit", "-m", "Push to main (should be blocked)"],
        &clone_dir,
    );
    t.action("Created commit on main branch");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push", "origin", "main"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    t.assert_true(
        "git push fails (branch blocked)",
        output.status.code().unwrap() != 0,
    );
    t.assert_contains(
        "stderr contains 'blocked by proxy policy'",
        &stderr,
        "blocked by proxy policy",
    );
    t.assert_contains(
        "stderr contains 'remote rejected'",
        &stderr,
        "remote rejected",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_branch_restricted_rule_blocked_on_plain_http() {
    let t = test_report!("Branch-restricted git rule blocks plain HTTP (can't inspect body)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    // Use a dummy upstream port — the request should be blocked before forwarding
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "push",
            "http://plain-http-host.invalid/*",
            &["feature/*"],
        )],
        1, // dummy port, not used for plain HTTP
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());

    // POST to the git-receive-pack endpoint via plain HTTP
    let resp = client
        .post("http://plain-http-host.invalid/repo.git/git-receive-pack")
        .await;
    t.assert_eq(
        "plain HTTP POST to branch-restricted endpoint returns 451",
        &resp.status().as_u16(),
        &451u16,
    );

    proxy.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_fetch_only_rule_blocks_push_endpoints_directly() {
    let t = test_report!("Fetch-only rule blocks push endpoints via direct HTTP requests");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("unreachable"))
        .report(&t, "dummy upstream")
        .start()
        .await;

    // Only allow fetch, not push
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // POST to git-receive-pack should be blocked
    let resp = client
        .post("https://localhost/repo.git/git-receive-pack")
        .await;
    t.assert_eq(
        "POST /git-receive-pack returns 451",
        &resp.status().as_u16(),
        &451u16,
    );

    // GET info/refs?service=git-receive-pack should be blocked
    let resp = client
        .get("https://localhost/repo.git/info/refs?service=git-receive-pack")
        .await;
    t.assert_eq(
        "GET /info/refs?service=git-receive-pack returns 451",
        &resp.status().as_u16(),
        &451u16,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_push_only_rule_blocks_fetch_endpoints_directly() {
    let t = test_report!("Push-only rule blocks fetch endpoints via direct HTTP requests");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, ok_handler("unreachable"))
        .report(&t, "dummy upstream")
        .start()
        .await;

    // Only allow push, not fetch
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // POST to git-upload-pack should be blocked
    let resp = client
        .post("https://localhost/repo.git/git-upload-pack")
        .await;
    t.assert_eq(
        "POST /git-upload-pack returns 451",
        &resp.status().as_u16(),
        &451u16,
    );

    // GET info/refs?service=git-upload-pack should be blocked
    let resp = client
        .get("https://localhost/repo.git/info/refs?service=git-upload-pack")
        .await;
    t.assert_eq(
        "GET /info/refs?service=git-upload-pack returns 451",
        &resp.status().as_u16(),
        &451u16,
    );

    proxy.shutdown();
    upstream.shutdown();
}

// ==========================================================================
// Branch exclusion (! prefix deny pattern) tests
// ==========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_exclude_branch_blocked() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Branch exclusion: push to denied branch is blocked");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    let bare_repo = repos_dir.join("repo.git");
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Created test repo with receivepack enabled");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Allow push to any branch EXCEPT main: ["*", "!main"]
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "*",
            "https://localhost/*",
            &["*", "!main"],
        )],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone succeeds", &output.status.code().unwrap(), &0);

    // Commit on main and try to push — should be blocked by deny pattern
    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);
    std::fs::write(clone_dir.join("blocked.txt"), "should not arrive\n").unwrap();
    run_git(&["add", "blocked.txt"], &clone_dir);
    run_git(
        &["commit", "-m", "Push to main (should be blocked)"],
        &clone_dir,
    );
    t.action("Created commit on main branch");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push", "origin", "main"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_true(
        "git push to main fails (denied by ! pattern)",
        output.status.code().unwrap() != 0,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_exclude_branch_allowed() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Branch exclusion: push to non-denied branch is allowed");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    let bare_repo = repos_dir.join("repo.git");
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Created test repo with receivepack enabled");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Allow push to any branch EXCEPT main: ["*", "!main"]
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "*",
            "https://localhost/*",
            &["*", "!main"],
        )],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone succeeds", &output.status.code().unwrap(), &0);

    // Create and push to feature/test branch — should succeed
    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);
    run_git(&["checkout", "-b", "feature/test"], &clone_dir);
    std::fs::write(clone_dir.join("feature.txt"), "feature work\n").unwrap();
    run_git(&["add", "feature.txt"], &clone_dir);
    run_git(&["commit", "-m", "Feature commit"], &clone_dir);
    t.action("Created commit on feature/test branch");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push", "origin", "feature/test"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq(
        "git push to feature/test succeeds (not denied)",
        &output.status.code().unwrap(),
        &0,
    );

    // Verify the bare repo received the push
    let verify = std::process::Command::new("git")
        .args(["show", "feature/test:feature.txt"])
        .current_dir(&bare_repo)
        .output()
        .unwrap();
    let content = String::from_utf8_lossy(&verify.stdout);
    t.assert_contains("bare repo has feature file", &content, "feature work");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_exclude_deny_wins() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Branch exclusion: deny wins when ref matches both allow and deny");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    let bare_repo = repos_dir.join("repo.git");
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Created test repo with receivepack enabled");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Allow feature/* but deny feature/dangerous
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "*",
            "https://localhost/*",
            &["feature/*", "!feature/dangerous"],
        )],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone succeeds", &output.status.code().unwrap(), &0);

    // Create and push to feature/dangerous — should be blocked (deny wins)
    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);
    run_git(&["checkout", "-b", "feature/dangerous"], &clone_dir);
    std::fs::write(clone_dir.join("dangerous.txt"), "dangerous\n").unwrap();
    run_git(&["add", "dangerous.txt"], &clone_dir);
    run_git(&["commit", "-m", "Dangerous commit"], &clone_dir);
    t.action("Created commit on feature/dangerous branch");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push", "origin", "feature/dangerous"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_true(
        "git push to feature/dangerous fails (deny wins over allow)",
        output.status.code().unwrap() != 0,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_exclude_only_syntax() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Branch exclusion: deny-only syntax with implicit allow-all");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    let bare_repo = repos_dir.join("repo.git");
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Created test repo with receivepack enabled");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Only deny main — everything else implicitly allowed: ["!main"]
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "*",
            "https://localhost/*",
            &["!main"],
        )],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone succeeds", &output.status.code().unwrap(), &0);

    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);

    // Push to feature/test — should succeed (implicit allow-all)
    run_git(&["checkout", "-b", "feature/test"], &clone_dir);
    std::fs::write(clone_dir.join("feature.txt"), "feature work\n").unwrap();
    run_git(&["add", "feature.txt"], &clone_dir);
    run_git(&["commit", "-m", "Feature commit"], &clone_dir);
    t.action("Created commit on feature/test branch");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push", "origin", "feature/test"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq(
        "git push to feature/test succeeds (implicit allow-all)",
        &output.status.code().unwrap(),
        &0,
    );

    // Push to main — should be blocked
    run_git(&["checkout", "main"], &clone_dir);
    std::fs::write(clone_dir.join("blocked.txt"), "should not arrive\n").unwrap();
    run_git(&["add", "blocked.txt"], &clone_dir);
    run_git(
        &["commit", "-m", "Push to main (should be blocked)"],
        &clone_dir,
    );
    t.action("Created commit on main branch");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push", "origin", "main"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_true(
        "git push to main fails (denied)",
        output.status.code().unwrap() != 0,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_exclude_shows_error_message() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Branch exclusion: denied push shows 'blocked by proxy policy' message");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    let bare_repo = repos_dir.join("repo.git");
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Created test repo with receivepack enabled");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    // Allow push to any branch EXCEPT main
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "*",
            "https://localhost/*",
            &["*", "!main"],
        )],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Clone
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone succeeds", &output.status.code().unwrap(), &0);

    // Commit on main and try to push — should fail with clear message
    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);
    std::fs::write(clone_dir.join("blocked.txt"), "should not arrive\n").unwrap();
    run_git(&["add", "blocked.txt"], &clone_dir);
    run_git(
        &["commit", "-m", "Push to main (should be blocked)"],
        &clone_dir,
    );
    t.action("Created commit on main branch");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push", "origin", "main"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    t.assert_true(
        "git push fails (denied by ! pattern)",
        output.status.code().unwrap() != 0,
    );
    t.assert_contains(
        "stderr contains 'blocked by proxy policy'",
        &stderr,
        "blocked by proxy policy",
    );
    t.assert_contains(
        "stderr contains 'remote rejected'",
        &stderr,
        "remote rejected",
    );

    proxy.shutdown();
    upstream.shutdown();
}
