//! Git tag push through the HTTPS proxy.
//!
//! Pushing a tag sends a `refs/tags/<name>` ref in the git-receive-pack
//! pkt-line rather than a `refs/heads/<branch>` ref. These tests confirm tag
//! pushes work end-to-end through the proxy in two configurations:
//!   1. A plain `git = "push"` rule with no branch restrictions.
//!   2. Permissive mode with no explicit rules.

mod common;

use common::{
    create_test_repo, git_cgi_handler, git_http_backend_path, git_rule, git_rule_with_branches,
    run_command_reported, RequestLog, TestCa, TestProxy, TestUpstream,
};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

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

/// Clone the repo through the proxy, make a commit, and create an annotated
/// tag `v1.0` pointing at it. Returns the clone directory.
async fn clone_and_create_tag(
    t: &common::TestReport,
    proxy_url: &str,
    ca: &TestCa,
    tmp: &TempDir,
) -> std::path::PathBuf {
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone exit code", &output.status.code().unwrap(), &0);

    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);
    std::fs::write(clone_dir.join("tagged.txt"), "tagged content\n").unwrap();
    run_git(&["add", "tagged.txt"], &clone_dir);
    run_git(&["commit", "-m", "Commit to tag"], &clone_dir);
    run_git(&["tag", "-a", "v1.0", "-m", "Release v1.0"], &clone_dir);
    t.action("Created annotated tag v1.0");

    clone_dir
}

/// Push tag `v1.0` to origin through the proxy. Returns the command output so
/// callers can assert success or failure.
fn push_tag(
    t: &common::TestReport,
    proxy_url: &str,
    ca: &TestCa,
    clone_dir: &Path,
) -> std::process::Output {
    run_command_reported(
        t,
        std::process::Command::new("git")
            .args(["push", "origin", "v1.0"])
            .current_dir(clone_dir)
            .env("HTTPS_PROXY", proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    )
}

/// Whether the bare repo holds a tag named `v1.0`.
fn bare_repo_has_v1_tag(bare_repo: &Path) -> bool {
    let verify = std::process::Command::new("git")
        .args(["tag", "-l"])
        .current_dir(bare_repo)
        .output()
        .unwrap();
    String::from_utf8_lossy(&verify.stdout).contains("v1.0")
}

/// Clone, create the tag, push it, and assert it landed in the bare repo.
async fn clone_commit_and_push_tag(
    t: &common::TestReport,
    proxy_url: &str,
    ca: &TestCa,
    tmp: &TempDir,
    bare_repo: &Path,
) {
    let clone_dir = clone_and_create_tag(t, proxy_url, ca, tmp).await;
    let output = push_tag(t, proxy_url, ca, &clone_dir);
    t.assert_eq("git push tag exit code", &output.status.code().unwrap(), &0);
    t.assert_true("bare repo has v1.0 tag", bare_repo_has_v1_tag(bare_repo));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_tag_with_push_rule() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Git tag push through HTTPS proxy (push rule, no branch restrictions)");
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

    // Plain fetch + push rules, no branch restrictions
    let proxy = TestProxy::builder(
        &ca,
        vec![
            git_rule("fetch", "https://localhost/*"),
            git_rule("push", "https://localhost/*"),
        ],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    clone_commit_and_push_tag(&t, &proxy_url, &ca, &tmp, &bare_repo).await;

    // Confirm the push went through git-receive-pack as expected
    let logged = request_log.lock().unwrap();
    let saw_receive_pack = logged
        .iter()
        .any(|r| r.contains("POST") && r.contains("git-receive-pack"));
    t.assert_true(
        "proxy forwarded git-receive-pack POST request",
        saw_receive_pack,
    );
    drop(logged);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_tag_permissive() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Git tag push through HTTPS proxy (permissive mode, no rules)");
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

    // No rules + permissive mode: everything is allowed through
    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .permissive(true)
        .report(&t)
        .start()
        .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    clone_commit_and_push_tag(&t, &proxy_url, &ca, &tmp, &bare_repo).await;

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_tag_blocked_by_branch_restriction() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Bare branch restriction (feature/*) blocks a tag push");
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

    // Push allowed only to feature/* branches. A bare pattern matches only
    // refs/heads/*, so a tag push (refs/tags/v1.0) must NOT match and is blocked.
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

    let clone_dir = clone_and_create_tag(&t, &proxy_url, &ca, &tmp).await;
    let output = push_tag(&t, &proxy_url, &ca, &clone_dir);

    t.assert_true(
        "git push tag fails (blocked by branch restriction)",
        output.status.code().unwrap() != 0,
    );
    t.assert_true(
        "bare repo did NOT receive the v1.0 tag",
        !bare_repo_has_v1_tag(&bare_repo),
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_tag_allowed_by_refs_tags_pattern() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Explicit refs/tags/* restriction allows a tag push");
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

    // A `refs/`-prefixed pattern is matched literally, so refs/tags/* allows
    // tag pushes (and excludes branch pushes).
    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_branches(
            "*",
            "https://localhost/*",
            &["refs/tags/*"],
        )],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    let clone_dir = clone_and_create_tag(&t, &proxy_url, &ca, &tmp).await;
    let output = push_tag(&t, &proxy_url, &ca, &clone_dir);

    t.assert_eq("git push tag exit code", &output.status.code().unwrap(), &0);
    t.assert_true(
        "bare repo received the v1.0 tag",
        bare_repo_has_v1_tag(&bare_repo),
    );

    proxy.shutdown();
    upstream.shutdown();
}
