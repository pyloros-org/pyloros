//! E2E tests for force-push and protected-branch enforcement.
//!
//! These exercise the full proxy: real git clients push through an HTTPS
//! MITM proxy to a real git-http-backend CGI, with `protected_branches`
//! rules that require fast-forward-only updates on matching refs.

mod common;

use common::{
    create_test_repo, git_cgi_handler, git_http_backend_path, git_rule_with_protected,
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

/// Set up a proxy + bare repo with the given protected pattern, and a clone
/// directory ready for edits. Returns (proxy, upstream, clone_dir, tmp, ca, proxy_url).
async fn setup(
    t: &pyloros_test_support::TestReport,
    branches: &[&str],
    protected: &[&str],
) -> (
    TestProxy,
    TestUpstream,
    std::path::PathBuf,
    std::path::PathBuf,
    TempDir,
    TestCa,
    String,
) {
    let backend_path = git_http_backend_path();
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    let bare_repo = repos_dir.join("repo.git");
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Created test repo with receivepack enabled");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));
    let upstream =
        TestUpstream::builder(&ca, git_cgi_handler(backend_path, repos_dir, request_log))
            .report(t, "git http-backend CGI")
            .start()
            .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule_with_protected(
            "*",
            "https://localhost/*",
            branches,
            protected,
        )],
        upstream.port(),
    )
    .report(t)
    .start()
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        t,
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

    (proxy, upstream, clone_dir, bare_repo, tmp, ca, proxy_url)
}

fn git_with_proxy<'a>(
    cmd: &'a mut std::process::Command,
    cwd: &Path,
    proxy_url: &str,
    ca_path: &str,
) -> &'a mut std::process::Command {
    cmd.current_dir(cwd)
        .env("HTTPS_PROXY", proxy_url)
        .env("GIT_SSL_CAINFO", ca_path)
        .env("GIT_TERMINAL_PROMPT", "0")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_force_push_to_protected_branch_blocked() {
    let t = test_report!("Force-push to protected branch is blocked");
    let (proxy, upstream, clone_dir, _bare, _tmp, ca, proxy_url) =
        setup(&t, &["*"], &["main"]).await;

    // Rewrite history: amend the initial commit so HEAD diverges from origin/main.
    run_git(
        &["commit", "--amend", "-m", "rewritten initial"],
        &clone_dir,
    );
    t.action("amended HEAD to create a non-fast-forward update");

    let output = run_command_reported(
        &t,
        git_with_proxy(
            std::process::Command::new("git").args(["push", "--force", "origin", "main"]),
            &clone_dir,
            &proxy_url,
            &ca.cert_path,
        ),
    );
    t.assert_true(
        "force-push to main fails",
        output.status.code().unwrap() != 0,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    t.assert_contains(
        "stderr mentions protected-branch policy",
        &stderr,
        "protected",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_fast_forward_to_protected_branch_allowed() {
    let t = test_report!("Fast-forward push to protected branch is allowed");
    let (proxy, upstream, clone_dir, bare, _tmp, ca, proxy_url) =
        setup(&t, &["*"], &["main"]).await;

    std::fs::write(clone_dir.join("ff.txt"), "ff content\n").unwrap();
    run_git(&["add", "ff.txt"], &clone_dir);
    run_git(&["commit", "-m", "fast-forward"], &clone_dir);
    t.action("created fast-forward commit on main");

    let output = run_command_reported(
        &t,
        git_with_proxy(
            std::process::Command::new("git").args(["push", "origin", "main"]),
            &clone_dir,
            &proxy_url,
            &ca.cert_path,
        ),
    );
    t.assert_eq(
        "git push (fast-forward) succeeds",
        &output.status.code().unwrap(),
        &0,
    );

    let verify = std::process::Command::new("git")
        .args(["show", "main:ff.txt"])
        .current_dir(&bare)
        .output()
        .unwrap();
    t.assert_contains(
        "bare repo received ff commit",
        &String::from_utf8_lossy(&verify.stdout),
        "ff content",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_force_push_to_unprotected_branch_allowed() {
    let t = test_report!("Force-push on unprotected branch is allowed");
    let (proxy, upstream, clone_dir, _bare, _tmp, ca, proxy_url) =
        setup(&t, &["*"], &["main"]).await;

    // Create and push a feature branch so origin has it.
    run_git(&["checkout", "-b", "feature/x"], &clone_dir);
    std::fs::write(clone_dir.join("f.txt"), "v1\n").unwrap();
    run_git(&["add", "f.txt"], &clone_dir);
    run_git(&["commit", "-m", "v1"], &clone_dir);
    let output = run_command_reported(
        &t,
        git_with_proxy(
            std::process::Command::new("git").args(["push", "origin", "feature/x"]),
            &clone_dir,
            &proxy_url,
            &ca.cert_path,
        ),
    );
    t.assert_eq(
        "initial push to feature/x succeeds",
        &output.status.code().unwrap(),
        &0,
    );

    // Rewrite: amend and force-push. Since feature/x is not protected, this should succeed.
    std::fs::write(clone_dir.join("f.txt"), "v2\n").unwrap();
    run_git(&["add", "f.txt"], &clone_dir);
    run_git(&["commit", "--amend", "-m", "v2"], &clone_dir);
    let output = run_command_reported(
        &t,
        git_with_proxy(
            std::process::Command::new("git").args(["push", "--force", "origin", "feature/x"]),
            &clone_dir,
            &proxy_url,
            &ca.cert_path,
        ),
    );
    t.assert_eq(
        "force-push to feature/x succeeds",
        &output.status.code().unwrap(),
        &0,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_delete_protected_branch_blocked() {
    let t = test_report!("Deleting a protected branch is blocked");
    // Create an extra branch on origin first, then protect it and try to delete.
    let (proxy, upstream, clone_dir, _bare, _tmp, ca, proxy_url) =
        setup(&t, &["*"], &["victim"]).await;

    run_git(&["checkout", "-b", "victim"], &clone_dir);
    std::fs::write(clone_dir.join("v.txt"), "v\n").unwrap();
    run_git(&["add", "v.txt"], &clone_dir);
    run_git(&["commit", "-m", "victim init"], &clone_dir);
    let output = run_command_reported(
        &t,
        git_with_proxy(
            std::process::Command::new("git").args(["push", "origin", "victim"]),
            &clone_dir,
            &proxy_url,
            &ca.cert_path,
        ),
    );
    t.assert_eq("push victim succeeds", &output.status.code().unwrap(), &0);

    // Now attempt deletion via `git push origin :victim`.
    let output = run_command_reported(
        &t,
        git_with_proxy(
            std::process::Command::new("git").args(["push", "origin", ":victim"]),
            &clone_dir,
            &proxy_url,
            &ca.cert_path,
        ),
    );
    t.assert_true(
        "delete of protected branch fails",
        output.status.code().unwrap() != 0,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_create_matching_protected_branch_allowed() {
    let t = test_report!("Creating a new ref that matches protected pattern is allowed");
    // Protect release/* but allow new ref creation matching it.
    let (proxy, upstream, clone_dir, _bare, _tmp, ca, proxy_url) =
        setup(&t, &["*"], &["release/*"]).await;

    run_git(&["checkout", "-b", "release/v1"], &clone_dir);
    std::fs::write(clone_dir.join("rel.txt"), "r\n").unwrap();
    run_git(&["add", "rel.txt"], &clone_dir);
    run_git(&["commit", "-m", "release init"], &clone_dir);
    let output = run_command_reported(
        &t,
        git_with_proxy(
            std::process::Command::new("git").args(["push", "origin", "release/v1"]),
            &clone_dir,
            &proxy_url,
            &ca.cert_path,
        ),
    );
    t.assert_eq(
        "new protected ref creation succeeds",
        &output.status.code().unwrap(),
        &0,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_protected_pattern_wildcard() {
    let t = test_report!("release/* protected: force-push blocked; main allowed");
    let (proxy, upstream, clone_dir, _bare, _tmp, ca, proxy_url) =
        setup(&t, &["*"], &["release/*"]).await;

    // Create release/v1 on origin.
    run_git(&["checkout", "-b", "release/v1"], &clone_dir);
    std::fs::write(clone_dir.join("r.txt"), "v1\n").unwrap();
    run_git(&["add", "r.txt"], &clone_dir);
    run_git(&["commit", "-m", "release v1"], &clone_dir);
    let output = run_command_reported(
        &t,
        git_with_proxy(
            std::process::Command::new("git").args(["push", "origin", "release/v1"]),
            &clone_dir,
            &proxy_url,
            &ca.cert_path,
        ),
    );
    t.assert_eq(
        "push release/v1 succeeds",
        &output.status.code().unwrap(),
        &0,
    );

    // Attempt to force-push release/v1 (amend + force): should fail.
    std::fs::write(clone_dir.join("r.txt"), "v1b\n").unwrap();
    run_git(&["add", "r.txt"], &clone_dir);
    run_git(&["commit", "--amend", "-m", "release v1b"], &clone_dir);
    let output = run_command_reported(
        &t,
        git_with_proxy(
            std::process::Command::new("git").args(["push", "--force", "origin", "release/v1"]),
            &clone_dir,
            &proxy_url,
            &ca.cert_path,
        ),
    );
    t.assert_true(
        "force-push on release/v1 fails",
        output.status.code().unwrap() != 0,
    );

    // But force-push on main succeeds (not protected).
    run_git(&["checkout", "main"], &clone_dir);
    run_git(
        &["commit", "--allow-empty", "--amend", "-m", "new init"],
        &clone_dir,
    );
    let output = run_command_reported(
        &t,
        git_with_proxy(
            std::process::Command::new("git").args(["push", "--force", "origin", "main"]),
            &clone_dir,
            &proxy_url,
            &ca.cert_path,
        ),
    );
    t.assert_eq(
        "force-push on unprotected main succeeds",
        &output.status.code().unwrap(),
        &0,
    );

    proxy.shutdown();
    upstream.shutdown();
}
