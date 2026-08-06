//! Git smart HTTP clone/push through the HTTPS proxy.
//!
//! These tests verify that git operations work end-to-end through the proxy's
//! MITM TLS pipeline using git-specific rules. They use `git http-backend`
//! (CGI) as the upstream server.

mod common;

use common::{
    RequestLog, TestCa, TestProxy, TestUpstream, create_test_repo, git_cgi_handler,
    git_http_backend_path, git_rule, run_command_reported,
};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_clone_through_proxy() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Git clone through HTTPS proxy (git rule)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    t.setup(format!("Created test git repo at {:?}", repos_dir));

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let clone_dir = tmp.path().join("cloned");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env(
                "HTTPS_PROXY",
                format!("http://127.0.0.1:{}", proxy.addr().port()),
            )
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );

    t.assert_eq("git clone exit code", &output.status.code().unwrap(), &0);
    t.assert_true(
        "cloned README.md exists",
        clone_dir.join("README.md").exists(),
    );

    let readme_content = std::fs::read_to_string(clone_dir.join("README.md")).unwrap();
    t.assert_contains("README content", &readme_content, "Hello from git test!");

    // Verify the proxy forwarded the expected git smart HTTP requests
    let logged = request_log.lock().unwrap();
    let saw_discovery = logged
        .iter()
        .any(|r| r.contains("info/refs") && r.contains("git-upload-pack"));
    let saw_pack = logged
        .iter()
        .any(|r| r.contains("POST") && r.contains("git-upload-pack"));
    t.assert_true(
        "proxy forwarded git-upload-pack discovery request",
        saw_discovery,
    );
    t.assert_true("proxy forwarded git-upload-pack POST request", saw_pack);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_through_proxy() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Git push through HTTPS proxy (git rule)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path(), "repo.git");
    t.setup(format!("Created test git repo at {:?}", repos_dir));

    // Enable receive-pack on the bare repo so pushes are accepted
    let bare_repo = repos_dir.join("repo.git");
    let run_git = |args: &[&str], cwd: &Path| {
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
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Enabled http.receivepack on bare repo");

    let request_log: RequestLog = Arc::new(Mutex::new(Vec::new()));

    let upstream = TestUpstream::builder(
        &ca,
        git_cgi_handler(backend_path, repos_dir, request_log.clone()),
    )
    .report(&t, "git http-backend CGI")
    .start()
    .await;

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

    // Step 1: Clone through proxy
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
    t.assert_eq("git clone exit code", &output.status.code().unwrap(), &0);

    // Step 2: Make a new commit in the cloned repo
    run_git(&["config", "user.email", "test@test.com"], &clone_dir);
    run_git(&["config", "user.name", "Test User"], &clone_dir);
    std::fs::write(clone_dir.join("newfile.txt"), "pushed content\n").unwrap();
    run_git(&["add", "newfile.txt"], &clone_dir);
    run_git(&["commit", "-m", "Add newfile"], &clone_dir);
    t.action("Created new commit with newfile.txt");

    // Step 3: Push through proxy
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git push exit code", &output.status.code().unwrap(), &0);

    // Step 4: Verify the bare repo received the push
    let verify = std::process::Command::new("git")
        .args(["show", "HEAD:newfile.txt"])
        .current_dir(&bare_repo)
        .output()
        .unwrap();
    let content = String::from_utf8_lossy(&verify.stdout);
    t.assert_contains("bare repo has pushed file", &content, "pushed content");

    // Verify the proxy forwarded the expected git smart HTTP requests
    let logged = request_log.lock().unwrap();
    let saw_receive_discovery = logged
        .iter()
        .any(|r| r.contains("info/refs") && r.contains("git-receive-pack"));
    let saw_receive_pack = logged
        .iter()
        .any(|r| r.contains("POST") && r.contains("git-receive-pack"));
    t.assert_true(
        "proxy forwarded git-receive-pack discovery request",
        saw_receive_discovery,
    );
    t.assert_true(
        "proxy forwarded git-receive-pack POST request",
        saw_receive_pack,
    );

    proxy.shutdown();
    upstream.shutdown();
}
