//! Binary-level integration tests that spawn the real `pyloros` binary
//! and drive it with `curl`.

mod common;

use common::{ok_handler, TestCa, TestReport, TestUpstream};
use std::io::{BufRead, BufReader, Read as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a TOML config string with optional auth.
fn build_config_toml_with_auth(
    ca_cert: &str,
    ca_key: &str,
    upstream_override_port: u16,
    upstream_tls_ca: &str,
    rules: &[(&str, &str)],
    auth: Option<(&str, &str)>,
) -> String {
    let auth_section = if let Some((user, pass)) = auth {
        format!("auth_username = \"{user}\"\nauth_password = \"{pass}\"\n")
    } else {
        String::new()
    };

    let mut toml = format!(
        r#"[proxy]
bind_address = "127.0.0.1:0"
ca_cert = "{ca_cert}"
ca_key = "{ca_key}"
upstream_override_port = {upstream_override_port}
upstream_tls_ca = "{upstream_tls_ca}"
{auth_section}
[logging]
level = "info"
log_requests = true

"#
    );

    for (method, url) in rules {
        toml.push_str(&format!(
            r#"[[rules]]
method = "{method}"
url = "{url}"

"#
        ));
    }

    toml
}

/// Spawn the proxy binary with the given config file path.
/// Parses stderr for the "Proxy server listening address=..." line to discover the port.
/// Returns (Child, port). A background thread drains stderr to prevent pipe blocking.
fn spawn_proxy(config_path: &Path) -> (Child, u16) {
    let bin = assert_cmd::cargo::cargo_bin!("pyloros");

    let mut child = Command::new(bin)
        .args(["run", "--config", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn pyloros binary");

    let stderr = child.stderr.take().expect("no stderr");

    // Background thread reads all stderr; sends port once found.
    let (tx, rx) = std::sync::mpsc::sync_channel::<u16>(1);

    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut sent = false;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if !sent {
                if let Some(port) = parse_listening_port(&line) {
                    let _ = tx.send(port);
                    sent = true;
                }
            }
        }
    });

    let port = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("timed out waiting for proxy to print listening address");

    (child, port)
}

/// Spawn the proxy binary with reporting.
fn spawn_proxy_reported(t: &TestReport, config_path: &Path) -> (Child, u16) {
    t.setup("Spawn proxy binary");
    spawn_proxy(config_path)
}

/// Like `spawn_proxy`, but also collects all stderr lines into a shared buffer.
fn spawn_proxy_with_logs(config_path: &Path) -> (Child, u16, Arc<Mutex<Vec<String>>>) {
    let bin = assert_cmd::cargo::cargo_bin!("pyloros");

    let mut child = Command::new(bin)
        .args(["run", "--config", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn pyloros binary");

    let stderr = child.stderr.take().expect("no stderr");
    let (tx, rx) = std::sync::mpsc::sync_channel::<u16>(1);
    let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let logs_clone = Arc::clone(&logs);

    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut sent = false;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if !sent {
                if let Some(port) = parse_listening_port(&line) {
                    let _ = tx.send(port);
                    sent = true;
                }
            }
            logs_clone.lock().unwrap().push(line);
        }
    });

    let port = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("timed out waiting for proxy to print listening address");

    (child, port, logs)
}

/// Spawn the proxy binary with log capture and reporting.
fn spawn_proxy_with_logs_reported(
    t: &TestReport,
    config_path: &Path,
) -> (Child, u16, Arc<Mutex<Vec<String>>>) {
    t.setup("Spawn proxy binary (with log capture)");
    spawn_proxy_with_logs(config_path)
}

/// Strip ANSI escape sequences from a string.
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Extract port from a tracing log line like "... Proxy server listening address=127.0.0.1:PORT"
fn parse_listening_port(line: &str) -> Option<u16> {
    let clean = strip_ansi(line);
    let idx = clean.find("address=")?;
    let addr_str = clean[idx + "address=".len()..].trim();
    let colon = addr_str.rfind(':')?;
    addr_str[colon + 1..].parse().ok()
}

/// Build a curl command with optional proxy auth credentials.
fn build_curl_command_with_auth(
    proxy_port: u16,
    url: &str,
    ca_cert_path: &str,
    auth: Option<(&str, &str)>,
) -> Command {
    let proxy_url = if let Some((user, pass)) = auth {
        format!("http://{}:{}@127.0.0.1:{}", user, pass, proxy_port)
    } else {
        format!("http://127.0.0.1:{}", proxy_port)
    };
    let mut cmd = Command::new("curl");
    cmd.env("HTTPS_PROXY", &proxy_url)
        .env("SSL_CERT_FILE", ca_cert_path)
        .args(["-s", "-S", "-w", "\n%{http_code}", "--max-time", "10", url]);
    cmd
}

/// Build a curl command for plain HTTP proxy usage.
/// Uses `http_proxy` env var (lowercase — curl ignores uppercase `HTTP_PROXY`
/// for http:// URLs as a CGI security measure). Sets `no_proxy=""` because curl
/// skips the proxy for localhost by default.
fn build_curl_plain_http_command(proxy_port: u16, url: &str) -> Command {
    build_curl_plain_http_command_with_auth(proxy_port, url, None)
}

/// Build a plain HTTP curl command with optional proxy auth.
fn build_curl_plain_http_command_with_auth(
    proxy_port: u16,
    url: &str,
    auth: Option<(&str, &str)>,
) -> Command {
    let proxy_url = if let Some((user, pass)) = auth {
        format!("http://{}:{}@127.0.0.1:{}", user, pass, proxy_port)
    } else {
        format!("http://127.0.0.1:{}", proxy_port)
    };
    let mut cmd = Command::new("curl");
    cmd.env("http_proxy", &proxy_url).env("no_proxy", "").args([
        "-s",
        "-S",
        "-w",
        "\n%{http_code}",
        "--max-time",
        "10",
        url,
    ]);
    cmd
}

/// Parse curl output (with `-w "\n%{http_code}"`) into (status_code, body, stderr).
fn parse_curl_output(output: &std::process::Output) -> (u16, String, String) {
    let full_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // The last line is the status code (from -w "\n%{http_code}")
    let (body, code) = full_output
        .trim_end()
        .rsplit_once('\n')
        .map_or_else(|| ("", full_output.trim()), |(body, code)| (body, code));

    let status: u16 = code.parse().unwrap_or_else(|_| {
        panic!(
            "failed to parse status code from curl output: {:?}, stderr: {}",
            full_output, stderr
        )
    });

    (status, body.to_string(), stderr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Spawn the binary with auth, curl an allowed HTTPS request, verify 200 + body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_binary_allowed_get_returns_200() {
    let t = test_report!("Binary: allowed HTTPS GET returns 200 (with auth)");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello binary"))
        .report(&t, "returns 'hello binary'")
        .start()
        .await;

    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    let config_toml = build_config_toml_with_auth(
        &ca.cert_path,
        &ca.key_path,
        upstream.port(),
        &ca.cert_path,
        &[("GET", "https://localhost/*")],
        Some(("testuser", "testpass")),
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    let (mut child, proxy_port) = spawn_proxy_reported(&t, &config_path);

    let output = common::run_command_reported(
        &t,
        &mut build_curl_command_with_auth(
            proxy_port,
            "https://localhost/test",
            &ca.cert_path,
            Some(("testuser", "testpass")),
        ),
    );
    let (status, body, _stderr) = parse_curl_output(&output);

    t.assert_eq("Response status", &status, &200u16);
    t.assert_eq("Response body", &body.as_str(), &"hello binary");

    child.kill().ok();
    child.wait().ok();
    upstream.shutdown();
}

/// Spawn the binary with auth, wget an allowed HTTPS request, verify 200 + body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_binary_allowed_get_returns_200_wget() {
    let t = test_report!("Binary: allowed HTTPS GET returns 200 via wget (with auth)");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello binary wget"))
        .report(&t, "returns 'hello binary wget'")
        .start()
        .await;

    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    let config_toml = build_config_toml_with_auth(
        &ca.cert_path,
        &ca.key_path,
        upstream.port(),
        &ca.cert_path,
        &[("GET", "https://localhost/*")],
        Some(("testuser", "testpass")),
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    let (mut child, proxy_port) = spawn_proxy_reported(&t, &config_path);

    let proxy_url = format!("http://testuser:testpass@127.0.0.1:{}", proxy_port);
    let mut cmd = Command::new("wget");
    cmd.env("https_proxy", &proxy_url)
        .env("SSL_CERT_FILE", &ca.cert_path)
        .args(["-q", "-O", "-", "https://localhost/test"]);
    let output = common::run_command_reported(&t, &mut cmd);

    let body = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    t.assert_true("wget exited successfully", output.status.success());
    t.assert_eq("Response body", &body.as_str(), &"hello binary wget");

    if !output.status.success() {
        panic!("wget failed: exit={}, stderr={}", output.status, stderr);
    }

    child.kill().ok();
    child.wait().ok();
    upstream.shutdown();
}

/// Verify wget's hop-by-hop headers (Connection, Proxy-Connection) are stripped.
/// wget sends these by default inside the CONNECT tunnel; the proxy must remove
/// them before forwarding upstream per RFC 7230 §6.1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_binary_wget_hop_by_hop_stripped() {
    let t = test_report!("Binary: wget hop-by-hop headers stripped before upstream");

    let ca = TestCa::generate();
    // Use h1-only upstream to avoid hyper's h2 auto-stripping masking the bug.
    let upstream = TestUpstream::builder(&ca, common::echo_handler())
        .h1_only()
        .report(&t, "echoes request details (h1 only)")
        .start()
        .await;

    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    let config_toml = build_config_toml_with_auth(
        &ca.cert_path,
        &ca.key_path,
        upstream.port(),
        &ca.cert_path,
        &[("GET", "https://localhost/*")],
        Some(("testuser", "testpass")),
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    let (mut child, proxy_port) = spawn_proxy_reported(&t, &config_path);

    let proxy_url = format!("http://testuser:testpass@127.0.0.1:{}", proxy_port);
    let mut cmd = Command::new("wget");
    cmd.env("https_proxy", &proxy_url)
        .env("SSL_CERT_FILE", &ca.cert_path)
        .args(["-q", "-O", "-", "https://localhost/test"]);
    let output = common::run_command_reported(&t, &mut cmd);

    let body = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    t.assert_true("wget exited successfully", output.status.success());
    // The echo handler returns the upstream-received headers. Verify hop-by-hop
    // headers are not forwarded (they would cause a 502 on h2 upstream).
    t.assert_not_contains("No connection header forwarded", &body, "connection:");
    t.assert_not_contains(
        "No proxy-connection header forwarded",
        &body,
        "proxy-connection:",
    );
    t.assert_not_contains("No keep-alive header forwarded", &body, "keep-alive:");

    if !output.status.success() {
        panic!("wget failed: exit={}, stderr={}", output.status, stderr);
    }

    child.kill().ok();
    child.wait().ok();
    upstream.shutdown();
}

/// Spawn the binary with auth, curl a blocked HTTPS request, verify 451.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_binary_blocked_request_returns_451() {
    let t = test_report!("Binary: blocked HTTPS request returns 451 (with auth)");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("should not reach"))
        .report(&t, "returns 'should not reach'")
        .start()
        .await;

    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    // Rule only allows example.com, not localhost
    let config_toml = build_config_toml_with_auth(
        &ca.cert_path,
        &ca.key_path,
        upstream.port(),
        &ca.cert_path,
        &[("GET", "https://example.com/*")],
        Some(("testuser", "testpass")),
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    let (mut child, proxy_port) = spawn_proxy_reported(&t, &config_path);

    let output = common::run_command_reported(
        &t,
        &mut build_curl_command_with_auth(
            proxy_port,
            "https://localhost/test",
            &ca.cert_path,
            Some(("testuser", "testpass")),
        ),
    );
    let (status, _body, _stderr) = parse_curl_output(&output);

    t.assert_eq("Response status", &status, &451u16);

    child.kill().ok();
    child.wait().ok();
    upstream.shutdown();
}

/// Spawn the binary with auth, curl an allowed plain HTTP request, verify 200 + body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_binary_plain_http_allowed_get_returns_200() {
    let t = test_report!("Binary: allowed plain HTTP GET returns 200 (with auth)");

    let upstream = MockServer::start().await;
    t.setup("MockServer returning 200 'hello plain binary'");
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("hello plain binary"))
        .mount(&upstream)
        .await;

    let upstream_port = upstream.address().port();

    let ca = TestCa::generate();
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    let config_toml = build_config_toml_with_auth(
        &ca.cert_path,
        &ca.key_path,
        upstream_port,
        &ca.cert_path,
        &[("GET", "http://localhost/*")],
        Some(("testuser", "testpass")),
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    let (mut child, proxy_port, proxy_logs) = spawn_proxy_with_logs_reported(&t, &config_path);

    let url = format!("http://localhost:{}/test", upstream_port);
    let output = common::run_command_reported(
        &t,
        &mut build_curl_plain_http_command_with_auth(
            proxy_port,
            &url,
            Some(("testuser", "testpass")),
        ),
    );
    let (status, body, _stderr) = parse_curl_output(&output);

    t.assert_eq("Response status", &status, &200u16);
    t.assert_eq("Response body", &body.as_str(), &"hello plain binary");

    // Give the proxy a moment to flush logs, then verify traffic went through it.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let logs = proxy_logs.lock().unwrap();
    let saw_allowed = logs.iter().any(|line| {
        let clean = strip_ansi(line);
        clean.contains("ALLOWED") && clean.contains("localhost")
    });
    t.assert_true("Proxy logged ALLOWED request to localhost", saw_allowed);
    if !saw_allowed {
        panic!(
            "proxy did not log an ALLOWED request to localhost\nproxy logs:\n{}",
            logs.join("\n")
        );
    }

    child.kill().ok();
    child.wait().ok();
}

/// Generate a TOML config for connecting to real upstream servers (no test overrides).
fn build_real_config_toml(ca_cert: &str, ca_key: &str, rules: &[(&str, &str)]) -> String {
    let mut toml = format!(
        r#"[proxy]
bind_address = "127.0.0.1:0"
ca_cert = "{ca_cert}"
ca_key = "{ca_key}"

[logging]
level = "info"
log_requests = true

"#
    );

    for (method, url) in rules {
        toml.push_str(&format!(
            r#"[[rules]]
method = "{method}"
url = "{url}"

"#
        ));
    }

    toml
}

/// Run `claude -p "Say hi"` through the proxy, verify it gets a response and
/// the proxy logged an ALLOWED request to api.anthropic.com.
///
/// Skipped if `claude` CLI is not installed, not authenticated, or running
/// inside another Claude Code session (nested sessions hang).
///
/// NOTE: Nested `claude -p` hangs when spawned from within a Claude Code
/// session (the Node.js event loop busy-spins after completing the API call).
/// The root cause is unknown — it's not env vars, inherited FDs, stdin, or
/// process group. See `devdocs/lessons/nested-claude-code-hangs.md`.
/// Because most development on this project happens agentically, this test
/// is at risk of silently rotting. Run it manually from a standalone terminal
/// after changes to TLS/proxy logic:
///   cargo test test_binary_claude_code_through_proxy -- --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_binary_claude_code_through_proxy() {
    let t = test_report!("Binary: Claude Code through proxy (live API)");

    // Skip if running inside another claude session (nested claude -p hangs;
    // see devdocs/lessons/nested-claude-code-hangs.md)
    if std::env::var("CLAUDECODE").is_ok() {
        t.skip("running inside Claude Code session");
        return;
    }

    // Skip if `claude` not on PATH
    if Command::new("claude").arg("--version").output().is_err() {
        t.skip("claude CLI not found");
        return;
    }

    // Skip if not authenticated
    let home = std::env::var("HOME").expect("HOME not set");
    let creds_path = std::path::PathBuf::from(&home).join(".claude/.credentials.json");
    if !creds_path.exists() {
        t.skip("claude not authenticated (~/.claude/.credentials.json missing)");
        return;
    }

    let ca = TestCa::generate();

    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    let config_toml = build_real_config_toml(
        &ca.cert_path,
        &ca.key_path,
        &[
            ("*", "https://api.anthropic.com/*"),
            ("*", "https://statsig.anthropic.com/*"),
            ("*", "https://sentry.io/*"),
            ("*", "https://*.sentry.io/*"),
        ],
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    let (mut child, proxy_port, proxy_logs) = spawn_proxy_with_logs_reported(&t, &config_path);

    t.action("Run `claude -p 'Say hi'` through proxy (no auth — backward compat)");
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let mut claude_child = Command::new("claude")
        .args([
            "-p",
            "Say hi",
            "--model",
            "claude-haiku-4-5-20251001",
            "--max-turns",
            "1",
        ])
        .env("HTTPS_PROXY", &proxy_url)
        .env("NODE_EXTRA_CA_CERTS", &ca.cert_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn claude");

    let claude_pid = claude_child.id();

    // Wait with a 60-second timeout
    let timeout = std::time::Duration::from_secs(60);
    let start = std::time::Instant::now();
    let status = loop {
        match claude_child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > timeout {
                    claude_child.kill().ok();
                    claude_child.wait().ok();
                    child.kill().ok();
                    child.wait().ok();
                    panic!(
                        "claude CLI timed out after {:?} (pid {})",
                        timeout, claude_pid
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => panic!("error waiting for claude: {}", e),
        }
    };

    let stdout = {
        let mut buf = Vec::new();
        claude_child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        String::from_utf8_lossy(&buf).to_string()
    };
    let stderr = {
        let mut buf = Vec::new();
        claude_child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        String::from_utf8_lossy(&buf).to_string()
    };

    t.assert_true("claude exited successfully", status.success());
    t.assert_true(
        "claude produced non-empty output",
        !stdout.trim().is_empty(),
    );

    // Verify the proxy actually intercepted an Anthropic API call
    let logs = proxy_logs.lock().unwrap();
    let saw_anthropic = logs.iter().any(|line| {
        let clean = strip_ansi(line);
        clean.contains("ALLOWED") && clean.contains("api.anthropic.com")
    });
    t.assert_true(
        "Proxy logged ALLOWED request to api.anthropic.com",
        saw_anthropic,
    );

    if !status.success() {
        panic!(
            "claude exited with {}\nstdout: {}\nstderr: {}",
            status, stdout, stderr
        );
    }
    if stdout.trim().is_empty() {
        panic!("claude produced empty output\nstderr: {}", stderr);
    }
    if !saw_anthropic {
        panic!(
            "proxy did not log an ALLOWED request to api.anthropic.com\nproxy logs:\n{}",
            logs.join("\n")
        );
    }

    eprintln!("claude response: {}", stdout.trim());

    child.kill().ok();
    child.wait().ok();
}

/// Spawn the binary with auth, curl WITHOUT credentials via plain HTTP, verify 407.
/// Uses plain HTTP because curl can't report HTTPS CONNECT 407 as an HTTP status.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_binary_auth_required_without_credentials() {
    let t = test_report!("Binary: auth required without credentials returns 407");

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("should not reach"))
        .mount(&upstream)
        .await;

    let upstream_port = upstream.address().port();

    let ca = TestCa::generate();
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    let config_toml = build_config_toml_with_auth(
        &ca.cert_path,
        &ca.key_path,
        upstream_port,
        &ca.cert_path,
        &[("GET", "http://localhost/*")],
        Some(("testuser", "testpass")),
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    let (mut child, proxy_port) = spawn_proxy_reported(&t, &config_path);

    // curl without proxy auth — should get 407
    let url = format!("http://localhost:{}/test", upstream_port);
    let output =
        common::run_command_reported(&t, &mut build_curl_plain_http_command(proxy_port, &url));
    let (status, _body, _stderr) = parse_curl_output(&output);

    t.assert_eq("Response status", &status, &407u16);

    child.kill().ok();
    child.wait().ok();
}

/// Run `generate-ca --out <tmpdir>`, verify cert and key files are created with valid PEM.
#[test]
fn test_binary_generate_ca() {
    let t = test_report!("Binary: generate-ca creates valid PEM files");

    let tmp = TempDir::new().unwrap();

    let bin = assert_cmd::cargo::cargo_bin!("pyloros");
    let mut cmd = Command::new(bin);
    cmd.args(["generate-ca", "--out", tmp.path().to_str().unwrap()]);
    let output = common::run_command_reported(&t, &mut cmd);

    t.assert_true("generate-ca exits successfully", output.status.success());

    let cert_path = tmp.path().join("ca.crt");
    let key_path = tmp.path().join("ca.key");

    t.assert_true("ca.crt exists", cert_path.exists());
    t.assert_true("ca.key exists", key_path.exists());

    let cert_content = std::fs::read_to_string(&cert_path).unwrap();
    let key_content = std::fs::read_to_string(&key_path).unwrap();

    t.assert_contains(
        "ca.crt has PEM header",
        &cert_content,
        "-----BEGIN CERTIFICATE-----",
    );
    t.assert_contains(
        "ca.key has PEM header",
        &key_content,
        "-----BEGIN PRIVATE KEY-----",
    );
}
