//! Tests for the generate-hosts CLI subcommand

mod common;

use common::TestReport;
use std::fs;
use tempfile::TempDir;

/// Run a CLI command and report it.
fn run_cli_reported(t: &TestReport, args: &[&str]) -> std::process::Output {
    let bin = assert_cmd::cargo::cargo_bin!("pyloros");
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args);
    common::run_command_reported(t, &mut cmd)
}

#[test]
fn generate_hosts_literal_hostnames() {
    let t = test_report!("generate-hosts extracts literal hostnames");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[[rules]]
method = "GET"
url = "https://api.example.com/health"

[[rules]]
method = "*"
url = "https://github.com/org/repo"

[[rules]]
git = "fetch"
url = "https://gitlab.com/myorg/project"
"#,
    )
    .unwrap();

    let output = run_cli_reported(
        &t,
        &[
            "generate-hosts",
            "--config",
            config_path.to_str().unwrap(),
            "--ip",
            "127.0.0.12",
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    t.assert_true("Exit success", output.status.success());
    t.assert_contains("api.example.com", &stdout, "127.0.0.12 api.example.com");
    t.assert_contains("github.com", &stdout, "127.0.0.12 github.com");
    t.assert_contains("gitlab.com", &stdout, "127.0.0.12 gitlab.com");
    t.assert_contains("count in stderr", &stderr, "Generated 3 host entries");
}

#[test]
fn generate_hosts_skips_wildcards() {
    let t = test_report!("generate-hosts skips wildcard patterns with warning");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[[rules]]
method = "*"
url = "https://*.github.com/*"

[[rules]]
method = "GET"
url = "https://api.example.com/health"
"#,
    )
    .unwrap();

    let output = run_cli_reported(
        &t,
        &[
            "generate-hosts",
            "--config",
            config_path.to_str().unwrap(),
            "--ip",
            "10.0.0.1",
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    t.assert_true("Exit success", output.status.success());
    // Only api.example.com should be in stdout (literal)
    t.assert_contains("literal host", &stdout, "10.0.0.1 api.example.com");
    t.assert_true(
        "wildcard host NOT in stdout",
        !stdout.contains("*.github.com"),
    );
    // Warning about wildcard in stderr
    t.assert_contains("wildcard warning", &stderr, "*.github.com");
    t.assert_contains("skip count", &stderr, "1 wildcard patterns skipped");
}

#[test]
fn generate_hosts_deduplicates() {
    let t = test_report!("generate-hosts deduplicates hostnames");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[[rules]]
method = "GET"
url = "https://api.example.com/v1/*"

[[rules]]
method = "POST"
url = "https://api.example.com/v2/*"

[[rules]]
git = "fetch"
url = "https://api.example.com/repo"
"#,
    )
    .unwrap();

    let output = run_cli_reported(
        &t,
        &[
            "generate-hosts",
            "--config",
            config_path.to_str().unwrap(),
            "--ip",
            "127.0.0.12",
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    t.assert_true("Exit success", output.status.success());
    // Should only appear once
    let count = stdout.matches("api.example.com").count();
    t.assert_eq("appears once", &count, &1usize);
}

#[test]
fn generate_hosts_no_rules() {
    let t = test_report!("generate-hosts with no rules warns");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(&config_path, "").unwrap();

    let output = run_cli_reported(
        &t,
        &[
            "generate-hosts",
            "--config",
            config_path.to_str().unwrap(),
            "--ip",
            "127.0.0.12",
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    t.assert_true("Exit success", output.status.success());
    t.assert_true("empty stdout", stdout.trim().is_empty());
    t.assert_contains("warning", &stderr, "no literal hostnames");
}

#[test]
fn generate_hosts_includes_credential_hosts() {
    let t = test_report!("generate-hosts includes hosts from credential URL patterns");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[[rules]]
method = "*"
url = "https://api.example.com/*"

[[credentials]]
url = "https://api.example.com/*"
header = "x-api-key"
value = "secret"
local_value = "local"

[[credentials]]
url = "https://other-api.example.com/*"
header = "authorization"
value = "Bearer token"
local_value = "local"
"#,
    )
    .unwrap();

    let output = run_cli_reported(
        &t,
        &[
            "generate-hosts",
            "--config",
            config_path.to_str().unwrap(),
            "--ip",
            "127.0.0.12",
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    t.assert_true("Exit success", output.status.success());
    t.assert_contains("api.example.com", &stdout, "127.0.0.12 api.example.com");
    t.assert_contains(
        "other-api.example.com",
        &stdout,
        "127.0.0.12 other-api.example.com",
    );
}

#[test]
fn generate_hosts_default_ip() {
    let t = test_report!("generate-hosts uses 127.0.0.12 as default IP");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[[rules]]
method = "GET"
url = "https://example.com/test"
"#,
    )
    .unwrap();

    // Don't pass --ip, use default
    let output = run_cli_reported(
        &t,
        &["generate-hosts", "--config", config_path.to_str().unwrap()],
    );

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    t.assert_true("Exit success", output.status.success());
    t.assert_contains("default IP", &stdout, "127.0.0.12 example.com");
}
