//! Tests that the generated_secrets_file is preserved across proxy restarts
//! and refreshed (preserving existing entries) on config reload.

mod common;

use common::*;
use std::collections::HashMap;
use std::path::Path;

fn read_secrets_file(path: &Path) -> HashMap<String, String> {
    let contents = std::fs::read_to_string(path).expect("secrets file should exist");
    contents
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_string(), v.to_string()))
        })
        .collect()
}

fn build_config(ca: &TestCa, secrets_path: &Path, extra: &str) -> String {
    format!(
        "[proxy]\nbind_address = \"127.0.0.1:0\"\nca_cert = \"{}\"\nca_key = \"{}\"\ngenerated_secrets_file = \"{}\"\n{}",
        ca.cert_path,
        ca.key_path,
        secrets_path.display(),
        extra,
    )
}

/// Starting a proxy preserves the existing values in the generated_secrets_file
/// instead of regenerating them, so a sandbox holding the old local credential
/// keeps working across proxy restarts.
#[tokio::test]
async fn test_restart_preserves_generated_local_credentials() {
    let t = test_report!("Proxy restart reuses existing generated_secrets_file values");
    let ca = TestCa::generate();
    let dir = tempfile::tempdir().unwrap();
    let secrets_path = dir.path().join("secrets.env");

    let config_toml = build_config(
        &ca,
        &secrets_path,
        r#"
[[credentials]]
url = "https://example.com/*"
header = "x-api-key"
value = "real-secret"
local_generated = true
local_env_name = "LOCAL_API_KEY"
"#,
    );

    // First boot: proxy generates a fresh value and writes it to disk.
    let config = pyloros::Config::parse(&config_toml).unwrap();
    let _server = pyloros::ProxyServer::new(config).unwrap();
    let first = read_secrets_file(&secrets_path);
    t.assert_true(
        "first boot wrote LOCAL_API_KEY",
        first.contains_key("LOCAL_API_KEY"),
    );
    let original = first["LOCAL_API_KEY"].clone();

    // Second boot with the same config + same file: should reuse the value,
    // not rotate it. This is the property a long-lived sandbox depends on.
    let config2 = pyloros::Config::parse(&config_toml).unwrap();
    let _server2 = pyloros::ProxyServer::new(config2).unwrap();
    let second = read_secrets_file(&secrets_path);
    t.assert_eq(
        "value preserved across restart",
        &second.get("LOCAL_API_KEY").map(String::as_str),
        &Some(original.as_str()),
    );
}

/// SigV4 generated locals (access_key_id + secret_access_key) are also stable
/// across restarts.
#[tokio::test]
async fn test_restart_preserves_generated_sigv4_local_credentials() {
    let t = test_report!("Proxy restart reuses generated SigV4 local credentials");
    let ca = TestCa::generate();
    let dir = tempfile::tempdir().unwrap();
    let secrets_path = dir.path().join("secrets.env");

    // Set real-credential env vars; the local env-var names default to
    // these via inference from the ${VAR} placeholders.
    std::env::set_var("RESTART_AWS_AKID", "AKIAREAL_FOR_TEST");
    std::env::set_var("RESTART_AWS_SAK", "REAL_SECRET_FOR_TEST");

    let config_toml = build_config(
        &ca,
        &secrets_path,
        r#"
[[credentials]]
type = "aws-sigv4"
url = "https://*.amazonaws.com/*"
access_key_id = "${RESTART_AWS_AKID}"
secret_access_key = "${RESTART_AWS_SAK}"
local_generated = true
"#,
    );

    let config = pyloros::Config::parse(&config_toml).unwrap();
    let _s1 = pyloros::ProxyServer::new(config).unwrap();
    let first = read_secrets_file(&secrets_path);
    let akid = first["RESTART_AWS_AKID"].clone();
    let sak = first["RESTART_AWS_SAK"].clone();

    let config2 = pyloros::Config::parse(&config_toml).unwrap();
    let _s2 = pyloros::ProxyServer::new(config2).unwrap();
    let second = read_secrets_file(&secrets_path);
    t.assert_eq(
        "AKID preserved",
        &second["RESTART_AWS_AKID"].as_str(),
        &akid.as_str(),
    );
    t.assert_eq(
        "SAK preserved",
        &second["RESTART_AWS_SAK"].as_str(),
        &sak.as_str(),
    );
}

/// When a credential is added to the config and the proxy reloads, the new
/// generated local appears in the secrets file while the existing entry is
/// preserved.
#[tokio::test]
async fn test_reload_writes_new_generated_secret_and_preserves_existing() {
    let t = test_report!("Reload adds new generated secret and preserves existing one");
    let ca = TestCa::generate();
    let dir = tempfile::tempdir().unwrap();
    let secrets_path = dir.path().join("secrets.env");
    let config_path = dir.path().join("config.toml");

    let initial = build_config(
        &ca,
        &secrets_path,
        r#"
[[credentials]]
url = "https://a.example.com/*"
header = "x-a"
value = "real-a"
local_generated = true
local_env_name = "LOCAL_A"
"#,
    );
    std::fs::write(&config_path, &initial).unwrap();

    let config = pyloros::Config::from_file(&config_path).unwrap();
    let mut server = pyloros::ProxyServer::new(config)
        .unwrap()
        .with_config_path(config_path.clone());
    let reload_tx = server.reload_trigger();
    let reload_complete = server.reload_complete_notify();
    let _addr = server.bind().await.unwrap().tcp_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });

    let before = read_secrets_file(&secrets_path);
    let local_a = before["LOCAL_A"].clone();

    // Reload: keep credential A, add credential B.
    let updated = build_config(
        &ca,
        &secrets_path,
        r#"
[[credentials]]
url = "https://a.example.com/*"
header = "x-a"
value = "real-a"
local_generated = true
local_env_name = "LOCAL_A"

[[credentials]]
url = "https://b.example.com/*"
header = "x-b"
value = "real-b"
local_generated = true
local_env_name = "LOCAL_B"
"#,
    );
    std::fs::write(&config_path, &updated).unwrap();
    let notified = reload_complete.notified();
    reload_tx.send(()).await.unwrap();
    notified.await;

    let after = read_secrets_file(&secrets_path);
    t.assert_eq(
        "LOCAL_A preserved",
        &after.get("LOCAL_A").map(String::as_str),
        &Some(local_a.as_str()),
    );
    t.assert_true("LOCAL_B added", after.contains_key("LOCAL_B"));

    let _ = shutdown_tx.send(());
}

/// When a credential is removed from the config and the proxy reloads, its
/// entry disappears from the secrets file.
#[tokio::test]
async fn test_reload_removes_secret_no_longer_referenced() {
    let t = test_report!("Reload drops secrets for credentials removed from config");
    let ca = TestCa::generate();
    let dir = tempfile::tempdir().unwrap();
    let secrets_path = dir.path().join("secrets.env");
    let config_path = dir.path().join("config.toml");

    let initial = build_config(
        &ca,
        &secrets_path,
        r#"
[[credentials]]
url = "https://a.example.com/*"
header = "x-a"
value = "real-a"
local_generated = true
local_env_name = "LOCAL_A"

[[credentials]]
url = "https://b.example.com/*"
header = "x-b"
value = "real-b"
local_generated = true
local_env_name = "LOCAL_B"
"#,
    );
    std::fs::write(&config_path, &initial).unwrap();

    let config = pyloros::Config::from_file(&config_path).unwrap();
    let mut server = pyloros::ProxyServer::new(config)
        .unwrap()
        .with_config_path(config_path.clone());
    let reload_tx = server.reload_trigger();
    let reload_complete = server.reload_complete_notify();
    let _addr = server.bind().await.unwrap().tcp_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });

    let before = read_secrets_file(&secrets_path);
    t.assert_true("LOCAL_A present before", before.contains_key("LOCAL_A"));
    t.assert_true("LOCAL_B present before", before.contains_key("LOCAL_B"));

    // Drop credential B.
    let updated = build_config(
        &ca,
        &secrets_path,
        r#"
[[credentials]]
url = "https://a.example.com/*"
header = "x-a"
value = "real-a"
local_generated = true
local_env_name = "LOCAL_A"
"#,
    );
    std::fs::write(&config_path, &updated).unwrap();
    let notified = reload_complete.notified();
    reload_tx.send(()).await.unwrap();
    notified.await;

    let after = read_secrets_file(&secrets_path);
    t.assert_true("LOCAL_A still present", after.contains_key("LOCAL_A"));
    t.assert_true("LOCAL_B removed", !after.contains_key("LOCAL_B"));

    let _ = shutdown_tx.send(());
}
