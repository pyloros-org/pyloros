mod common;

use common::{LogCapture, ReportingClient, TestCa, TestUpstream, ok_handler, rule};
use pyloros::{Config, ProxyServer};

// ---------------------------------------------------------------------------
// Granular request logging config
// ---------------------------------------------------------------------------

/// With log_blocked=true, log_allowed=false: BLOCKED is logged, ALLOWED is not.
#[tokio::test]
async fn test_log_blocked_only() {
    let t = test_report!("Log blocked only: BLOCKED logged, ALLOWED not");

    let logs = LogCapture::new();

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("logged"))
        .report(&t, "returns 'logged'")
        .start()
        .await;

    t.setup("Proxy with log_allowed=false, log_blocked=true");
    let mut config = Config::minimal(
        "127.0.0.1:0".to_string(),
        ca.cert_path.clone(),
        ca.key_path.clone(),
    );
    config.rules = vec![rule("GET", "https://localhost/*")];
    config.logging.log_allowed_requests = false;
    config.logging.log_blocked_requests = true;

    let client_tls = ca.client_tls_config();
    let mut server = ProxyServer::new(config).unwrap();
    server = server
        .with_upstream_port_override(upstream.port())
        .with_upstream_tls(client_tls);

    let addr = server.bind().await.unwrap().tcp_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });

    let client = ReportingClient::new(&t, addr, &ca);

    // Allowed request — should NOT produce an ALLOWED log line
    let resp = client.get("https://localhost/ok").await;
    t.assert_eq("Allowed response status", &resp.status().as_u16(), &200u16);

    // Blocked request — should produce a BLOCKED log line
    let resp = client.post("https://localhost/blocked").await;
    t.assert_eq("Blocked response status", &resp.status().as_u16(), &451u16);

    // Give spawned tasks a moment to flush log output
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    t.assert_true("BLOCKED in logs", logs.contains("BLOCKED"));
    t.assert_true("ALLOWED not in logs", !logs.contains("ALLOWED"));

    let _ = shutdown_tx.send(());
    upstream.shutdown();
}

/// With log_allowed=true, log_blocked=false: ALLOWED is logged, BLOCKED is not.
#[tokio::test]
async fn test_log_allowed_only() {
    let t = test_report!("Log allowed only: ALLOWED logged, BLOCKED not");

    let logs = LogCapture::new();

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("logged"))
        .report(&t, "returns 'logged'")
        .start()
        .await;

    t.setup("Proxy with log_allowed=true, log_blocked=false");
    let mut config = Config::minimal(
        "127.0.0.1:0".to_string(),
        ca.cert_path.clone(),
        ca.key_path.clone(),
    );
    config.rules = vec![rule("GET", "https://localhost/*")];
    config.logging.log_allowed_requests = true;
    config.logging.log_blocked_requests = false;

    let client_tls = ca.client_tls_config();
    let mut server = ProxyServer::new(config).unwrap();
    server = server
        .with_upstream_port_override(upstream.port())
        .with_upstream_tls(client_tls);

    let addr = server.bind().await.unwrap().tcp_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });

    let client = ReportingClient::new(&t, addr, &ca);

    // Allowed request — should produce an ALLOWED log line
    let resp = client.get("https://localhost/ok").await;
    t.assert_eq("Allowed response status", &resp.status().as_u16(), &200u16);

    // Blocked request — should NOT produce a BLOCKED log line
    let resp = client.post("https://localhost/blocked").await;
    t.assert_eq("Blocked response status", &resp.status().as_u16(), &451u16);

    // Give spawned tasks a moment to flush log output
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    t.assert_true("ALLOWED in logs", logs.contains("ALLOWED"));
    t.assert_true("BLOCKED not in logs", !logs.contains("BLOCKED"));

    let _ = shutdown_tx.send(());
    upstream.shutdown();
}
