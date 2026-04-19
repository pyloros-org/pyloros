//! Tests for direct HTTPS mode (SNI-based routing without proxy protocol)

mod common;

use common::*;
use pyloros::config::Rule;
use pyloros::{Config, ProxyServer};
use reqwest::Certificate;
use std::net::SocketAddr;

/// Helper to start a proxy with both regular proxy listener and direct HTTPS listener.
/// Returns (proxy_addr, direct_https_addr).
async fn start_proxy_with_direct_https(
    ca: &TestCa,
    rules: Vec<Rule>,
    upstream_port: u16,
) -> (SocketAddr, SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let mut config = Config::minimal(
        "127.0.0.1:0".to_string(),
        ca.cert_path.clone(),
        ca.key_path.clone(),
    );
    config.rules = rules;
    config.logging.log_allowed_requests = false;
    config.logging.log_blocked_requests = false;

    let client_tls = ca.client_tls_config();

    let mut server = ProxyServer::new(config).unwrap();
    server = server
        .with_upstream_port_override(upstream_port)
        .with_upstream_host_override("127.0.0.1".to_string())
        .with_upstream_tls(client_tls);

    let proxy_addr = server.bind().await.unwrap().tcp_addr();
    let direct_addr = server
        .bind_direct_https("127.0.0.1:0")
        .await
        .unwrap()
        .tcp_addr();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });

    (proxy_addr, direct_addr, shutdown_tx)
}

#[tokio::test]
async fn test_direct_https_allowed_request() {
    let t = test_report!("Direct HTTPS: allowed request is proxied correctly");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("direct-https-ok"))
        .hostname("allowed.example.com")
        .report(&t, "upstream echoing 'direct-https-ok'")
        .start()
        .await;

    let rules = vec![Rule {
        method: Some("*".to_string()),
        url: "https://allowed.example.com/*".to_string(),
        websocket: false,
        git: None,
        branches: None,
        allow_redirects: Vec::new(),
        log_body: false,
        protected_branches: None,
    }];

    let (_proxy_addr, direct_addr, shutdown_tx) =
        start_proxy_with_direct_https(&ca, rules, upstream.port()).await;

    t.action(format!(
        "Connect directly to proxy at {} with SNI=allowed.example.com",
        direct_addr
    ));

    // Use resolve to point allowed.example.com at the direct listener
    let ca_cert = Certificate::from_pem(&std::fs::read(&ca.cert_path).unwrap()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .no_proxy()
        .resolve(
            "allowed.example.com",
            SocketAddr::new("127.0.0.1".parse().unwrap(), direct_addr.port()),
        )
        .build()
        .unwrap();

    let resp = client
        .get(format!(
            "https://allowed.example.com:{}/hello",
            direct_addr.port()
        ))
        .send()
        .await
        .unwrap();

    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("body", &body.as_str(), &"direct-https-ok");

    upstream.shutdown();
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_direct_https_blocked_request() {
    let t = test_report!("Direct HTTPS: blocked request returns 451");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("should-not-reach"))
        .hostname("blocked.example.com")
        .report(&t, "upstream (should not be reached)")
        .start()
        .await;

    // Only allow a different host
    let rules = vec![Rule {
        method: Some("*".to_string()),
        url: "https://other.example.com/*".to_string(),
        websocket: false,
        git: None,
        branches: None,
        allow_redirects: Vec::new(),
        log_body: false,
        protected_branches: None,
    }];

    let (_proxy_addr, direct_addr, shutdown_tx) =
        start_proxy_with_direct_https(&ca, rules, upstream.port()).await;

    t.action("Connect to direct HTTPS listener with SNI=blocked.example.com".to_string());

    let ca_cert = Certificate::from_pem(&std::fs::read(&ca.cert_path).unwrap()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .no_proxy()
        .resolve(
            "blocked.example.com",
            SocketAddr::new("127.0.0.1".parse().unwrap(), direct_addr.port()),
        )
        .build()
        .unwrap();

    let resp = client
        .get(format!(
            "https://blocked.example.com:{}/secret",
            direct_addr.port()
        ))
        .send()
        .await
        .unwrap();

    t.assert_eq("status", &resp.status().as_u16(), &451u16);

    upstream.shutdown();
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_direct_https_credential_injection() {
    let t = test_report!("Direct HTTPS: credentials are injected into forwarded requests");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .hostname("api.example.com")
        .report(&t, "upstream echo handler")
        .start()
        .await;

    let rules = vec![Rule {
        method: Some("*".to_string()),
        url: "https://api.example.com/*".to_string(),
        websocket: false,
        git: None,
        branches: None,
        allow_redirects: Vec::new(),
        log_body: false,
        protected_branches: None,
    }];

    let credentials = vec![pyloros::config::Credential::Header {
        url: "https://api.example.com/*".to_string(),
        header: "x-api-key".to_string(),
        value: "test-secret-key".to_string(),
    }];

    // Need to build the proxy manually to add credentials
    let mut config = Config::minimal(
        "127.0.0.1:0".to_string(),
        ca.cert_path.clone(),
        ca.key_path.clone(),
    );
    config.rules = rules;
    config.credentials = credentials;
    config.logging.log_allowed_requests = false;
    config.logging.log_blocked_requests = false;

    let client_tls = ca.client_tls_config();
    let mut server = ProxyServer::new(config).unwrap();
    server = server
        .with_upstream_port_override(upstream.port())
        .with_upstream_host_override("127.0.0.1".to_string())
        .with_upstream_tls(client_tls);

    let _proxy_addr = server.bind().await.unwrap().tcp_addr();
    let direct_addr = server
        .bind_direct_https("127.0.0.1:0")
        .await
        .unwrap()
        .tcp_addr();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });

    t.action("Send GET via direct HTTPS, expect x-api-key header injected");

    let ca_cert = Certificate::from_pem(&std::fs::read(&ca.cert_path).unwrap()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .no_proxy()
        .resolve(
            "api.example.com",
            SocketAddr::new("127.0.0.1".parse().unwrap(), direct_addr.port()),
        )
        .build()
        .unwrap();

    let resp = client
        .get(format!(
            "https://api.example.com:{}/data",
            direct_addr.port()
        ))
        .send()
        .await
        .unwrap();

    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_contains("has injected header", &body, "x-api-key: test-secret-key");

    upstream.shutdown();
    let _ = shutdown_tx.send(());
}
