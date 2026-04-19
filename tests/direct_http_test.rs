//! Tests for direct HTTP mode (Host-header-based routing without proxy protocol).

mod common;

use common::*;
use pyloros::config::Rule;
use pyloros::{Config, ProxyServer};
use std::net::SocketAddr;
use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

/// Start a proxy with both the regular proxy listener and a direct-HTTP listener,
/// forwarding all upstream connections to `upstream_port` on 127.0.0.1.
async fn start_proxy_with_direct_http(
    ca: &TestCa,
    rules: Vec<Rule>,
    upstream_port: u16,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let mut config = Config::minimal(
        "127.0.0.1:0".to_string(),
        ca.cert_path.clone(),
        ca.key_path.clone(),
    );
    config.rules = rules;
    config.logging.log_allowed_requests = false;
    config.logging.log_blocked_requests = false;

    let mut server = ProxyServer::new(config).unwrap();
    server = server
        .with_upstream_port_override(upstream_port)
        .with_upstream_host_override("127.0.0.1".to_string());

    let _proxy_addr = server.bind().await.unwrap().tcp_addr();
    let direct_addr = server
        .bind_direct_http("127.0.0.1:0")
        .await
        .unwrap()
        .tcp_addr();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });

    (direct_addr, shutdown_tx)
}

#[tokio::test]
async fn test_direct_http_allowed_request() {
    let t = test_report!("Direct HTTP: allowed request is proxied to upstream");
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("direct-http-ok"))
        .mount(&upstream)
        .await;
    t.setup(format!(
        "wiremock upstream on port {}",
        upstream.address().port()
    ));

    let rules = vec![rule("*", "http://allowed.example.com/*")];

    let (direct_addr, shutdown_tx) =
        start_proxy_with_direct_http(&ca, rules, upstream.address().port()).await;

    t.action(format!(
        "Send plain HTTP GET directly to listener at {} with Host: allowed.example.com",
        direct_addr
    ));

    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve(
            "allowed.example.com",
            SocketAddr::new("127.0.0.1".parse().unwrap(), direct_addr.port()),
        )
        .build()
        .unwrap();

    let resp = client
        .get(format!(
            "http://allowed.example.com:{}/hello",
            direct_addr.port()
        ))
        .send()
        .await
        .unwrap();

    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("body", &body.as_str(), &"direct-http-ok");

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_direct_http_blocked_request() {
    let t = test_report!("Direct HTTP: unmatched request returns 451");
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("should-not-reach"))
        .mount(&upstream)
        .await;

    // Rule allows a different host
    let rules = vec![rule("*", "http://other.example.com/*")];

    let (direct_addr, shutdown_tx) =
        start_proxy_with_direct_http(&ca, rules, upstream.address().port()).await;

    t.action("Send plain HTTP GET with Host: blocked.example.com (no matching rule)");

    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve(
            "blocked.example.com",
            SocketAddr::new("127.0.0.1".parse().unwrap(), direct_addr.port()),
        )
        .build()
        .unwrap();

    let resp = client
        .get(format!(
            "http://blocked.example.com:{}/secret",
            direct_addr.port()
        ))
        .send()
        .await
        .unwrap();

    t.assert_eq("status", &resp.status().as_u16(), &451u16);

    // Upstream must not have received the request
    let received = upstream.received_requests().await.unwrap();
    t.assert_eq("upstream got 0 requests", &received.len(), &0usize);

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_direct_http_branch_rule_blocks_plain_http() {
    let t = test_report!(
        "Direct HTTP: branch-restriction rule blocks plain HTTP (body inspection requires HTTPS)"
    );
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("should-not-reach"))
        .mount(&upstream)
        .await;

    // A git rule with branch restriction would force body inspection;
    // this must block over plain HTTP.
    let rules = vec![git_rule_with_branches(
        "push",
        "http://git.example.com/repo.git",
        &["main"],
    )];

    let (direct_addr, shutdown_tx) =
        start_proxy_with_direct_http(&ca, rules, upstream.address().port()).await;

    t.action("Push-style request over direct HTTP must be blocked");

    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve(
            "git.example.com",
            SocketAddr::new("127.0.0.1".parse().unwrap(), direct_addr.port()),
        )
        .build()
        .unwrap();

    let resp = client
        .post(format!(
            "http://git.example.com:{}/repo.git/git-receive-pack",
            direct_addr.port()
        ))
        .header("content-type", "application/x-git-receive-pack-request")
        .body("dummy")
        .send()
        .await
        .unwrap();

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);
    let received = upstream.received_requests().await.unwrap();
    t.assert_eq("upstream got 0 requests", &received.len(), &0usize);

    let _ = shutdown_tx.send(());
}
