//! Tests for direct HTTP mode (Host-header-based routing without proxy protocol).

mod common;

use common::*;
use pyloros::config::Rule;
use pyloros::{Config, ProxyServer};
use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

/// Start a proxy with both the regular proxy listener and a direct-HTTP listener
/// bound on 127.0.0.1. Returns the direct-HTTP address and a shutdown handle.
///
/// Direct-HTTP forwards to whatever the Host header says, so tests use `localhost`
/// as the target hostname — it resolves to 127.0.0.1 on any system and lets a
/// real wiremock server act as the upstream without any host-override plumbing.
async fn start_proxy_with_direct_http(
    ca: &TestCa,
    rules: Vec<Rule>,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let mut config = Config::minimal(
        "127.0.0.1:0".to_string(),
        ca.cert_path.clone(),
        ca.key_path.clone(),
    );
    config.rules = rules;
    config.logging.log_allowed_requests = false;
    config.logging.log_blocked_requests = false;

    let mut server = ProxyServer::new(config).unwrap();
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

/// Send a raw HTTP/1.1 request to the direct-HTTP listener. Using a raw TCP
/// client is simpler than configuring reqwest to bypass proxy + DNS, and mirrors
/// how `apt` or `wget` behave when wildcard DNS lands their plain-HTTP connection
/// on the proxy.
async fn raw_get(
    direct_addr: std::net::SocketAddr,
    host_header: &str,
    path: &str,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(direct_addr).await.unwrap();
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host_header
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status_line = text.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
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
    let upstream_port = upstream.address().port();
    t.setup(format!("wiremock upstream on localhost:{}", upstream_port));

    let rules = vec![rule("*", &format!("http://localhost:{}/*", upstream_port))];

    let (direct_addr, shutdown_tx) = start_proxy_with_direct_http(&ca, rules).await;

    t.action(format!(
        "Send raw plain HTTP GET to direct listener at {} with Host: localhost:{}",
        direct_addr, upstream_port
    ));

    let (status, body) = raw_get(
        direct_addr,
        &format!("localhost:{}", upstream_port),
        "/hello",
    )
    .await;

    t.assert_eq("status", &status, &200u16);
    t.assert_contains("body", &body, "direct-http-ok");

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
    let upstream_port = upstream.address().port();

    // Rule allows a different port/host pair
    let rules = vec![rule("*", "http://other.example.com/*")];

    let (direct_addr, shutdown_tx) = start_proxy_with_direct_http(&ca, rules).await;

    t.action("Send raw plain HTTP GET with unmatched Host header");

    let (status, _body) = raw_get(
        direct_addr,
        &format!("localhost:{}", upstream_port),
        "/secret",
    )
    .await;

    t.assert_eq("status 451", &status, &451u16);

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
    let upstream_port = upstream.address().port();

    // A git rule with branch restriction would force body inspection;
    // over plain HTTP this must be blocked (body inspection needs HTTPS).
    let rules = vec![git_rule_with_branches(
        "push",
        &format!("http://localhost:{}/repo.git", upstream_port),
        &["main"],
    )];

    let (direct_addr, shutdown_tx) = start_proxy_with_direct_http(&ca, rules).await;

    t.action("Push-style request over direct HTTP must be blocked with 451");

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(direct_addr).await.unwrap();
    let body = "dummy";
    let req = format!(
        "POST /repo.git/git-receive-pack HTTP/1.1\r\nHost: localhost:{}\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        upstream_port,
        body.len(),
        body,
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    t.assert_eq("status 451", &status, &451u16);
    let received = upstream.received_requests().await.unwrap();
    t.assert_eq("upstream got 0 requests", &received.len(), &0usize);

    let _ = shutdown_tx.send(());
}
