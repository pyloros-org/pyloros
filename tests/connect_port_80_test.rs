//! Tests for port-80 CONNECT: the proxy accepts `CONNECT host:80`, hands the
//! upgraded byte stream to the same plain-HTTP serving path used by the
//! direct-HTTP listener, then forwards origin-style requests through the
//! explicit-proxy plain-HTTP handler. CONNECT to any other non-443 port is
//! still blocked.

mod common;

use common::{TestCa, TestProxy, read_audit_entries, rule};
use pyloros::config::Credential;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

/// Open a CONNECT tunnel to the proxy and return the live stream after the
/// proxy replies `HTTP/1.1 200`. The `tunnel_target` is the `host:port`
/// authority sent in the CONNECT request (drives the proxy's port-routing
/// decision); for port-80 tests pass something ending in `:80`.
async fn open_connect_tunnel(proxy_addr: std::net::SocketAddr, tunnel_target: &str) -> TcpStream {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n",
        target = tunnel_target
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    // Read the CONNECT response. The proxy sends "HTTP/1.1 200 OK\r\n\r\n"
    // (or an error response). Read up to and including the header terminator.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "proxy closed tunnel before sending CONNECT response");
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let response_head = String::from_utf8_lossy(&buf).to_string();
    assert!(
        response_head.starts_with("HTTP/1.1 200"),
        "expected 200 from CONNECT, got:\n{}",
        response_head
    );
    stream
}

/// Send an origin-form GET on an established stream and read the full response.
async fn tunneled_get(stream: &mut TcpStream, host_header: &str, path: &str) -> (u16, String) {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        path = path,
        host = host_header,
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

/// A CONNECT to port 80 followed by an allowed plain-HTTP request reaches the
/// upstream and returns its response. The upstream is reached by setting the
/// Host header to `localhost:<mockport>` inside the tunnel — that's what
/// drives the upstream destination after URI rewrite (same mechanism the
/// direct-HTTP listener uses), so we don't actually need to bind port 80.
#[tokio::test]
async fn test_port_80_connect_allowed_reaches_upstream() {
    let t = test_report!("Port-80 CONNECT: allowed tunneled HTTP reaches upstream");
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    t.setup("MockServer returning 200 'port-80-tunnel-ok'");
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("port-80-tunnel-ok"))
        .mount(&upstream)
        .await;
    let upstream_port = upstream.address().port();

    let rules = vec![rule(
        "GET",
        &format!("http://localhost:{}/*", upstream_port),
    )];
    let proxy = TestProxy::builder(&ca, rules, upstream_port)
        .report(&t)
        .start()
        .await;

    t.action("CONNECT localhost:80 then GET /hello with upstream Host header");
    let mut tunnel = open_connect_tunnel(proxy.addr(), "localhost:80").await;
    let (status, body) = tunneled_get(
        &mut tunnel,
        &format!("localhost:{}", upstream_port),
        "/hello",
    )
    .await;

    t.assert_eq("status", &status, &200u16);
    t.assert_contains("body", &body, "port-80-tunnel-ok");

    proxy.shutdown();
}

/// A CONNECT to port 80 followed by a request that no rule matches returns
/// 451 over the tunnel — the proxy applies the same filter that an explicit
/// plain-HTTP request would face.
#[tokio::test]
async fn test_port_80_connect_blocked_returns_451() {
    let t = test_report!("Port-80 CONNECT: unmatched tunneled HTTP is blocked with 451");
    let ca = TestCa::generate();

    // No rule for the host the client will actually request.
    let rules = vec![rule("GET", "http://other.example.com/*")];
    let proxy = TestProxy::builder(&ca, rules, 1).report(&t).start().await;

    t.action("CONNECT localhost:80 then GET /secret on a non-matching host");
    let mut tunnel = open_connect_tunnel(proxy.addr(), "localhost:80").await;
    let (status, _body) = tunneled_get(&mut tunnel, "localhost", "/secret").await;

    t.assert_eq("status", &status, &451u16);

    proxy.shutdown();
}

/// The audit entry for an allowed port-80 CONNECT request carries
/// `scheme: "http"` / `protocol: "http"` (proving it went through the
/// plain-HTTP path, not the HTTPS MITM path).
#[tokio::test]
async fn test_port_80_connect_audit_scheme_is_http() {
    let t = test_report!("Port-80 CONNECT: audit entry has scheme=http, protocol=http");
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;
    let upstream_port = upstream.address().port();

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let rules = vec![rule(
        "GET",
        &format!("http://localhost:{}/*", upstream_port),
    )];
    let proxy = TestProxy::builder(&ca, rules, upstream_port)
        .audit_log(audit_path_str)
        .report(&t)
        .start()
        .await;

    t.action("CONNECT localhost:80 + GET /a — exercise plain-HTTP path");
    let mut tunnel = open_connect_tunnel(proxy.addr(), "localhost:80").await;
    let (status, _) =
        tunneled_get(&mut tunnel, &format!("localhost:{}", upstream_port), "/a").await;
    t.assert_eq("status", &status, &200u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let raw = std::fs::read_to_string(audit_path_str).unwrap();
    t.output("audit_log", &raw);
    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "event",
        &entries[0]["event"].as_str().unwrap(),
        &"request_allowed",
    );
    t.assert_eq("scheme", &entries[0]["scheme"].as_str().unwrap(), &"http");
    t.assert_eq(
        "protocol",
        &entries[0]["protocol"].as_str().unwrap(),
        &"http",
    );

    proxy.shutdown();
}

/// Per SPEC.md, credentials are not injected over cleartext channels. A
/// port-80 CONNECT tunnels plain HTTP to the upstream, so even when a
/// credential rule matches the URL, the injected header must NOT appear in
/// the upstream-received request — same posture as an explicit plain-HTTP
/// proxy request.
#[tokio::test]
async fn test_port_80_connect_does_not_inject_credentials() {
    let t = test_report!("Port-80 CONNECT does not inject credentials (cleartext)");
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;
    let upstream_port = upstream.address().port();
    let url_pattern = format!("http://localhost:{}/*", upstream_port);

    let proxy = TestProxy::builder(&ca, vec![rule("*", &url_pattern)], upstream_port)
        .credentials(vec![Credential::Header {
            url: url_pattern.clone(),
            header: "x-api-key".to_string(),
            value: "should-not-inject".to_string(),
        }])
        .report(&t)
        .start()
        .await;

    t.action("CONNECT localhost:80 + GET /needs-creds");
    let mut tunnel = open_connect_tunnel(proxy.addr(), "localhost:80").await;
    let (status, _) = tunneled_get(
        &mut tunnel,
        &format!("localhost:{}", upstream_port),
        "/needs-creds",
    )
    .await;
    t.assert_eq("status", &status, &200u16);

    let requests = upstream.received_requests().await.unwrap();
    t.assert_eq("one request received", &requests.len(), &1usize);
    let has_api_key = requests[0].headers.get("x-api-key").is_some();
    t.assert_true("no x-api-key header on upstream request", !has_api_key);

    proxy.shutdown();
}

/// CONNECT to a port other than 80 or 443 is still blocked — that's the
/// "default-deny for unverifiable restrictions" guarantee (the proxy cannot
/// parse arbitrary protocols, so it refuses to tunnel them). The audit entry
/// carries `reason: "unsupported_connect_port"`.
#[tokio::test]
async fn test_unsupported_connect_port_still_blocked() {
    let t = test_report!("CONNECT to port 8080 is blocked with unsupported_connect_port");
    let ca = TestCa::generate();

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], 1)
        .audit_log(audit_path_str)
        .report(&t)
        .start()
        .await;

    t.action("Raw TCP CONNECT localhost:8080 (neither 80 nor 443)");
    let mut tcp = TcpStream::connect(proxy.addr()).await.unwrap();
    let connect_req = "CONNECT localhost:8080 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
    tcp.write_all(connect_req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 4096];
    let n = tcp.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]).to_string();

    t.assert_starts_with("Response starts with 451", &response, "HTTP/1.1 451");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "reason",
        &entries[0]["reason"].as_str().unwrap(),
        &"unsupported_connect_port",
    );

    proxy.shutdown();
}
