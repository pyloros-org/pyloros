mod common;

use common::{
    ReportingClient, TestCa, TestProxy, TestUpstream, UpstreamHandler, echo_handler, ok_handler,
    rule,
};

// ---------------------------------------------------------------------------
// Header forwarding + error handling tests
// ---------------------------------------------------------------------------

/// Request headers are forwarded to upstream.
#[tokio::test]
async fn test_request_headers_forwarded() {
    let t = test_report!("Request headers forwarded to upstream");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo handler")
        .start()
        .await;
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .get_with_header("https://localhost/headers", "X-Custom-Header", "test-value")
        .await;

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();

    t.assert_eq("Response status", &status, &200u16);
    t.assert_contains(
        "Custom header in body",
        &body,
        "x-custom-header: test-value",
    );
}

/// Response headers are forwarded to client.
#[tokio::test]
async fn test_response_headers_forwarded() {
    let t = test_report!("Response headers forwarded to client");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo handler")
        .start()
        .await;
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/headers").await;

    let status = resp.status().as_u16();
    let x_echo = resp
        .headers()
        .get("X-Echo")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    t.assert_eq("Response status", &status, &200u16);
    t.assert_eq("X-Echo header", &x_echo.as_str(), &"true");
}

/// Upstream down returns 502 Bad Gateway.
#[tokio::test]
async fn test_upstream_down_returns_502() {
    let t = test_report!("Upstream down returns 502");

    let ca = TestCa::generate();
    // Start and immediately shutdown the upstream so its port is dead
    let upstream = TestUpstream::builder(&ca, ok_handler("nope")).start().await;
    let dead_port = upstream.port();
    upstream.shutdown();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    t.setup("Upstream: shut down (dead port)");
    let proxy = TestProxy::builder(&ca, vec![rule("GET", "https://localhost/*")], dead_port)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/gone").await;

    t.assert_eq("Response status", &resp.status().as_u16(), &502u16);

    proxy.shutdown();
}

/// Large response body is forwarded intact.
#[tokio::test]
async fn test_large_response_body() {
    use std::sync::Arc;

    let t = test_report!("Large response body forwarded intact");

    let ca = TestCa::generate();
    let large_body: String = "x".repeat(100_000);
    let expected = large_body.clone();

    let handler: UpstreamHandler = Arc::new(move |_req| {
        let body = large_body.clone();
        Box::pin(async move {
            use bytes::Bytes;
            use http_body_util::{BodyExt, Full};
            Ok(hyper::Response::builder()
                .status(200)
                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                .unwrap())
        })
    });

    let upstream = TestUpstream::builder(&ca, handler)
        .report(&t, "returns 100KB body")
        .start()
        .await;
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/large").await;

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();

    t.assert_eq("Response status", &status, &200u16);
    t.assert_eq("Body length", &body.len(), &expected.len());
    t.assert_eq("Body content matches", &body, &expected);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// CONNECT port restriction tests
// ---------------------------------------------------------------------------

/// CONNECT to a non-443 port is blocked with 451.
#[tokio::test]
async fn test_connect_non_443_port_blocked() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let t = test_report!("CONNECT to non-443 port blocked");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("should not reach"))
        .report(&t, "returns 'should not reach'")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .report(&t)
        .start()
        .await;

    // Raw TCP connect to proxy, send CONNECT with non-443 port
    t.action("Raw TCP CONNECT localhost:8080 (non-443 port)");
    let mut tcp = TcpStream::connect(proxy.addr()).await.unwrap();
    let connect_req = "CONNECT localhost:8080 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
    tcp.write_all(connect_req.as_bytes()).await.unwrap();

    // Read response
    let mut buf = [0u8; 4096];
    let n = tcp.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]).to_string();

    t.assert_starts_with("Response starts with 451", &response, "HTTP/1.1 451");
    t.assert_contains("X-Blocked-By header", &response, "X-Blocked-By: pyloros");
    t.assert_contains(
        "Blocking reason in body",
        &response,
        "Request blocked by proxy policy",
    );

    proxy.shutdown();
    upstream.shutdown();
}
