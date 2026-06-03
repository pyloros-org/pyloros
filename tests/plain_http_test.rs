mod common;

use common::{ReportingClient, TestCa, TestProxy, rule};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

// ---------------------------------------------------------------------------
// Plain HTTP forwarding tests
// ---------------------------------------------------------------------------

/// Allowed plain HTTP GET reaches upstream and returns 200 + body.
#[tokio::test]
async fn test_http_allowed_get_returns_200() {
    let t = test_report!("Plain HTTP allowed GET returns 200");

    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    t.setup("MockServer returning 200 'hello plain http'");
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("hello plain http"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let proxy = TestProxy::builder(&ca, vec![rule("GET", "http://localhost/*")], port)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let url = format!("http://localhost:{}/test", port);
    let resp = client.get(&url).await;

    t.assert_eq("Response status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("Response body", &body.as_str(), &"hello plain http");

    proxy.shutdown();
}

/// Blocked plain HTTP request returns 451.
#[tokio::test]
async fn test_http_blocked_request_returns_451() {
    let t = test_report!("Plain HTTP blocked request returns 451");

    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    t.setup("MockServer returning 200 (should not reach)");
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("should not reach"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    // Rule only allows example.com, not localhost
    let proxy = TestProxy::builder(&ca, vec![rule("GET", "http://example.com/*")], port)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let url = format!("http://localhost:{}/blocked", port);
    let resp = client.get(&url).await;

    t.assert_eq("Response status", &resp.status().as_u16(), &451u16);
    t.assert_eq(
        "X-Blocked-By header",
        &resp
            .headers()
            .get("X-Blocked-By")
            .unwrap()
            .to_str()
            .unwrap(),
        &"pyloros",
    );

    proxy.shutdown();
}

/// Plain HTTP forwarding strips hop-by-hop headers and forwards custom headers.
#[tokio::test]
async fn test_http_headers_forwarded() {
    let t = test_report!("Plain HTTP headers forwarded correctly");

    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    t.setup("MockServer returning 200");
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let proxy = TestProxy::builder(&ca, vec![rule("GET", "http://localhost/*")], port)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let url = format!("http://localhost:{}/headers", port);
    let resp = client
        .get_with_headers(
            &url,
            &[
                ("X-Custom-Header", "test-value"),
                ("Proxy-Connection", "keep-alive"),
            ],
        )
        .await;

    t.assert_eq("Response status", &resp.status().as_u16(), &200u16);

    // Inspect what the upstream actually received
    let received = upstream.received_requests().await.unwrap();
    t.assert_eq("Request count", &received.len(), &1usize);
    let req = &received[0];

    t.assert_eq(
        "Custom header forwarded",
        &req.headers
            .get("x-custom-header")
            .unwrap()
            .to_str()
            .unwrap(),
        &"test-value",
    );
    t.assert_true(
        "Hop-by-hop Proxy-Connection stripped",
        req.headers.get("proxy-connection").is_none(),
    );

    proxy.shutdown();
}

/// Plain HTTP upstream unreachable returns 502 Bad Gateway.
#[tokio::test]
async fn test_http_upstream_down_returns_502() {
    let t = test_report!("Plain HTTP upstream down returns 502");

    let ca = TestCa::generate();
    // Bind a port then drop the listener so nothing is listening
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = listener.local_addr().unwrap().port();
    drop(listener);

    t.setup("Upstream: dead port (nothing listening)");
    let proxy = TestProxy::builder(&ca, vec![rule("GET", "http://localhost/*")], dead_port)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let url = format!("http://localhost:{}/gone", dead_port);
    let resp = client.get(&url).await;

    t.assert_eq("Response status", &resp.status().as_u16(), &502u16);

    proxy.shutdown();
}

/// Plain HTTP POST with body is forwarded to upstream.
#[tokio::test]
async fn test_http_post_with_body() {
    let t = test_report!("Plain HTTP POST with body forwarded");

    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    t.setup("MockServer returning 200 'post ok'");
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("post ok"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let proxy = TestProxy::builder(&ca, vec![rule("POST", "http://localhost/*")], port)
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let url = format!("http://localhost:{}/submit", port);
    let resp = client.post_with_body(&url, "hello from client").await;

    t.assert_eq("Response status", &resp.status().as_u16(), &200u16);
    t.assert_eq(
        "Response body",
        &resp.text().await.unwrap().as_str(),
        &"post ok",
    );

    // Verify upstream received the POST with correct method and body
    let received = upstream.received_requests().await.unwrap();
    t.assert_eq("Request count", &received.len(), &1usize);
    let req = &received[0];
    t.assert_eq("Method is POST", &req.method.as_str(), &"POST");
    t.assert_eq(
        "Body forwarded",
        &req.body.as_slice(),
        &b"hello from client".as_slice(),
    );

    proxy.shutdown();
}

/// When the client does not send a Host header, the proxy constructs one
/// in the format `host:port` for non-80 ports.
#[tokio::test]
async fn test_host_header_constructed_when_absent() {
    let t = test_report!("Host header constructed when client omits it");

    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let proxy = TestProxy::builder(&ca, vec![rule("GET", "http://localhost/*")], port)
        .start()
        .await;

    // Send a raw HTTP request through the proxy *without* a Host header.
    // reqwest always adds Host, so we use a raw TCP stream.
    let mut stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    let raw_request = format!("GET http://localhost:{}/host-test HTTP/1.1\r\n\r\n", port);
    stream.write_all(raw_request.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    t.assert_true("Response contains 200", response.contains("200"));

    // Verify upstream received a constructed Host header
    let received = upstream.received_requests().await.unwrap();
    t.assert_eq("Request count", &received.len(), &1usize);
    let req = &received[0];
    let host_value = req.headers.get("host").unwrap().to_str().unwrap();
    let expected_host = format!("localhost:{}", port);
    t.assert_eq(
        "Constructed Host header",
        &host_value,
        &expected_host.as_str(),
    );

    proxy.shutdown();
}

/// When the client sends an explicit Host header, the proxy preserves it
/// and does NOT overwrite it with a constructed one.
#[tokio::test]
async fn test_host_header_preserved_when_present() {
    let t = test_report!("Client-provided Host header preserved by proxy");

    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let proxy = TestProxy::builder(&ca, vec![rule("GET", "http://localhost/*")], port)
        .start()
        .await;

    // Send a raw HTTP request with an explicit custom Host header
    let mut stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    let raw_request = format!(
        "GET http://localhost:{}/host-test HTTP/1.1\r\nHost: custom.example.com\r\n\r\n",
        port
    );
    stream.write_all(raw_request.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    t.assert_true("Response contains 200", response.contains("200"));

    // Verify upstream received the original Host header, not a constructed one
    let received = upstream.received_requests().await.unwrap();
    t.assert_eq("Request count", &received.len(), &1usize);
    let req = &received[0];
    let host_value = req.headers.get("host").unwrap().to_str().unwrap();
    t.assert_eq("Preserved Host header", &host_value, &"custom.example.com");

    proxy.shutdown();
}
