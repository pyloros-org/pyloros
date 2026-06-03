mod common;

use common::{ReportingClient, TestCa, TestProxy, TestUpstream, UpstreamHandler, ok_handler, rule};

// ---------------------------------------------------------------------------
// HTTP/2 tests
// ---------------------------------------------------------------------------

/// Default client (h2-capable) talks to h2-capable upstream — response uses HTTP/2.
#[tokio::test]
async fn test_h2_allowed_request() {
    let t = test_report!("HTTP/2 allowed request");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("h2 hello"))
        .report(&t, "returns 'h2 hello'")
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
    let resp = client.get("https://localhost/h2").await;

    t.assert_eq("Response status", &resp.status().as_u16(), &200u16);
    t.assert_eq(
        "HTTP version",
        &format!("{:?}", resp.version()),
        &"HTTP/2.0",
    );
    t.assert_eq(
        "Response body",
        &resp.text().await.unwrap().as_str(),
        &"h2 hello",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// HTTP/1.1-only client talks to h2-capable upstream — proxy translates protocol.
#[tokio::test]
async fn test_h1_client_to_h2_upstream() {
    let t = test_report!("H1 client to H2 upstream protocol translation");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("translated"))
        .report(&t, "returns 'translated'")
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

    let client = ReportingClient::new_h1_only(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;

    t.assert_eq("Response status", &resp.status().as_u16(), &200u16);
    t.assert_eq(
        "HTTP version",
        &format!("{:?}", resp.version()),
        &"HTTP/1.1",
    );
    t.assert_eq(
        "Response body",
        &resp.text().await.unwrap().as_str(),
        &"translated",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// h2-capable client talks to h1-only upstream — proxy translates protocol.
#[tokio::test]
async fn test_h2_client_to_h1_upstream() {
    let t = test_report!("H2 client to H1-only upstream protocol translation");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("h1 only"))
        .h1_only()
        .report(&t, "returns 'h1 only'")
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
    let resp = client.get("https://localhost/test").await;

    t.assert_eq("Response status", &resp.status().as_u16(), &200u16);
    t.assert_eq(
        "HTTP version",
        &format!("{:?}", resp.version()),
        &"HTTP/2.0",
    );
    t.assert_eq(
        "Response body",
        &resp.text().await.unwrap().as_str(),
        &"h1 only",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// Blocked request over HTTP/2 returns 451.
#[tokio::test]
async fn test_h2_blocked_returns_451() {
    let t = test_report!("Blocked request over HTTP/2 returns 451");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("should not reach"))
        .report(&t, "returns 'should not reach'")
        .start()
        .await;
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://example.com/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/blocked").await;

    let status = resp.status().as_u16();
    let version = format!("{:?}", resp.version());
    let blocked_by = resp
        .headers()
        .get("X-Blocked-By")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    t.assert_eq("Response status", &status, &451u16);
    t.assert_eq("HTTP version", &version.as_str(), &"HTTP/2.0");
    t.assert_eq("X-Blocked-By header", &blocked_by.as_str(), &"pyloros");

    proxy.shutdown();
    upstream.shutdown();
}

/// Large body over HTTP/2 is forwarded intact.
#[tokio::test]
async fn test_h2_large_body() {
    use std::sync::Arc;

    let t = test_report!("Large body over HTTP/2 forwarded intact");

    let ca = TestCa::generate();
    let large_body: String = "y".repeat(100_000);
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
    let version = format!("{:?}", resp.version());
    let body = resp.text().await.unwrap();

    t.assert_eq("Response status", &status, &200u16);
    t.assert_eq("HTTP version", &version.as_str(), &"HTTP/2.0");
    t.assert_eq("Body length", &body.len(), &expected.len());
    t.assert_eq("Body content matches", &body, &expected);

    proxy.shutdown();
    upstream.shutdown();
}
