mod common;

use common::{echo_handler, rule, ReportingClient, TestCa, TestProxy, TestUpstream};

// ---------------------------------------------------------------------------
// Hop-by-hop header stripping tests
// ---------------------------------------------------------------------------
//
// A proxy must strip hop-by-hop headers (Connection, Keep-Alive,
// Proxy-Connection, etc.) before forwarding requests upstream, per RFC 7230
// section 6.1. We test against an h1-only upstream so that hyper's h2 client
// (which auto-strips these) doesn't mask the bug.

/// Proxy must strip hop-by-hop headers before forwarding to upstream.
/// Uses h1-only upstream to avoid hyper's h2 auto-stripping.
#[tokio::test]
async fn test_proxy_strips_hop_by_hop_headers() {
    let t = test_report!("Proxy strips hop-by-hop headers (h1→h1)");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .h1_only()
        .report(&t, "echoes request details (h1 only)")
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

    // Use h1-only client. reqwest strips Connection itself, so we add
    // Proxy-Connection and Keep-Alive which reqwest does NOT strip.
    let client = ReportingClient::new_h1_only(&t, proxy.addr(), &ca);
    let resp = client
        .get_with_headers(
            "https://localhost/test",
            &[
                ("Proxy-Connection", "Keep-Alive"),
                ("Keep-Alive", "timeout=5"),
            ],
        )
        .await;

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();

    t.assert_eq("Response status", &status, &200u16);
    t.assert_not_contains(
        "No proxy-connection header forwarded",
        &body,
        "proxy-connection:",
    );
    t.assert_not_contains("No keep-alive header forwarded", &body, "keep-alive:");

    proxy.shutdown();
    upstream.shutdown();
}

/// Normal (non-hop-by-hop) headers must still be forwarded through the proxy.
#[tokio::test]
async fn test_proxy_preserves_normal_headers() {
    let t = test_report!("Proxy preserves normal headers alongside hop-by-hop");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .h1_only()
        .report(&t, "echoes request details (h1 only)")
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
    let resp = client
        .get_with_headers(
            "https://localhost/test",
            &[
                ("Proxy-Connection", "Keep-Alive"),
                ("X-Custom", "test-value"),
            ],
        )
        .await;

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();

    t.assert_eq("Response status", &status, &200u16);
    t.assert_contains("Custom header forwarded", &body, "x-custom: test-value");

    proxy.shutdown();
    upstream.shutdown();
}
