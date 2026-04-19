//! E2E tests asserting that rules distinguish between http:// and https://
//! schemes — an https rule must NOT grant access to the same URL over plain HTTP,
//! and vice versa.

mod common;

use common::*;
use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

/// An `https://` rule must not match a plain-HTTP request through the proxy.
#[tokio::test]
async fn test_https_rule_does_not_match_http_request() {
    let t = test_report!("https:// rule does not allow plain HTTP request to same host");
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("should-not-reach"))
        .mount(&upstream)
        .await;
    let plain_port = upstream.address().port();

    // Only an https rule — plain http to the same host+path must be blocked.
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("*", &format!("https://localhost:{}/*", plain_port))],
        plain_port,
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let resp = client
        .get(&format!("http://localhost:{}/data", plain_port))
        .await;

    t.assert_eq("status 451 (blocked)", &resp.status().as_u16(), &451u16);

    let received = upstream.received_requests().await.unwrap();
    t.assert_eq("upstream got 0 requests", &received.len(), &0usize);

    proxy.shutdown();
}

/// An `http://` rule must not match an HTTPS CONNECT request to the same host.
#[tokio::test]
async fn test_http_rule_does_not_match_https_request() {
    let t = test_report!("http:// rule does not allow HTTPS request to same host");
    let ca = TestCa::generate();

    let upstream = TestUpstream::builder(&ca, ok_handler("should-not-reach"))
        .report(&t, "HTTPS upstream (should not be reached)")
        .start()
        .await;

    // Only an http rule — https CONNECT to the same host must be blocked.
    let proxy = TestProxy::builder(&ca, vec![rule("*", "http://localhost/*")], upstream.port())
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/data").await;

    t.assert_eq("status 451 (blocked)", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

/// A wildcard-scheme rule (`*://...`) must match a plain-HTTP request.
/// (The https side of the wildcard is covered by unit tests in matcher.rs; a CONNECT-tunnel
/// e2e pairing is awkward because CONNECT only permits port 443.)
#[tokio::test]
async fn test_wildcard_scheme_rule_matches_http() {
    let t = test_report!("Wildcard scheme rule (*://) matches a plain-HTTP request");
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("http-ok"))
        .mount(&upstream)
        .await;
    let http_port = upstream.address().port();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule("*", &format!("*://localhost:{}/*", http_port))],
        http_port,
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let resp = client
        .get(&format!("http://localhost:{}/data", http_port))
        .await;
    t.assert_eq("http status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
}
