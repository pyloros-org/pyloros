//! Integration tests for proxy authentication (HTTP Basic)

mod common;

use common::{ReportingClient, TestCa, TestProxy, TestUpstream, ok_handler};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

/// Helper: attempt an HTTPS GET and return either the response or the error debug string.
/// reqwest surfaces 407 on CONNECT as a connection error, not an HTTP response.
async fn try_https_get(
    client: &ReportingClient<'_>,
    url: &str,
) -> Result<reqwest::Response, String> {
    client.report().action(format!("GET `{}`", url));
    match client.inner().get(url).send().await {
        Ok(resp) => Ok(resp),
        Err(e) => Err(format!("{:?}", e)), // Debug format includes nested error types
    }
}

/// Auth enabled + correct credentials → 200
#[tokio::test]
async fn test_auth_correct_credentials_https() {
    let t = test_report!("Auth: correct credentials allow HTTPS request");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("auth ok"))
        .report(&t, "returns 'auth ok'")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![common::rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .auth("user", "pass")
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_with_proxy_auth(&t, proxy.addr(), &ca, "user", "pass");
    let resp = client.get("https://localhost/test").await;

    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("body", &body.as_str(), &"auth ok");

    proxy.shutdown();
    upstream.shutdown();
}

/// Auth enabled + wrong password → 407 (CONNECT rejected)
#[tokio::test]
async fn test_auth_wrong_password_returns_407() {
    let t = test_report!("Auth: wrong password returns 407");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("should not reach"))
        .report(&t, "returns 'should not reach'")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![common::rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .auth("user", "pass")
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_with_proxy_auth(&t, proxy.addr(), &ca, "user", "wrongpass");
    let result = try_https_get(&client, "https://localhost/test").await;

    // reqwest surfaces 407 on CONNECT as a connection error
    t.assert_true("request failed", result.is_err());
    t.assert_contains(
        "error mentions proxy auth",
        &result.unwrap_err(),
        "ProxyAuthRequired",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// Auth enabled + no credentials → 407 (CONNECT rejected)
#[tokio::test]
async fn test_auth_no_credentials_returns_407() {
    let t = test_report!("Auth: no credentials returns 407");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("should not reach"))
        .report(&t, "returns 'should not reach'")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![common::rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .auth("user", "pass")
    .report(&t)
    .start()
    .await;

    // Client without proxy auth
    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let result = try_https_get(&client, "https://localhost/test").await;

    // reqwest surfaces 407 on CONNECT as a connection error
    t.assert_true("request failed", result.is_err());
    t.assert_contains(
        "error mentions proxy auth",
        &result.unwrap_err(),
        "ProxyAuthRequired",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// Auth enabled + wrong username → 407 (CONNECT rejected)
#[tokio::test]
async fn test_auth_wrong_username_returns_407() {
    let t = test_report!("Auth: wrong username returns 407");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("should not reach"))
        .report(&t, "returns 'should not reach'")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![common::rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .auth("user", "pass")
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_with_proxy_auth(&t, proxy.addr(), &ca, "wronguser", "pass");
    let result = try_https_get(&client, "https://localhost/test").await;

    // reqwest surfaces 407 on CONNECT as a connection error
    t.assert_true("request failed", result.is_err());
    t.assert_contains(
        "error mentions proxy auth",
        &result.unwrap_err(),
        "ProxyAuthRequired",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// Auth disabled (no config) → 200 (backward compatibility)
#[tokio::test]
async fn test_auth_disabled_allows_request() {
    let t = test_report!("Auth: disabled (no config) allows request");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("no auth"))
        .report(&t, "returns 'no auth'")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![common::rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;

    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("body", &body.as_str(), &"no auth");

    proxy.shutdown();
    upstream.shutdown();
}

/// Auth enabled + plain HTTP + correct credentials → 200
#[tokio::test]
async fn test_auth_plain_http_correct_credentials() {
    let t = test_report!("Auth: plain HTTP with correct credentials returns 200");

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("plain auth ok"))
        .mount(&upstream)
        .await;

    let ca = TestCa::generate();
    let proxy = TestProxy::builder(
        &ca,
        vec![common::rule("GET", "http://localhost/*")],
        upstream.address().port(),
    )
    .auth("user", "pass")
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_plain_with_proxy_auth(&t, proxy.addr(), "user", "pass");
    let url = format!("http://localhost:{}/test", upstream.address().port());
    let resp = client.get(&url).await;

    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("body", &body.as_str(), &"plain auth ok");

    proxy.shutdown();
}

/// Auth enabled + plain HTTP + no credentials → 407
#[tokio::test]
async fn test_auth_plain_http_no_credentials_returns_407() {
    let t = test_report!("Auth: plain HTTP without credentials returns 407");

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("should not reach"))
        .mount(&upstream)
        .await;

    let ca = TestCa::generate();
    let proxy = TestProxy::builder(
        &ca,
        vec![common::rule("GET", "http://localhost/*")],
        upstream.address().port(),
    )
    .auth("user", "pass")
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let url = format!("http://localhost:{}/test", upstream.address().port());
    let resp = client.get(&url).await;

    t.assert_eq("status", &resp.status().as_u16(), &407u16);

    proxy.shutdown();
}
