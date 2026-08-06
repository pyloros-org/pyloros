mod common;

use common::{ReportingClient, TestCa, TestProxy, TestUpstream, ok_handler, rule};

// ---------------------------------------------------------------------------
// Core e2e tests — allowed/blocked flow
// ---------------------------------------------------------------------------

/// Allowed GET reaches upstream and returns 200 + body.
#[tokio::test]
async fn test_allowed_get_returns_200() {
    let t = test_report!("Allowed GET reaches upstream");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello from upstream"))
        .report(&t, "returns 'hello from upstream'")
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

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();

    t.assert_eq("Response status", &status, &200u16);
    t.assert_eq("Response body", &body.as_str(), &"hello from upstream");

    proxy.shutdown();
    upstream.shutdown();
}

/// Blocked request (no matching rule) returns 451 with X-Blocked-By header.
#[tokio::test]
async fn test_blocked_request_returns_451() {
    let t = test_report!("Blocked request returns 451");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("should not reach"))
        .report(&t, "returns 'should not reach'")
        .start()
        .await;

    // Rule only allows example.com, not localhost
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
    let blocked_by = resp
        .headers()
        .get("X-Blocked-By")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    t.assert_eq("Response status", &status, &451u16);
    t.assert_eq("X-Blocked-By header", &blocked_by.as_str(), &"pyloros");

    proxy.shutdown();
    upstream.shutdown();
}

/// Method filtering: rule allows GET but POST is blocked.
#[tokio::test]
async fn test_method_filtering() {
    let t = test_report!("Method filtering: GET allowed, POST blocked");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "returns 'ok'")
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

    // GET should be allowed
    let resp = client.get("https://localhost/path").await;
    t.assert_eq("GET status", &resp.status().as_u16(), &200u16);

    // POST should be blocked
    let resp = client.post("https://localhost/path").await;
    t.assert_eq("POST status", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

/// Empty ruleset blocks everything.
#[tokio::test]
async fn test_empty_ruleset_blocks_all() {
    let t = test_report!("Empty ruleset blocks all requests");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("nope"))
        .report(&t, "returns 'nope'")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/anything").await;

    t.assert_eq("Response status", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Wildcard + multi-rule tests
// ---------------------------------------------------------------------------

/// Wildcard method (`*`) allows GET, POST, PUT.
#[tokio::test]
async fn test_wildcard_method() {
    let t = test_report!("Wildcard method allows any HTTP method");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "returns 'ok'")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    for method in &["GET", "POST", "PUT"] {
        let resp = client
            .request(method.parse().unwrap(), "https://localhost/test")
            .await;
        t.assert_eq(
            &format!("{} status", method),
            &resp.status().as_u16(),
            &200u16,
        );
    }

    proxy.shutdown();
    upstream.shutdown();
}

/// Wildcard path: `/api/*` allows `/api/foo` but blocks `/other`.
#[tokio::test]
async fn test_wildcard_path() {
    let t = test_report!("Wildcard path matching");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "returns 'ok'")
        .start()
        .await;
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/api/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // /api/foo should be allowed
    let resp = client.get("https://localhost/api/foo").await;
    t.assert_eq("/api/foo status", &resp.status().as_u16(), &200u16);

    // /api/foo/bar/baz should also be allowed (* is multi-segment)
    let resp = client.get("https://localhost/api/foo/bar/baz").await;
    t.assert_eq("/api/foo/bar/baz status", &resp.status().as_u16(), &200u16);

    // /other should be blocked
    let resp = client.get("https://localhost/other").await;
    t.assert_eq("/other status", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

/// Multiple rules: correct allow/block behavior.
#[tokio::test]
async fn test_multiple_rules() {
    let t = test_report!("Multiple rules allow/block correctly");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "returns 'ok'")
        .start()
        .await;
    let proxy = TestProxy::builder(
        &ca,
        vec![
            rule("GET", "https://localhost/api/*"),
            rule("POST", "https://localhost/submit"),
        ],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // GET /api/data — allowed by first rule
    let resp = client.get("https://localhost/api/data").await;
    t.assert_eq("GET /api/data status", &resp.status().as_u16(), &200u16);

    // POST /submit — allowed by second rule
    let resp = client.post("https://localhost/submit").await;
    t.assert_eq("POST /submit status", &resp.status().as_u16(), &200u16);

    // POST /api/data — not allowed
    let resp = client.post("https://localhost/api/data").await;
    t.assert_eq("POST /api/data status", &resp.status().as_u16(), &451u16);

    // GET /submit — not allowed
    let resp = client.get("https://localhost/submit").await;
    t.assert_eq("GET /submit status", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}
