//! End-to-end tests for the redirect-following feature (`allow_redirects`).
//!
//! Most tests use two plain HTTP mock servers on different localhost ports
//! to simulate a cross-host redirect (origin → CDN). All logic flows through
//! the proxy's plain HTTP handler path, which shares the redirect-whitelist
//! primitive with the MITM/HTTPS path.

#[path = "common/mod.rs"]
mod common;

use bytes::Bytes;
use common::{rule, rule_with_redirects, ReportingClient, TestCa, TestProxy, TestUpstream};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use wiremock::{
    matchers::{method, path as wm_path},
    Mock, MockServer, ResponseTemplate,
};

/// Build a client that does NOT auto-follow redirects, so tests can observe
/// each hop individually and the follow-up request goes through the proxy
/// explicitly (reqwest with follow=none returns the 3xx to the caller).
fn plain_client_no_follow(
    t: &pyloros_test_support::TestReport,
    proxy_addr: std::net::SocketAddr,
) -> ReportingClient<'_> {
    ReportingClient::new_plain_no_follow(t, proxy_addr)
}

/// Baseline: a rule without `allow_redirects` does NOT whitelist the redirect
/// target; the follow-up request is blocked.
#[tokio::test]
async fn test_rule_without_allow_redirects_blocks_followup() {
    let t = test_report!("Rule without allow_redirects: redirect target follow-up is blocked");

    let ca = TestCa::generate();

    let cdn = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/cdn/file"))
        .respond_with(ResponseTemplate::new(200).set_body_string("payload"))
        .mount(&cdn)
        .await;
    let cdn_port = cdn.address().port();

    let origin = MockServer::start().await;
    let location = format!("http://localhost:{}/cdn/file", cdn_port);
    Mock::given(method("GET"))
        .and(wm_path("/origin"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", location.as_str()))
        .mount(&origin)
        .await;
    let origin_port = origin.address().port();

    // Only the origin is allowed; no redirect policy.
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", &format!("http://localhost:{}/*", origin_port))],
        origin_port,
    )
    .report(&t)
    .start()
    .await;

    let client = plain_client_no_follow(&t, proxy.addr());
    let origin_url = format!("http://localhost:{}/origin", origin_port);
    let resp = client.get(&origin_url).await;
    t.assert_eq("origin response is 302", &resp.status().as_u16(), &302u16);

    // Attempt the redirect target directly through the proxy — should be 451.
    let resp2 = client.get(&location).await;
    t.assert_eq(
        "CDN follow-up blocked (451)",
        &resp2.status().as_u16(),
        &451u16,
    );

    proxy.shutdown();
}

/// Rule with `allow_redirects = ["*"]` whitelists any redirect target.
#[tokio::test]
async fn test_allow_redirects_wildcard_whitelists_target() {
    let t = test_report!("allow_redirects=[\"*\"] whitelists any redirect target for TTL");

    let ca = TestCa::generate();

    let cdn = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/cdn/file"))
        .respond_with(ResponseTemplate::new(200).set_body_string("payload"))
        .mount(&cdn)
        .await;
    let cdn_port = cdn.address().port();

    let origin = MockServer::start().await;
    let location = format!("http://localhost:{}/cdn/file", cdn_port);
    Mock::given(method("GET"))
        .and(wm_path("/origin"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", location.as_str()))
        .mount(&origin)
        .await;
    let origin_port = origin.address().port();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_redirects(
            "GET",
            &format!("http://localhost:{}/*", origin_port),
            &["*"],
        )],
        origin_port,
    )
    .report(&t)
    .start()
    .await;

    let client = plain_client_no_follow(&t, proxy.addr());
    let origin_url = format!("http://localhost:{}/origin", origin_port);
    let resp = client.get(&origin_url).await;
    t.assert_eq("origin response is 302", &resp.status().as_u16(), &302u16);

    // Follow-up to CDN should now be allowed by the whitelist.
    let resp2 = client.get(&location).await;
    t.assert_eq(
        "CDN follow-up allowed (200)",
        &resp2.status().as_u16(),
        &200u16,
    );
    t.assert_eq(
        "CDN body",
        &resp2.text().await.unwrap().as_str(),
        &"payload",
    );

    proxy.shutdown();
}

/// `allow_redirects` pattern list is enforced: Location matching the list is
/// whitelisted, Location outside the list is not.
#[tokio::test]
async fn test_allow_redirects_pattern_enforcement() {
    let t = test_report!("allow_redirects enforces its pattern list");

    let ca = TestCa::generate();

    // Two CDN mock servers; only one matches the pattern.
    let allowed_cdn = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/asset"))
        .respond_with(ResponseTemplate::new(200).set_body_string("allowed-cdn"))
        .mount(&allowed_cdn)
        .await;
    let allowed_cdn_port = allowed_cdn.address().port();

    let forbidden_cdn = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/asset"))
        .respond_with(ResponseTemplate::new(200).set_body_string("forbidden-cdn"))
        .mount(&forbidden_cdn)
        .await;
    let forbidden_cdn_port = forbidden_cdn.address().port();

    // Origin redirects to one or the other depending on path.
    let origin = MockServer::start().await;
    let allowed_loc = format!("http://localhost:{}/asset", allowed_cdn_port);
    let forbidden_loc = format!("http://localhost:{}/asset", forbidden_cdn_port);
    Mock::given(method("GET"))
        .and(wm_path("/to-allowed"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", allowed_loc.as_str()))
        .mount(&origin)
        .await;
    Mock::given(method("GET"))
        .and(wm_path("/to-forbidden"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", forbidden_loc.as_str()))
        .mount(&origin)
        .await;
    let origin_port = origin.address().port();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_redirects(
            "GET",
            &format!("http://localhost:{}/*", origin_port),
            &[&format!("http://localhost:{}/*", allowed_cdn_port)],
        )],
        origin_port,
    )
    .report(&t)
    .start()
    .await;

    let client = plain_client_no_follow(&t, proxy.addr());

    // Redirect to matching CDN → whitelisted → follow-up succeeds.
    let r1 = client
        .get(&format!("http://localhost:{}/to-allowed", origin_port))
        .await;
    t.assert_eq("origin→allowed 302", &r1.status().as_u16(), &302u16);
    let r1b = client.get(&allowed_loc).await;
    t.assert_eq("allowed CDN follow-up 200", &r1b.status().as_u16(), &200u16);

    // Redirect to non-matching CDN → NOT whitelisted → follow-up blocked.
    let r2 = client
        .get(&format!("http://localhost:{}/to-forbidden", origin_port))
        .await;
    t.assert_eq("origin→forbidden 302", &r2.status().as_u16(), &302u16);
    let r2b = client.get(&forbidden_loc).await;
    t.assert_eq(
        "forbidden CDN follow-up 451",
        &r2b.status().as_u16(),
        &451u16,
    );

    proxy.shutdown();
}

/// Whitelist entries expire after the configured TTL.
#[tokio::test]
async fn test_whitelist_ttl_expiry() {
    let t = test_report!("Whitelist entries expire after the configured TTL");

    let ca = TestCa::generate();

    let cdn = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/file"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&cdn)
        .await;
    let cdn_port = cdn.address().port();

    let origin = MockServer::start().await;
    let location = format!("http://localhost:{}/file", cdn_port);
    Mock::given(method("GET"))
        .and(wm_path("/origin"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", location.as_str()))
        .mount(&origin)
        .await;
    let origin_port = origin.address().port();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_redirects(
            "GET",
            &format!("http://localhost:{}/*", origin_port),
            &["*"],
        )],
        origin_port,
    )
    .redirect_whitelist_ttl_secs(1)
    .report(&t)
    .start()
    .await;

    let client = plain_client_no_follow(&t, proxy.addr());

    // Trigger whitelist insertion.
    let r = client
        .get(&format!("http://localhost:{}/origin", origin_port))
        .await;
    t.assert_eq("origin 302", &r.status().as_u16(), &302u16);

    // Within TTL: allowed.
    let r1 = client.get(&location).await;
    t.assert_eq("within TTL allowed", &r1.status().as_u16(), &200u16);

    // Wait past TTL.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // After TTL: blocked.
    let r2 = client.get(&location).await;
    t.assert_eq("past TTL blocked", &r2.status().as_u16(), &451u16);

    proxy.shutdown();
}

/// Redirect chains extend recursively using the origin rule's patterns.
#[tokio::test]
async fn test_redirect_chain_recursive() {
    let t = test_report!(
        "Redirect chain: a whitelisted 3xx response extends the whitelist with the new Location"
    );

    let ca = TestCa::generate();

    // Hop 3: final payload.
    let hop3 = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/final"))
        .respond_with(ResponseTemplate::new(200).set_body_string("final-payload"))
        .mount(&hop3)
        .await;
    let hop3_port = hop3.address().port();

    // Hop 2: redirects to hop 3.
    let hop2 = MockServer::start().await;
    let hop3_url = format!("http://localhost:{}/final", hop3_port);
    Mock::given(method("GET"))
        .and(wm_path("/hop2"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", hop3_url.as_str()))
        .mount(&hop2)
        .await;
    let hop2_port = hop2.address().port();

    // Origin: redirects to hop 2.
    let origin = MockServer::start().await;
    let hop2_url = format!("http://localhost:{}/hop2", hop2_port);
    Mock::given(method("GET"))
        .and(wm_path("/start"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", hop2_url.as_str()))
        .mount(&origin)
        .await;
    let origin_port = origin.address().port();

    // Allow redirects matching "localhost:ANY/*" — so both hop2 and hop3 are in scope.
    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_redirects(
            "GET",
            &format!("http://localhost:{}/*", origin_port),
            &["*"],
        )],
        origin_port,
    )
    .report(&t)
    .start()
    .await;

    let client = plain_client_no_follow(&t, proxy.addr());

    // Step through manually so we can assert each hop.
    let r1 = client
        .get(&format!("http://localhost:{}/start", origin_port))
        .await;
    t.assert_eq("hop1 (origin)", &r1.status().as_u16(), &302u16);

    let r2 = client.get(&hop2_url).await;
    t.assert_eq("hop2 allowed 302", &r2.status().as_u16(), &302u16);

    let r3 = client.get(&hop3_url).await;
    t.assert_eq("hop3 allowed 200", &r3.status().as_u16(), &200u16);
    t.assert_eq(
        "final payload",
        &r3.text().await.unwrap().as_str(),
        &"final-payload",
    );

    proxy.shutdown();
}

/// Relative `Location` headers are resolved against the request URL.
#[tokio::test]
async fn test_relative_location_resolution() {
    let t = test_report!("Relative Location header resolves against request URL");

    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/origin"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/cdn/file"))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(wm_path("/cdn/file"))
        .respond_with(ResponseTemplate::new(200).set_body_string("relative-ok"))
        .mount(&upstream)
        .await;
    let upstream_port = upstream.address().port();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_redirects(
            "GET",
            &format!("http://localhost:{}/origin", upstream_port),
            &[&format!("http://localhost:{}/cdn/*", upstream_port)],
        )],
        upstream_port,
    )
    .report(&t)
    .start()
    .await;

    let client = plain_client_no_follow(&t, proxy.addr());
    let r = client
        .get(&format!("http://localhost:{}/origin", upstream_port))
        .await;
    t.assert_eq("origin 302", &r.status().as_u16(), &302u16);

    let r2 = client
        .get(&format!("http://localhost:{}/cdn/file", upstream_port))
        .await;
    t.assert_eq(
        "relative target allowed 200",
        &r2.status().as_u16(),
        &200u16,
    );
    t.assert_eq("body", &r2.text().await.unwrap().as_str(), &"relative-ok");

    proxy.shutdown();
}

/// Audit log records `redirect_whitelisted` reason for the follow-up request.
#[tokio::test]
async fn test_audit_log_records_redirect_whitelisted_reason() {
    let t = test_report!(
        "Audit log has reason=redirect_whitelisted for follow-up request allowed by whitelist"
    );

    let ca = TestCa::generate();

    let cdn = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/file"))
        .respond_with(ResponseTemplate::new(200).set_body_string("payload"))
        .mount(&cdn)
        .await;
    let cdn_port = cdn.address().port();

    let origin = MockServer::start().await;
    let location = format!("http://localhost:{}/file", cdn_port);
    Mock::given(method("GET"))
        .and(wm_path("/origin"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", location.as_str()))
        .mount(&origin)
        .await;
    let origin_port = origin.address().port();

    let tmp = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap().to_string();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_redirects(
            "GET",
            &format!("http://localhost:{}/*", origin_port),
            &["*"],
        )],
        origin_port,
    )
    .audit_log(&audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = plain_client_no_follow(&t, proxy.addr());
    let r = client
        .get(&format!("http://localhost:{}/origin", origin_port))
        .await;
    t.assert_eq("origin 302", &r.status().as_u16(), &302u16);

    let r2 = client.get(&location).await;
    t.assert_eq("CDN 200", &r2.status().as_u16(), &200u16);

    // Give the audit logger a moment to flush to disk.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    let lines: Vec<&str> = audit.lines().collect();
    t.assert_true("at least 2 audit entries", lines.len() >= 2);

    let origin_entry = lines
        .iter()
        .find(|l| l.contains("/origin"))
        .expect("origin audit entry");
    t.assert_contains(
        "origin reason=rule_matched",
        origin_entry,
        "\"reason\":\"rule_matched\"",
    );

    let cdn_entry = lines
        .iter()
        .find(|l| l.contains("/file"))
        .expect("cdn audit entry");
    t.assert_contains(
        "cdn reason=redirect_whitelisted",
        cdn_entry,
        "\"reason\":\"redirect_whitelisted\"",
    );

    proxy.shutdown();
}

/// HTTPS (MITM CONNECT tunnel) end-to-end: the tunnel handler intercepts a 3xx
/// response, resolves the `Location` (relative in this test, since the test
/// upstream serves a cert for a single hostname), whitelists the target, and
/// lets the follow-up request through despite no rule matching it directly.
///
/// Uses a relative `Location` to keep the upstream cert scope to one hostname.
/// The cross-host HTTPS case would require a multi-SAN test cert, but the
/// shared `maybe_whitelist_redirect` helper is already exercised by the plain
/// HTTP cross-host tests above, so this test's job is to prove the MITM tunnel
/// path plumbs the helper correctly.
#[tokio::test]
async fn test_https_mitm_redirect_whitelisted() {
    let t = test_report!("HTTPS MITM: 3xx whitelist + follow-up allowed");

    let ca = TestCa::generate();

    // Single upstream serving two paths: /origin returns 302 → /cdn/file,
    // /cdn/file returns 200.
    let handler: common::UpstreamHandler = Arc::new(|req: Request<Incoming>| {
        Box::pin(async move {
            let resp = match req.uri().path() {
                "/origin" => Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", "/cdn/file")
                    .body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
                    .unwrap(),
                "/cdn/file" => Response::builder()
                    .status(StatusCode::OK)
                    .body(
                        Full::new(Bytes::from_static(b"https-payload"))
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .unwrap(),
                _ => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
                    .unwrap(),
            };
            Ok::<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>(resp)
        })
    });

    let upstream = TestUpstream::builder(&ca, handler)
        .report(&t, "serves /origin (302) and /cdn/file (200)")
        .start()
        .await;

    // Rule allows /origin and permits redirects to /cdn/* on the same host.
    // /cdn/file itself is NOT directly matched by any rule — only reachable
    // through the whitelist.
    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_redirects(
            "GET",
            "https://localhost/origin",
            &["https://localhost/cdn/*"],
        )],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    // reqwest with redirect=none so the follow-up goes through the proxy explicitly.
    let ca_cert = reqwest::tls::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap();
    let proxy_url = format!("http://{}", proxy.addr());
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
        .add_root_certificate(ca_cert)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Sanity: without triggering the origin first, /cdn/file is blocked (no matching rule).
    t.action("GET https://localhost/cdn/file directly (expect 451)".to_string());
    let pre = client
        .get("https://localhost/cdn/file")
        .send()
        .await
        .unwrap();
    t.assert_eq("pre-redirect cdn blocked", &pre.status().as_u16(), &451u16);

    // Trigger the origin (rule-matched) to insert whitelist entry.
    t.action("GET https://localhost/origin (rule-matched, returns 302)".to_string());
    let r1 = client.get("https://localhost/origin").send().await.unwrap();
    t.assert_eq("origin 302", &r1.status().as_u16(), &302u16);
    t.assert_eq(
        "Location header",
        &r1.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        &"/cdn/file",
    );

    // Follow-up to /cdn/file should now be allowed via the whitelist.
    t.action("GET https://localhost/cdn/file (post-redirect, expect 200)".to_string());
    let r2 = client
        .get("https://localhost/cdn/file")
        .send()
        .await
        .unwrap();
    t.assert_eq("cdn follow-up allowed", &r2.status().as_u16(), &200u16);
    t.assert_eq(
        "cdn body",
        &r2.text().await.unwrap().as_str(),
        &"https-payload",
    );

    upstream.shutdown();
    proxy.shutdown();
}
