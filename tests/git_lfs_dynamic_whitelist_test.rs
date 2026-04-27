//! Tests for dynamic whitelisting of LFS action URLs from batch responses.
//!
//! After a successful POST to `{repo}/info/lfs/objects/batch`, the proxy parses
//! the response and inserts each `objects[*].actions.{download,upload,verify}.href`
//! into a short-lived dynamic whitelist pinned to the action's HTTP method.
//! These tests verify the activation, scoping, method-pinning, and TTL behavior.
//!
//! Test setup uses a single TestUpstream that dispatches by request path:
//! - `POST /org/repo/info/lfs/objects/batch` → returns a crafted LFS batch
//!   response advertising action URLs at otherwise-unallowed paths
//!   (e.g. `/external/lfs/objects/abc/verify`).
//! - The follow-up call to that path either succeeds (proving whitelisting)
//!   or fails (proving method/scope/TTL constraints).

mod common;

use bytes::Bytes;
use common::{git_rule, TestCa, TestProxy, TestUpstream, UpstreamHandler};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;

/// Build a JSON LFS batch response advertising the given actions, all with
/// hrefs pointing back to the same test upstream (different host = different
/// URL pattern from the proxy's perspective). Hostname is the SNI the proxy
/// will present to the upstream; with `upstream_host_override` the actual TCP
/// connection is to the test upstream regardless.
fn batch_response_body(actions_json: &str) -> String {
    format!(
        r#"{{"transfer":"basic","objects":[{{"oid":"abc","size":42,"actions":{}}}]}}"#,
        actions_json
    )
}

/// Build an upstream handler that:
///  - On `POST /org/repo/info/lfs/objects/batch`, returns the supplied batch JSON.
///  - On any other path, returns 200 with body indicating which path was hit.
fn batch_then_action_handler(batch_body: String) -> UpstreamHandler {
    let batch = Arc::new(batch_body);
    Arc::new(move |req: Request<Incoming>| {
        let batch = Arc::clone(&batch);
        Box::pin(async move {
            let path = req.uri().path().to_string();
            let method = req.method().clone();
            let body_bytes =
                if method == hyper::Method::POST && path.ends_with("/info/lfs/objects/batch") {
                    Bytes::from((*batch).clone())
                } else {
                    Bytes::from(format!("ACTION-OK {} {}", method, path))
                };
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .body(Full::new(body_bytes).map_err(|e| match e {}).boxed())
                .unwrap())
        })
    })
}

/// Send a POST to the LFS batch endpoint with operation=upload to prime the
/// whitelist. Returns the response body (string) for assertions.
async fn prime_batch(
    client: &reqwest::Client,
    proxy_addr: std::net::SocketAddr,
    batch_url: &str,
    op: &str,
) -> reqwest::Response {
    let _ = proxy_addr; // already encoded into the client by ReportingClient
    client
        .post(batch_url)
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(format!(
            r#"{{"operation":"{}","transfers":["basic"],"objects":[{{"oid":"abc","size":42}}]}}"#,
            op
        ))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_verify_url_dynamically_whitelisted_after_batch() {
    let t = test_report!("After batch response advertises a verify URL, POST to that URL succeeds");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let actions = r#"{
        "upload": {"href": "https://localhost/external/lfs/objects/abc/upload"},
        "verify": {"href": "https://localhost/external/lfs/objects/abc/verify"}
    }"#;
    let upstream =
        TestUpstream::builder(&ca, batch_then_action_handler(batch_response_body(actions)))
            .report(&t, "LFS upstream (batch + action handler)")
            .start()
            .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = common::ReportingClient::new(&t, proxy.addr(), &ca);

    // Step 1: prime the whitelist with a batch upload request.
    let batch_resp = prime_batch(
        client.inner(),
        proxy.addr(),
        "https://localhost/org/repo/info/lfs/objects/batch",
        "upload",
    )
    .await;
    t.action("POST LFS batch (operation=upload)");
    t.assert_eq("batch status 200", &batch_resp.status().as_u16(), &200u16);
    let batch_text = batch_resp.text().await.unwrap();
    t.assert_true("batch returned actions JSON", batch_text.contains("verify"));

    // Step 2: POST to the verify URL — not covered by any static rule but should
    // be allowed via the dynamic whitelist.
    let verify_resp = client
        .inner()
        .post("https://localhost/external/lfs/objects/abc/verify")
        .body("{}")
        .send()
        .await
        .unwrap();
    t.action("POST verify URL (should be dynamically whitelisted)");
    t.assert_eq("verify status 200", &verify_resp.status().as_u16(), &200u16);

    // Step 3: PUT to the upload URL should also succeed.
    let upload_resp = client
        .inner()
        .put("https://localhost/external/lfs/objects/abc/upload")
        .body("object-bytes")
        .send()
        .await
        .unwrap();
    t.action("PUT upload URL (should be dynamically whitelisted)");
    t.assert_eq("upload status 200", &upload_resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_method_pinning_blocks_wrong_method() {
    let t = test_report!("Whitelisted upload URL rejects GET (method-pinned to PUT)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let actions = r#"{
        "upload": {"href": "https://localhost/external/lfs/objects/abc/upload"}
    }"#;
    let upstream =
        TestUpstream::builder(&ca, batch_then_action_handler(batch_response_body(actions)))
            .report(&t, "LFS upstream")
            .start()
            .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = common::ReportingClient::new(&t, proxy.addr(), &ca);

    let _ = prime_batch(
        client.inner(),
        proxy.addr(),
        "https://localhost/org/repo/info/lfs/objects/batch",
        "upload",
    )
    .await;
    t.action("Primed whitelist via batch upload");

    // PUT (correct method) succeeds.
    let put_resp = client
        .inner()
        .put("https://localhost/external/lfs/objects/abc/upload")
        .body("data")
        .send()
        .await
        .unwrap();
    t.assert_eq(
        "PUT (correct method) 200",
        &put_resp.status().as_u16(),
        &200u16,
    );

    // GET to the same URL is blocked — not whitelisted for GET, no static rule covers it.
    let get_resp = client
        .inner()
        .get("https://localhost/external/lfs/objects/abc/upload")
        .send()
        .await
        .unwrap();
    t.action("GET to whitelisted PUT URL (should be blocked)");
    t.assert_eq(
        "GET 451 (method-pinned)",
        &get_resp.status().as_u16(),
        &451u16,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_fetch_rule_does_not_whitelist_upload_actions() {
    let t =
        test_report!("Fetch-only rule sees only download actions; upload/verify URLs stay blocked");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    // Server is misbehaving / overly chatty: returns upload+verify even though
    // we requested download. Our scope filter (lfs_operations on the matched
    // rule) should reject those — only `download` is in scope.
    let actions = r#"{
        "download": {"href": "https://localhost/external/lfs/objects/abc/download"},
        "upload":   {"href": "https://localhost/external/lfs/objects/abc/upload"},
        "verify":   {"href": "https://localhost/external/lfs/objects/abc/verify"}
    }"#;
    let upstream =
        TestUpstream::builder(&ca, batch_then_action_handler(batch_response_body(actions)))
            .report(&t, "LFS upstream")
            .start()
            .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = common::ReportingClient::new(&t, proxy.addr(), &ca);

    let _ = prime_batch(
        client.inner(),
        proxy.addr(),
        "https://localhost/org/repo/info/lfs/objects/batch",
        "download",
    )
    .await;
    t.action("Primed whitelist via batch download");

    // GET download URL is allowed (in scope of fetch).
    let download_resp = client
        .inner()
        .get("https://localhost/external/lfs/objects/abc/download")
        .send()
        .await
        .unwrap();
    t.assert_eq(
        "GET download 200",
        &download_resp.status().as_u16(),
        &200u16,
    );

    // PUT upload URL is blocked (not in scope of fetch).
    let upload_resp = client
        .inner()
        .put("https://localhost/external/lfs/objects/abc/upload")
        .body("x")
        .send()
        .await
        .unwrap();
    t.assert_eq(
        "PUT upload 451 (out of fetch scope)",
        &upload_resp.status().as_u16(),
        &451u16,
    );

    // POST verify URL is blocked (also not in scope of fetch).
    let verify_resp = client
        .inner()
        .post("https://localhost/external/lfs/objects/abc/verify")
        .body("{}")
        .send()
        .await
        .unwrap();
    t.assert_eq(
        "POST verify 451 (out of fetch scope)",
        &verify_resp.status().as_u16(),
        &451u16,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_no_priming_means_action_url_blocked() {
    let t = test_report!(
        "Without a preceding batch response, the action URL is blocked (no whitelist entry)"
    );
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::builder(&ca, batch_then_action_handler(batch_response_body("{}")))
        .report(&t, "LFS upstream")
        .start()
        .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = common::ReportingClient::new(&t, proxy.addr(), &ca);

    // No batch call — straight to verify URL. Must be blocked since no rule
    // matches and no whitelist entry exists.
    let resp = client
        .inner()
        .post("https://localhost/external/lfs/objects/abc/verify")
        .body("{}")
        .send()
        .await
        .unwrap();
    t.action("POST verify URL without priming");
    t.assert_eq("blocked 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_malformed_batch_response_does_not_panic() {
    let t = test_report!("Malformed JSON in batch response is forwarded; nothing whitelisted");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    // Handler returns garbage on batch endpoint.
    let upstream = TestUpstream::builder(
        &ca,
        Arc::new(|req: Request<Incoming>| {
            Box::pin(async move {
                let body = if req.uri().path().ends_with("/info/lfs/objects/batch") {
                    "this is not json"
                } else {
                    "ACTION-OK"
                };
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                    .unwrap())
            })
        }),
    )
    .report(&t, "LFS upstream (returns garbage)")
    .start()
    .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", "https://localhost/org/repo")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = common::ReportingClient::new(&t, proxy.addr(), &ca);

    let batch_resp = prime_batch(
        client.inner(),
        proxy.addr(),
        "https://localhost/org/repo/info/lfs/objects/batch",
        "upload",
    )
    .await;
    t.assert_eq(
        "batch forwarded successfully despite garbage body",
        &batch_resp.status().as_u16(),
        &200u16,
    );
    let body = batch_resp.text().await.unwrap();
    t.assert_eq(
        "body passed through unchanged",
        &body.as_str(),
        &"this is not json",
    );

    // Subsequent action URL must still be blocked — nothing was whitelisted.
    let resp = client
        .inner()
        .post("https://localhost/external/lfs/objects/abc/verify")
        .send()
        .await
        .unwrap();
    t.assert_eq("verify blocked", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_short_ttl_lets_entry_expire() {
    let t = test_report!("After redirect_whitelist_ttl_secs elapses, action URL is blocked again");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    // Use no expires_at/expires_in — falls back to config TTL.
    // We set redirect_whitelist_ttl_secs=1; clamping in lfs_response only
    // applies when the response provides its own expiration, so the config
    // default (1s) governs here.
    let actions = r#"{
        "verify": {"href": "https://localhost/external/lfs/objects/abc/verify"}
    }"#;
    let upstream =
        TestUpstream::builder(&ca, batch_then_action_handler(batch_response_body(actions)))
            .report(&t, "LFS upstream")
            .start()
            .await;

    let proxy = TestProxy::builder(
        &ca,
        vec![git_rule("push", "https://localhost/org/repo")],
        upstream.port(),
    )
    .redirect_whitelist_ttl_secs(1)
    .report(&t)
    .start()
    .await;

    let client = common::ReportingClient::new(&t, proxy.addr(), &ca);

    let _ = prime_batch(
        client.inner(),
        proxy.addr(),
        "https://localhost/org/repo/info/lfs/objects/batch",
        "upload",
    )
    .await;
    t.action("Primed whitelist (TTL=1s)");

    // Immediate POST is allowed.
    let immediate = client
        .inner()
        .post("https://localhost/external/lfs/objects/abc/verify")
        .send()
        .await
        .unwrap();
    t.assert_eq("immediate POST 200", &immediate.status().as_u16(), &200u16);

    // Wait for entry to expire.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let later = client
        .inner()
        .post("https://localhost/external/lfs/objects/abc/verify")
        .send()
        .await
        .unwrap();
    t.action("Wait > TTL then retry");
    t.assert_eq("expired POST 451", &later.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}
