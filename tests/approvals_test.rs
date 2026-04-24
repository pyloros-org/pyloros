mod common;

use common::{ok_handler, ReportingClient, TestCa, TestProxy, TestUpstream};
use pyloros::approvals::{ApprovalStatus, Lifetime};
use serde_json::json;

/// Test-only: start a proxy with approvals enabled and return both its
/// address and an `Arc<ApprovalManager>` handle so tests can poke at
/// internal state (resolve_for_test, list_pending, etc.).
async fn start_proxy_with_approvals(
    t: &common::TestReport,
    ca: &TestCa,
    upstream_port: u16,
) -> (TestProxy, tempfile::NamedTempFile) {
    let sidecar = tempfile::NamedTempFile::new().unwrap();
    let sidecar_path = sidecar.path().to_string_lossy().into_owned();
    let proxy = TestProxy::builder(ca, vec![], upstream_port)
        .with_approvals(&sidecar_path)
        .report(t)
        .start()
        .await;
    (proxy, sidecar)
}

/// When the `[approvals]` section is absent from config, requests to
/// `https://pyloros.internal/...` through the proxy return 404. The feature
/// is opt-in; we don't want agents to tell the difference between "disabled"
/// and "endpoint doesn't exist".
#[tokio::test]
async fn test_agent_api_404_when_feature_disabled() {
    let t = test_report!("Agent API returns 404 when approvals feature is disabled");

    let ca = TestCa::generate();
    // Need an upstream only to satisfy the TestProxy builder; not actually hit.
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;

    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .report(&t)
        .start()
        .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://pyloros.internal/approvals").await;

    t.assert_eq("Status", &resp.status().as_u16(), &404u16);

    proxy.shutdown();
    upstream.shutdown();
}

/// GET on an unknown approval id returns 404 (Phase 2 behavior).
#[tokio::test]
async fn test_agent_api_unknown_id_returns_404() {
    let t = test_report!("GET of unknown approval id returns 404");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .get("https://pyloros.internal/approvals/apr_does_not_exist")
        .await;

    t.assert_eq("Status", &resp.status().as_u16(), &404u16);

    proxy.shutdown();
    upstream.shutdown();
}

/// The dashboard listener is bound to a separate port when approvals are
/// enabled. Its Phase 1 stub returns 501 for any request.
#[tokio::test]
async fn test_dashboard_listener_bound_and_returns_501() {
    let t = test_report!("Dashboard listener is bound and returns 501 (Phase 1 stub)");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;

    let sidecar = tempfile::NamedTempFile::new().unwrap();
    let sidecar_path = sidecar.path().to_string_lossy().into_owned();

    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .with_approvals(&sidecar_path)
        .report(&t)
        .start()
        .await;

    let dashboard_addr = proxy
        .dashboard_addr
        .expect("dashboard addr should be bound");

    // Plain HTTP client, no proxy — the dashboard is a direct endpoint.
    let client = reqwest::Client::builder().build().unwrap();
    let resp = client
        .get(format!("http://{}/", dashboard_addr))
        .send()
        .await
        .unwrap();
    t.assert_eq("Status", &resp.status().as_u16(), &501u16);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Phase 2: agent API end-to-end (POST + long-poll GET, resolved via
// ApprovalManager::resolve_for_test). Rule merging (Phase 4) and dashboard
// decisions (Phase 3) not yet wired.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_post_approve_roundtrip_via_resolve_for_test() {
    let t = test_report!("POST approval, resolve_for_test(approved), long-poll returns approved");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;
    let manager = proxy.approvals.clone().expect("approvals enabled");

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let post_body = json!({
        "rules": ["GET https://api.foo.com/*"],
        "reason": "need weather data"
    })
    .to_string();
    let resp = client
        .post_with_body("https://pyloros.internal/approvals", post_body)
        .await;
    t.assert_eq("POST status", &resp.status().as_u16(), &202u16);
    let submitted: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    let id = submitted["id"].as_str().expect("id present").to_string();

    // Resolve out-of-band (as the dashboard will in Phase 3).
    let rules = vec!["GET https://api.foo.com/*".to_string()];
    manager
        .resolve(
            &id,
            ApprovalStatus::Approved {
                rules_applied: rules.clone(),
                ttl: Lifetime::Session,
            },
        )
        .expect("resolve succeeds");

    let resp = client
        .get(&format!(
            "https://pyloros.internal/approvals/{}?wait=5s",
            id
        ))
        .await;
    t.assert_eq("GET status", &resp.status().as_u16(), &200u16);
    let got: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    t.assert_eq("status", &got["status"].as_str().unwrap(), &"approved");
    t.assert_eq(
        "rules_applied",
        &got["rules_applied"][0].as_str().unwrap(),
        &"GET https://api.foo.com/*",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_post_deny_with_message_returned() {
    let t = test_report!("POST approval, deny with message, long-poll returns message");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;
    let manager = proxy.approvals.clone().expect("approvals enabled");

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .post_with_body(
            "https://pyloros.internal/approvals",
            json!({"rules": ["GET https://api.foo.com/*"]}).to_string(),
        )
        .await;
    let id = serde_json::from_str::<serde_json::Value>(&resp.text().await.unwrap()).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    manager
        .resolve(
            &id,
            ApprovalStatus::Denied {
                message: Some("rule too broad, scope to /v1/weather".to_string()),
            },
        )
        .unwrap();

    let resp = client
        .get(&format!(
            "https://pyloros.internal/approvals/{}?wait=5s",
            id
        ))
        .await;
    let got: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    t.assert_eq("status", &got["status"].as_str().unwrap(), &"denied");
    t.assert_eq(
        "message",
        &got["message"].as_str().unwrap(),
        &"rule too broad, scope to /v1/weather",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_long_poll_wakes_on_resolution() {
    let t = test_report!("Long-poll GET blocks until resolve_for_test fires");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;
    let manager = proxy.approvals.clone().expect("approvals enabled");

    // POST first.
    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let id = client
        .post_with_body(
            "https://pyloros.internal/approvals",
            json!({"rules": ["GET https://x/*"]}).to_string(),
        )
        .await
        .text()
        .await
        .map(|s| serde_json::from_str::<serde_json::Value>(&s).unwrap())
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Resolve after a small delay. Must happen concurrently with the poll.
    let manager_clone = manager.clone();
    let id_for_resolver = id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        manager_clone
            .resolve(
                &id_for_resolver,
                ApprovalStatus::Approved {
                    rules_applied: vec!["GET https://x/*".to_string()],
                    ttl: Lifetime::Session,
                },
            )
            .unwrap();
    });

    let start = std::time::Instant::now();
    let resp = client
        .get(&format!(
            "https://pyloros.internal/approvals/{}?wait=5s",
            id
        ))
        .await;
    let elapsed = start.elapsed();
    t.assert_eq("GET status", &resp.status().as_u16(), &200u16);
    let got: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    t.assert_eq("status", &got["status"].as_str().unwrap(), &"approved");
    // The wake should have arrived well before the 5s cap.
    t.assert_true(
        "woke before wait cap",
        elapsed < std::time::Duration::from_secs(2),
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_long_poll_times_out_returns_pending() {
    let t = test_report!("Long-poll with short wait returns pending if no decision");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let id = client
        .post_with_body(
            "https://pyloros.internal/approvals",
            json!({"rules": ["GET https://x/*"]}).to_string(),
        )
        .await
        .text()
        .await
        .map(|s| serde_json::from_str::<serde_json::Value>(&s).unwrap())
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = client
        .get(&format!(
            "https://pyloros.internal/approvals/{}?wait=500ms",
            id
        ))
        .await;
    t.assert_eq("status code", &resp.status().as_u16(), &200u16);
    let got: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    t.assert_eq("status", &got["status"].as_str().unwrap(), &"pending");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_post_rejects_empty_rules() {
    let t = test_report!("POST with empty rules returns 400");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .post_with_body(
            "https://pyloros.internal/approvals",
            json!({"rules": []}).to_string(),
        )
        .await;
    t.assert_eq("status", &resp.status().as_u16(), &400u16);

    proxy.shutdown();
    upstream.shutdown();
}
