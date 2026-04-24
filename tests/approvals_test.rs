mod common;

use common::{ok_handler, ReportingClient, TestCa, TestProxy, TestUpstream};

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

/// When `[approvals]` is configured, the agent API endpoint is reachable
/// and returns 501 (Phase 1 stub — real handlers land in Phase 2).
#[tokio::test]
async fn test_agent_api_501_when_feature_enabled() {
    let t = test_report!("Agent API returns 501 when approvals feature is enabled (Phase 1 stub)");

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

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://pyloros.internal/approvals").await;

    t.assert_eq("Status", &resp.status().as_u16(), &501u16);

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
