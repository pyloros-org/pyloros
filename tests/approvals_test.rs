mod common;

use common::{ok_handler, ReportingClient, TestCa, TestProxy, TestUpstream};
use pyloros::approvals::{ApprovalStatus, Lifetime};
use pyloros::config::Rule;
use serde_json::json;

/// Build a method Rule for tests. Mirrors the JSON shape the API now accepts.
fn method_rule(method: &str, url: &str) -> Rule {
    Rule {
        method: Some(method.to_string()),
        url: url.to_string(),
        websocket: false,
        git: None,
        branches: None,
        allow_redirects: Vec::new(),
        log_body: false,
    }
}

/// JSON form of `method_rule` for use inside `json!(...)` POST bodies.
fn method_rule_json(method: &str, url: &str) -> serde_json::Value {
    json!({"method": method, "url": url})
}

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
        "rules": [method_rule_json("GET", "https://api.foo.com/*")],
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
    let rules = vec![method_rule("GET", "https://api.foo.com/*")];
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
        "rules_applied[0].method",
        &got["rules_applied"][0]["method"].as_str().unwrap(),
        &"GET",
    );
    t.assert_eq(
        "rules_applied[0].url",
        &got["rules_applied"][0]["url"].as_str().unwrap(),
        &"https://api.foo.com/*",
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
            json!({"rules": [method_rule_json("GET", "https://api.foo.com/*")]}).to_string(),
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
            json!({"rules": [method_rule_json("GET", "https://x/*")]}).to_string(),
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
                    rules_applied: vec![method_rule("GET", "https://x/*")],
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
            json!({"rules": [method_rule_json("GET", "https://x/*")]}).to_string(),
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

// ---------------------------------------------------------------------------
// Phase 3: dashboard + SSE + decision endpoint.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dashboard_get_root_returns_html() {
    let t = test_report!("Dashboard GET / returns HTML");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;
    let dashboard_addr = proxy.dashboard_addr.unwrap();

    let client = reqwest::Client::builder().build().unwrap();
    let resp = client
        .get(format!("http://{}/", dashboard_addr))
        .send()
        .await
        .unwrap();
    t.assert_eq("Status", &resp.status().as_u16(), &200u16);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    t.assert_contains("content-type is html", ct.as_str(), "text/html");
    let body = resp.text().await.unwrap();
    t.assert_contains("doctype present", body.as_str(), "<!doctype html>");
    t.assert_contains("script present", body.as_str(), "EventSource");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_dashboard_decision_approves_and_wakes_long_poll() {
    let t = test_report!("Dashboard POST /approvals/{id}/decision resolves a pending approval");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;
    let dashboard_addr = proxy.dashboard_addr.unwrap();

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let id = serde_json::from_str::<serde_json::Value>(
        &client
            .post_with_body(
                "https://pyloros.internal/approvals",
                json!({"rules": [method_rule_json("GET", "https://api.foo.com/*")]}).to_string(),
            )
            .await
            .text()
            .await
            .unwrap(),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Post a decision over the dashboard listener. Concurrently, long-poll
    // for the result.
    let poll_url = format!("https://pyloros.internal/approvals/{}?wait=5s", id);
    let poll_fut = client.get(&poll_url);

    let dashboard = reqwest::Client::builder().build().unwrap();
    let id_for_dash = id.clone();
    let dash_fut = async move {
        // Tiny delay so the long-poll has actually subscribed.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        dashboard
            .post(format!(
                "http://{}/approvals/{}/decision",
                dashboard_addr, id_for_dash
            ))
            .header("Content-Type", "application/json")
            .body(json!({"action": "approve", "ttl": "one_hour"}).to_string())
            .send()
            .await
            .unwrap()
    };

    let (poll_resp, dash_resp) = tokio::join!(poll_fut, dash_fut);

    t.assert_eq(
        "Dashboard decision status",
        &dash_resp.status().as_u16(),
        &204u16,
    );
    t.assert_eq("Long-poll status", &poll_resp.status().as_u16(), &200u16);
    let got: serde_json::Value = serde_json::from_str(&poll_resp.text().await.unwrap()).unwrap();
    t.assert_eq("status", &got["status"].as_str().unwrap(), &"approved");
    t.assert_eq("ttl", &got["ttl"].as_str().unwrap(), &"one_hour");
    t.assert_eq(
        "rules_applied defaulted to proposed (method)",
        &got["rules_applied"][0]["method"].as_str().unwrap(),
        &"GET",
    );
    t.assert_eq(
        "rules_applied defaulted to proposed (url)",
        &got["rules_applied"][0]["url"].as_str().unwrap(),
        &"https://api.foo.com/*",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_dashboard_sse_streams_pending_and_resolved() {
    let t = test_report!("Dashboard /events streams snapshot, pending, and resolved events");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;
    let dashboard_addr = proxy.dashboard_addr.unwrap();
    let manager = proxy.approvals.clone().unwrap();

    // Open the SSE stream and read frames in a background task.
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<String>(32);
    let url = format!("http://{}/events", dashboard_addr);
    tokio::spawn(async move {
        let client = reqwest::Client::builder().build().unwrap();
        let mut resp = client.get(&url).send().await.unwrap();
        while let Some(chunk) = resp.chunk().await.unwrap() {
            let s = String::from_utf8_lossy(&chunk).to_string();
            for line in s.split("\n\n") {
                if let Some(rest) = line.strip_prefix("data: ") {
                    if ev_tx.send(rest.to_string()).await.is_err() {
                        return;
                    }
                }
            }
        }
    });

    // First frame should be a snapshot (initially empty).
    let snap = tokio::time::timeout(std::time::Duration::from_secs(2), ev_rx.recv())
        .await
        .unwrap()
        .unwrap();
    t.assert_contains("snapshot event", snap.as_str(), "\"snapshot\"");

    // Post a new approval; a Pending event must arrive on the stream.
    let req = manager
        .post(
            vec![method_rule("GET", "https://api.foo.com/*")],
            Some("because".to_string()),
            None,
            None,
        )
        .unwrap();
    let id = req.id.clone();

    let pending = tokio::time::timeout(std::time::Duration::from_secs(2), ev_rx.recv())
        .await
        .unwrap()
        .unwrap();
    t.assert_contains("pending event", pending.as_str(), "\"pending\"");
    t.assert_contains("approval id", pending.as_str(), id.as_str());

    // Resolve; a Resolved event must arrive.
    manager
        .resolve(
            &id,
            ApprovalStatus::Approved {
                rules_applied: vec![method_rule("GET", "https://api.foo.com/*")],
                ttl: Lifetime::Session,
            },
        )
        .unwrap();
    let resolved = tokio::time::timeout(std::time::Duration::from_secs(2), ev_rx.recv())
        .await
        .unwrap()
        .unwrap();
    t.assert_contains("resolved event", resolved.as_str(), "\"resolved\"");
    t.assert_contains("same id", resolved.as_str(), id.as_str());

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_dashboard_decision_with_custom_rules_and_message() {
    let t = test_report!("Dashboard decision may edit rules_applied and include deny message");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;
    let dashboard_addr = proxy.dashboard_addr.unwrap();
    let manager = proxy.approvals.clone().unwrap();

    let req = manager
        .post(
            vec![method_rule("GET", "https://broad/*")],
            None,
            None,
            None,
        )
        .unwrap();

    let dashboard = reqwest::Client::builder().build().unwrap();
    // Deny with a message.
    let resp = dashboard
        .post(format!(
            "http://{}/approvals/{}/decision",
            dashboard_addr, req.id
        ))
        .header("Content-Type", "application/json")
        .body(json!({"action": "deny", "message": "too broad"}).to_string())
        .send()
        .await
        .unwrap();
    t.assert_eq("Decision status", &resp.status().as_u16(), &204u16);

    let got = manager
        .get(&req.id, std::time::Duration::from_secs(1))
        .await
        .unwrap();
    match got.status {
        ApprovalStatus::Denied { message } => {
            t.assert_eq("message", &message.unwrap().as_str(), &"too broad");
        }
        other => panic!("expected denied, got {:?}", other),
    }

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Phase 4: approved rules take effect on live traffic.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_approved_session_rule_unblocks_traffic() {
    let t = test_report!("After approving, a previously blocked URL is allowed");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello from upstream"))
        .report(&t, "returns 'hello from upstream'")
        .start()
        .await;
    // Proxy with NO base rules — everything is blocked until approved.
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // 1. Before approval, request is blocked (451).
    let resp = client.get("https://localhost/hello").await;
    t.assert_eq("pre-approval status", &resp.status().as_u16(), &451u16);

    // 2. Post an approval and resolve it out-of-band.
    let manager = proxy.approvals.clone().unwrap();
    let req = manager
        .post(
            vec![method_rule("GET", "https://localhost/*")],
            None,
            None,
            None,
        )
        .unwrap();
    manager
        .resolve(
            &req.id,
            ApprovalStatus::Approved {
                rules_applied: vec![method_rule("GET", "https://localhost/*")],
                ttl: Lifetime::Session,
            },
        )
        .unwrap();

    // Give the rebuild signal a moment to propagate through the watch channel.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 3. The same request now succeeds — must use a fresh client because
    // reqwest pools CONNECT tunnels and an existing tunnel is tied to the
    // old FilterEngine (same pattern as config-reload tests).
    let client2 = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client2.get("https://localhost/hello").await;
    t.assert_eq("post-approval status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("body", &body.as_str(), &"hello from upstream");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_approve_invalid_rule_rejected() {
    let t = test_report!("Approving with an inconsistent Rule (no method, no git) fails cleanly");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;
    let manager = proxy.approvals.clone().unwrap();

    // Post a valid rule first so we have a pending approval to resolve.
    let req = manager
        .post(
            vec![method_rule("GET", "https://api.foo.com/*")],
            None,
            None,
            None,
        )
        .unwrap();

    // Construct an invalid rule: neither `method` nor `git` set —
    // Rule::validate rejects this.
    let invalid = Rule {
        method: None,
        url: "https://api.foo.com/*".to_string(),
        websocket: false,
        git: None,
        branches: None,
        allow_redirects: Vec::new(),
        log_body: false,
    };

    let err = manager
        .resolve(
            &req.id,
            ApprovalStatus::Approved {
                rules_applied: vec![invalid],
                ttl: Lifetime::Session,
            },
        )
        .unwrap_err();
    t.assert_contains(
        "InvalidRule error",
        err.to_string().as_str(),
        "invalid rule",
    );

    // The approval remains pending (not consumed by the failed resolve).
    let snap = manager.snapshot_pending(&req.id);
    t.assert_true("still pending after invalid resolve", snap.is_some());

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Phase 5: TTL + sidecar persistence.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_permanent_approval_writes_sidecar_and_persists_across_restart() {
    let t = test_report!("Permanent approval writes sidecar and a new proxy loads it on startup");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello from upstream"))
        .report(&t, "returns 'hello from upstream'")
        .start()
        .await;

    // Pick an explicit sidecar path so we can restart against the same file.
    let dir = tempfile::tempdir().unwrap();
    let sidecar_path = dir
        .path()
        .join("approvals.toml")
        .to_string_lossy()
        .into_owned();

    // Proxy #1 — approve with permanent lifetime; sidecar should be written.
    let proxy1 = TestProxy::builder(&ca, vec![], upstream.port())
        .with_approvals(&sidecar_path)
        .report(&t)
        .start()
        .await;
    let manager = proxy1.approvals.clone().unwrap();
    let req = manager
        .post(
            vec![method_rule("GET", "https://localhost/*")],
            None,
            None,
            None,
        )
        .unwrap();
    manager
        .resolve(
            &req.id,
            ApprovalStatus::Approved {
                rules_applied: vec![method_rule("GET", "https://localhost/*")],
                ttl: Lifetime::Permanent,
            },
        )
        .unwrap();
    t.assert_true(
        "sidecar file exists",
        std::path::Path::new(&sidecar_path).exists(),
    );
    let sidecar_contents = std::fs::read_to_string(&sidecar_path).unwrap();
    t.assert_contains(
        "sidecar has url",
        sidecar_contents.as_str(),
        "https://localhost/*",
    );
    proxy1.shutdown();
    // Drain the connection pool — otherwise a cached tunnel from proxy1
    // may race the proxy2 startup.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Proxy #2 — start a fresh proxy pointing at the same sidecar.
    // Its base rules are empty; the rule should be loaded from disk and
    // the request should succeed immediately.
    let proxy2 = TestProxy::builder(&ca, vec![], upstream.port())
        .with_approvals(&sidecar_path)
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy2.addr(), &ca);
    let resp = client.get("https://localhost/hello").await;
    t.assert_eq("after restart: status", &resp.status().as_u16(), &200u16);

    proxy2.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_revoke_removes_active_rule() {
    let t = test_report!("revoke_approval removes active rules and triggers rebuild");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;
    let manager = proxy.approvals.clone().unwrap();

    let req = manager
        .post(
            vec![method_rule("GET", "https://localhost/*")],
            None,
            None,
            None,
        )
        .unwrap();
    manager
        .resolve(
            &req.id,
            ApprovalStatus::Approved {
                rules_applied: vec![method_rule("GET", "https://localhost/*")],
                ttl: Lifetime::Session,
            },
        )
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Rule is active.
    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/x").await;
    t.assert_eq("after approve", &resp.status().as_u16(), &200u16);

    // Revoke.
    manager.revoke_approval(&req.id);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Rule is gone — fresh client because the old tunnel is sticky.
    let client2 = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client2.get("https://localhost/x").await;
    t.assert_eq("after revoke", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_permanent_revoke_rewrites_sidecar_empty() {
    let t = test_report!("Revoking a permanent approval rewrites the sidecar without it");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "unused")
        .start()
        .await;
    let dir = tempfile::tempdir().unwrap();
    let sidecar_path = dir
        .path()
        .join("approvals.toml")
        .to_string_lossy()
        .into_owned();

    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .with_approvals(&sidecar_path)
        .report(&t)
        .start()
        .await;
    let manager = proxy.approvals.clone().unwrap();

    let req = manager
        .post(
            vec![method_rule("GET", "https://localhost/*")],
            None,
            None,
            None,
        )
        .unwrap();
    manager
        .resolve(
            &req.id,
            ApprovalStatus::Approved {
                rules_applied: vec![method_rule("GET", "https://localhost/*")],
                ttl: Lifetime::Permanent,
            },
        )
        .unwrap();
    let before = std::fs::read_to_string(&sidecar_path).unwrap();
    t.assert_contains("before revoke: url", before.as_str(), "localhost/*");

    manager.revoke_approval(&req.id);
    let after = std::fs::read_to_string(&sidecar_path).unwrap();
    t.assert_true("after revoke: url absent", !after.contains("localhost/*"));

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Phase 6: dedup (I4) + rate limit.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dedup_auto_approves_subsumed_rule() {
    let t = test_report!("POST with rule already covered by ruleset auto-approves as 200");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    // Start the proxy with a base rule that already covers api.foo.com.
    // The approval POST should be short-circuited.
    let sidecar = tempfile::NamedTempFile::new().unwrap();
    let sidecar_path = sidecar.path().to_string_lossy().into_owned();
    let proxy = TestProxy::builder(
        &ca,
        vec![pyloros::config::Rule {
            method: Some("GET".to_string()),
            url: "https://api.foo.com/*".to_string(),
            websocket: false,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        }],
        upstream.port(),
    )
    .with_approvals(&sidecar_path)
    .report(&t)
    .start()
    .await;
    let manager = proxy.approvals.clone().unwrap();

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .post_with_body(
            "https://pyloros.internal/approvals",
            json!({"rules": [method_rule_json("GET", "https://api.foo.com/v1/weather")]})
                .to_string(),
        )
        .await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let got: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    t.assert_eq("status", &got["status"].as_str().unwrap(), &"approved");

    // No pending approval should have been created.
    let pending = manager.list_pending();
    t.assert_eq("no pending created", &pending.len(), &0usize);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_rate_limit_returns_429() {
    let t = test_report!("Bursting past 60 POSTs in <60s eventually returns 429");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let mut saw_429 = false;
    for i in 0..65 {
        let resp = client
            .post_with_body(
                "https://pyloros.internal/approvals",
                json!({"rules": [method_rule_json("GET", &format!("https://api.foo.com/{}", i))]})
                    .to_string(),
            )
            .await;
        if resp.status().as_u16() == 429 {
            saw_429 = true;
            break;
        }
    }
    t.assert_true("saw 429 within 65 posts", saw_429);

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

/// `GET https://pyloros.internal/` should serve the agent-instructions
/// markdown when approvals are enabled, so an agent can fetch the
/// up-to-date protocol spec instead of relying on a stale prompt.
#[tokio::test]
async fn test_agent_instructions_served_at_root() {
    let t = test_report!("GET pyloros.internal/ returns markdown agent instructions");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://pyloros.internal/").await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let ctype = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    t.assert_contains("Content-Type", ctype.as_str(), "text/markdown");
    let body = resp.text().await.unwrap();
    t.assert_contains("mentions 451", body.as_str(), "451");
    t.assert_contains(
        "documents POST endpoint",
        body.as_str(),
        "POST https://pyloros.internal/approvals",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// 451 responses should advertise the agent-instructions endpoint so
/// an agent that hits a block has a discoverable path to the approvals
/// protocol.
#[tokio::test]
async fn test_blocked_response_links_to_instructions() {
    let t = test_report!("451 body and Link header point at https://pyloros.internal/");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("unused"))
        .report(&t, "unused")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://blocked.example.com/anything").await;
    t.assert_eq("status", &resp.status().as_u16(), &451u16);
    let link = resp
        .headers()
        .get("link")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    t.assert_contains("Link header", link.as_str(), "https://pyloros.internal/");
    let body = resp.text().await.unwrap();
    t.assert_contains(
        "body mentions instructions URL",
        body.as_str(),
        "https://pyloros.internal/",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// A git=fetch rule submitted via the API should round-trip correctly:
/// the proposal is preserved verbatim, and once approved it expands to
/// the full smart-HTTP endpoint set so an actual `info/refs` request to
/// the upstream goes through.
#[tokio::test]
async fn test_git_fetch_rule_roundtrip() {
    let t = test_report!("Approving a git=fetch rule unblocks /info/refs?service=git-upload-pack");

    let ca = TestCa::generate();
    // Upstream serves a stub /info/refs response — we only care that the
    // proxy lets the request reach upstream after approval.
    let upstream = TestUpstream::builder(&ca, ok_handler("001e# service=git-upload-pack\n0000"))
        .report(&t, "git info/refs stub")
        .start()
        .await;
    let (proxy, _sidecar) = start_proxy_with_approvals(&t, &ca, upstream.port()).await;
    let manager = proxy.approvals.clone().unwrap();

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Pre-approval: even info/refs is blocked.
    let resp = client
        .get("https://localhost/repo/info/refs?service=git-upload-pack")
        .await;
    t.assert_eq("pre-approval status", &resp.status().as_u16(), &451u16);

    // POST the git=fetch rule via the agent API.
    let post_body = json!({
        "rules": [{"git": "fetch", "url": "https://localhost/repo"}],
        "reason": "clone the upstream repo"
    })
    .to_string();
    let resp = client
        .post_with_body("https://pyloros.internal/approvals", post_body)
        .await;
    t.assert_eq("POST status", &resp.status().as_u16(), &202u16);
    let posted: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    let id = posted["id"].as_str().unwrap().to_string();
    t.assert_eq(
        "rules[0].git preserved",
        &posted["rules"][0]["git"].as_str().unwrap(),
        &"fetch",
    );

    // Resolve as approved (session lifetime).
    manager
        .resolve(
            &id,
            ApprovalStatus::Approved {
                rules_applied: vec![Rule {
                    method: None,
                    url: "https://localhost/repo".to_string(),
                    websocket: false,
                    git: Some("fetch".to_string()),
                    branches: None,
                    allow_redirects: Vec::new(),
                    log_body: false,
                }],
                ttl: Lifetime::Session,
            },
        )
        .unwrap();

    // Let the rebuild signal propagate.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Post-approval: the smart-HTTP info/refs endpoint is now allowed.
    let client2 = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client2
        .get("https://localhost/repo/info/refs?service=git-upload-pack")
        .await;
    t.assert_eq("post-approval info/refs", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}
