mod common;

use common::{ReportingClient, TestCa, TestProxy, TestUpstream, ok_handler};
use serde_json::{Value, json};
use std::time::Duration;

/// Spin up a proxy with approvals + a fresh audit log file, return the
/// proxy plus a tempfile keeping the path alive. The audit-log file is
/// what the dashboard reads through the SSE-snapshot ring buffer.
async fn start_proxy(
    t: &common::TestReport,
    ca: &TestCa,
    upstream_port: u16,
) -> (TestProxy, tempfile::NamedTempFile, tempfile::NamedTempFile) {
    let rules_file = tempfile::NamedTempFile::new().unwrap();
    let audit_file = tempfile::NamedTempFile::new().unwrap();
    let proxy = TestProxy::builder(ca, vec![], upstream_port)
        .with_approvals(&rules_file.path().to_string_lossy())
        .audit_log(&audit_file.path().to_string_lossy())
        .report(t)
        .start()
        .await;
    (proxy, rules_file, audit_file)
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}

/// Read the first SSE frame from `GET /events` and parse it as the
/// dashboard snapshot. Used in place of a separate snapshot endpoint —
/// SSE is the single source of truth for dashboard state.
async fn fetch_snapshot(client: &reqwest::Client, dashboard: &str) -> Value {
    let mut resp = client
        .get(format!("{}/events", dashboard))
        .send()
        .await
        .unwrap();
    // The snapshot is the first `data: ...` line; read chunks until we
    // have a complete one.
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.unwrap() {
        buf.extend_from_slice(&chunk);
        if let Some(json) = buf
            .windows(2)
            .position(|w| w == b"\n\n")
            .and_then(|end| std::str::from_utf8(&buf[..end]).ok())
            .and_then(|s| s.strip_prefix("data: "))
        {
            return serde_json::from_str(json).unwrap();
        }
    }
    panic!("SSE stream closed before a snapshot frame arrived");
}

async fn json_post(client: &reqwest::Client, url: String, body: Value) -> (u16, String) {
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (status, text)
}

/// /permissive enables timeboxed permissive mode, an otherwise-blocked
/// request goes through, and after the duration elapses the override
/// auto-expires. Audit log records both toggle entries.
#[tokio::test]
async fn test_permissive_toggle_unblocks_then_auto_expires() {
    let t = test_report!(
        "POST /permissive enables timeboxed permissive mode and auto-expires after duration_secs"
    );

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Baseline: unmatched HTTPS request is blocked (no rule, no permissive).
    let url = format!(
        "https://{}.unmatched.example.com/anything",
        // Use a host that wiremock will accept but the proxy has no rule for.
        "x"
    );
    let resp = client.get(&url).await;
    t.assert_eq("blocked baseline", &resp.status().as_u16(), &451u16);

    // Enable permissive for 2s.
    let (s, body) = json_post(
        &http,
        format!("{}/permissive", dashboard),
        json!({"duration_secs": 2}),
    )
    .await;
    t.assert_eq("POST /permissive status", &s, &204u16);
    let _ = body;

    // Same blocked request now goes through (permissive).
    let resp = client.get(&url).await;
    let status = resp.status().as_u16();
    t.assert_true("permitted after toggle (not 451)", status != 451);

    // Audit log file contains a permissive_enabled entry.
    let audit_contents = std::fs::read_to_string(audit_file.path()).unwrap();
    t.assert_contains(
        "audit has permissive_enabled",
        audit_contents.as_str(),
        "\"event\":\"permissive_enabled\"",
    );
    t.assert_contains(
        "duration recorded",
        audit_contents.as_str(),
        "\"permissive_duration_secs\":2",
    );
    t.assert_contains(
        "source=dashboard",
        audit_contents.as_str(),
        "\"permissive_source\":\"dashboard\"",
    );

    // Wait past expiry + grace.
    tokio::time::sleep(Duration::from_millis(2300)).await;

    // Permissive is off → request blocked again.
    let resp = client.get(&url).await;
    t.assert_eq("blocked after expiry", &resp.status().as_u16(), &451u16);

    let audit_contents = std::fs::read_to_string(audit_file.path()).unwrap();
    t.assert_contains(
        "audit has permissive_disabled",
        audit_contents.as_str(),
        "\"event\":\"permissive_disabled\"",
    );
    t.assert_contains(
        "expired source",
        audit_contents.as_str(),
        "\"permissive_source\":\"expired\"",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// duration_secs=0 clears an active override immediately.
#[tokio::test]
async fn test_permissive_clear_with_zero_duration() {
    let t = test_report!("POST /permissive with duration_secs=0 clears the override immediately");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, _audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();

    let (s, _) = json_post(
        &http,
        format!("{}/permissive", dashboard),
        json!({"duration_secs": 60}),
    )
    .await;
    t.assert_eq("enable status", &s, &204u16);

    let state = fetch_snapshot(&http, &dashboard).await;
    t.assert_true(
        "state.permissive.active=true after enable",
        state["permissive"]["active"].as_bool().unwrap(),
    );

    let (s, _) = json_post(
        &http,
        format!("{}/permissive", dashboard),
        json!({"duration_secs": 0}),
    )
    .await;
    t.assert_eq("clear status", &s, &204u16);

    let state = fetch_snapshot(&http, &dashboard).await;
    t.assert_true(
        "state.permissive.active=false after clear",
        !state["permissive"]["active"].as_bool().unwrap(),
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// POST /rules/parse round-trips a `[[rules]]` TOML table into a Rule.
#[tokio::test]
async fn test_rules_parse_accepts_valid_toml_and_rejects_garbage() {
    let t = test_report!("POST /rules/parse parses valid TOML and rejects invalid input");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, _audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();

    let toml_src = "[[rules]]\nmethod = \"GET\"\nurl = \"https://api.example.com/*\"\n";
    let (s, body) = json_post(
        &http,
        format!("{}/rules/parse", dashboard),
        json!({"toml": toml_src}),
    )
    .await;
    t.assert_eq("valid TOML status", &s, &200u16);
    let parsed: Value = serde_json::from_str(&body).unwrap();
    t.assert_eq(
        "parsed method",
        &parsed["rules"][0]["method"].as_str().unwrap(),
        &"GET",
    );
    t.assert_eq(
        "parsed url",
        &parsed["rules"][0]["url"].as_str().unwrap(),
        &"https://api.example.com/*",
    );

    let (s, body) = json_post(
        &http,
        format!("{}/rules/parse", dashboard),
        json!({"toml": "not valid toml ~~~"}),
    )
    .await;
    t.assert_eq("invalid TOML status", &s, &400u16);
    t.assert_contains("error message", body.as_str(), "TOML parse error");

    proxy.shutdown();
    upstream.shutdown();
}

/// POST /rules/suggest emits an exact-match rule plus a commented
/// host-wildcard variant for a plain HTTPS blocked request. The suggested
/// TOML round-trips through /rules/parse.
#[tokio::test]
async fn test_rules_suggest_plain_http_returns_exact_and_wildcard() {
    let t = test_report!("POST /rules/suggest gives exact + commented wildcard for plain HTTPS");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, _audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();

    let entry = json!({
        "timestamp": "2026-05-31T00:00:00Z",
        "event": "request_blocked",
        "method": "GET",
        "url": "https://api.example.com/v1/widgets/42",
        "host": "api.example.com",
        "scheme": "https",
        "protocol": "https",
        "decision": "blocked",
        "reason": "no_matching_rule",
    });

    let (s, body) = json_post(
        &http,
        format!("{}/rules/suggest", dashboard),
        json!({"audit": entry}),
    )
    .await;
    t.assert_eq("status", &s, &200u16);
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let toml_text = parsed["toml"].as_str().unwrap().to_string();
    t.assert_contains("exact URL present", toml_text.as_str(), "v1/widgets/42");
    t.assert_contains(
        "broader variant present",
        toml_text.as_str(),
        "api.example.com/*",
    );
    t.assert_contains("broader is commented", toml_text.as_str(), "# Or, broader");

    // Round-trip: the un-commented portion parses cleanly.
    let (parse_s, parse_body) = json_post(
        &http,
        format!("{}/rules/parse", dashboard),
        json!({"toml": toml_text}),
    )
    .await;
    t.assert_eq("parse status", &parse_s, &200u16);
    let parsed: Value = serde_json::from_str(&parse_body).unwrap();
    t.assert_eq(
        "parsed url",
        &parsed["rules"][0]["url"].as_str().unwrap(),
        &"https://api.example.com/v1/widgets/42",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// /rules/suggest for a git smart-HTTP block emits a `git = "fetch"` rule
/// (or `"push"` for receive-pack) targeted at the repo URL.
#[tokio::test]
async fn test_rules_suggest_git_upload_pack_emits_git_fetch_rule() {
    let t = test_report!("/rules/suggest emits git=fetch for a blocked git-upload-pack URL");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, _audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();

    let entry = json!({
        "timestamp": "2026-05-31T00:00:00Z",
        "event": "request_blocked",
        "method": "POST",
        "url": "https://github.com/org/repo.git/git-upload-pack",
        "host": "github.com",
        "scheme": "https",
        "protocol": "https",
        "decision": "blocked",
        "reason": "no_matching_rule",
    });
    let (s, body) = json_post(
        &http,
        format!("{}/rules/suggest", dashboard),
        json!({"audit": entry}),
    )
    .await;
    t.assert_eq("status", &s, &200u16);
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let toml_text = parsed["toml"].as_str().unwrap().to_string();
    t.assert_contains("git=fetch present", toml_text.as_str(), "git = \"fetch\"");
    t.assert_contains(
        "repo URL stripped of suffix",
        toml_text.as_str(),
        "https://github.com/org/repo.git",
    );
    t.assert_not_contains(
        "no git-upload-pack suffix in suggestion",
        toml_text.as_str(),
        "git-upload-pack",
    );
}

/// /rules/suggest strips a `/info/refs?service=...` discovery URL down to the
/// bare repo URL, not `.../info/refs` (regression: query string broke suffix stripping).
#[tokio::test]
async fn test_rules_suggest_info_refs_query_strips_to_repo_url() {
    let t = test_report!("/rules/suggest strips /info/refs?service=... down to the repo URL");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, _audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();

    let entry = json!({
        "timestamp": "2026-05-31T00:00:00Z",
        "event": "request_blocked",
        "method": "GET",
        "url": "https://github.com/octocat/hello-world/info/refs?service=git-upload-pack",
        "host": "github.com",
        "scheme": "https",
        "protocol": "https",
        "decision": "blocked",
        "reason": "no_matching_rule",
    });
    let (s, body) = json_post(
        &http,
        format!("{}/rules/suggest", dashboard),
        json!({"audit": entry}),
    )
    .await;
    t.assert_eq("status", &s, &200u16);
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let toml_text = parsed["toml"].as_str().unwrap().to_string();
    t.assert_contains("git=fetch present", toml_text.as_str(), "git = \"fetch\"");
    t.assert_contains(
        "repo URL stripped to bare repo",
        toml_text.as_str(),
        "url = \"https://github.com/octocat/hello-world\"",
    );
    t.assert_not_contains(
        "no info/refs path in suggestion",
        toml_text.as_str(),
        "info/refs",
    );
    t.assert_not_contains(
        "no query string in suggestion",
        toml_text.as_str(),
        "service=",
    );
}

/// /rules/suggest with reason=branch_restriction includes a commented
/// `branches = [...]` line populated with the audit entry's blocked refs.
#[tokio::test]
async fn test_rules_suggest_branch_restriction_includes_branches_hint() {
    let t = test_report!(
        "/rules/suggest emits a commented branches = [...] line for branch_restriction blocks"
    );

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, _audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();

    let entry = json!({
        "timestamp": "2026-05-31T00:00:00Z",
        "event": "request_blocked",
        "method": "POST",
        "url": "https://github.com/org/repo.git/git-receive-pack",
        "host": "github.com",
        "scheme": "https",
        "protocol": "https",
        "decision": "blocked",
        "reason": "branch_restriction",
        "git": {"blocked_refs": ["refs/heads/main"]},
    });
    let (_, body) = json_post(
        &http,
        format!("{}/rules/suggest", dashboard),
        json!({"audit": entry}),
    )
    .await;
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let toml_text = parsed["toml"].as_str().unwrap().to_string();
    t.assert_contains("git=push present", toml_text.as_str(), "git = \"push\"");
    t.assert_contains(
        "branches hint present (commented)",
        toml_text.as_str(),
        "# branches = [\"refs/heads/main\"]",
    );
}

/// POST /rules adds an active timeboxed rule that immediately unblocks a
/// previously-blocked request and shows up in active.
#[tokio::test]
async fn test_post_rules_adds_active_rule_and_unblocks() {
    let t = test_report!("POST /rules adds an active rule, unblocks traffic, surfaces in snapshot");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, _audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let url = "https://test-host.example.com/api/foo";
    // Baseline blocked.
    let resp = client.get(url).await;
    t.assert_eq("baseline blocked", &resp.status().as_u16(), &451u16);

    let (s, body) = json_post(
        &http,
        format!("{}/rules", dashboard),
        json!({
            "rules": [{"method": "GET", "url": "https://test-host.example.com/*"}],
            "ttl": "one_hour",
        }),
    )
    .await;
    t.assert_eq("POST /rules status", &s, &200u16);
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let approval_id = parsed["approval_id"].as_str().unwrap().to_string();
    t.assert_starts_with("approval_id is rul_ prefix", &approval_id, "rul_");

    // Give the FilterEngine rebuild a moment to propagate.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Use a fresh client to avoid pooled-connection reuse from the
    // baseline call, which would still see the pre-rebuild filter.
    let client2 = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client2.get(url).await;
    t.assert_true(
        "now passes through (not 451)",
        resp.status().as_u16() != 451,
    );

    let state = fetch_snapshot(&http, &dashboard).await;
    let actives = state["active"].as_array().unwrap();
    let found = actives
        .iter()
        .any(|a| a["approval_id"].as_str() == Some(approval_id.as_str()));
    t.assert_true("rule listed in active", found);

    // DELETE revokes.
    let resp = http
        .delete(format!("{}/approvals/{}/rules", dashboard, approval_id))
        .send()
        .await
        .unwrap();
    t.assert_eq("DELETE status", &resp.status().as_u16(), &204u16);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client3 = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client3.get(url).await;
    t.assert_eq(
        "blocked again after revoke",
        &resp.status().as_u16(),
        &451u16,
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// Editing rules at decision time: user submits a `rules_applied` that
/// differs from the agent's proposal; the *edited* rules become active.
#[tokio::test]
async fn test_decision_with_edited_rules_applies_edited_version() {
    let t = test_report!(
        "POST /approvals/{id}/decision honors rules_applied when user edits the proposal"
    );

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, _audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Agent proposes a rule for the wrong host.
    let resp_text = client
        .post_with_body(
            "https://pyloros.internal/approvals",
            json!({
                "rules": [{"method": "GET", "url": "https://wrong.example.com/*"}]
            })
            .to_string(),
        )
        .await
        .text()
        .await
        .unwrap();
    let posted: Value = serde_json::from_str(&resp_text).unwrap();
    let id = posted["id"].as_str().unwrap().to_string();

    // Dashboard user edits to correct host, then approves.
    let edited = json!([{"method": "GET", "url": "https://right.example.com/*"}]);
    let (s, _) = json_post(
        &http,
        format!("{}/approvals/{}/decision", dashboard, id),
        json!({"action": "approve", "ttl": "one_hour", "rules_applied": edited}),
    )
    .await;
    t.assert_eq("decision status", &s, &204u16);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let wrong = client.get("https://wrong.example.com/x").await;
    t.assert_eq(
        "original (wrong) host stays blocked",
        &wrong.status().as_u16(),
        &451u16,
    );
    let right = client.get("https://right.example.com/x").await;
    t.assert_true("edited host passes", right.status().as_u16() != 451);

    proxy.shutdown();
    upstream.shutdown();
}

/// Initial SSE snapshot includes recent blocked entries after a blocked request, and
/// recent allowed entries surface in recent_all once a request matched.
#[tokio::test]
async fn test_state_includes_recent_audit_entries() {
    let t = test_report!("Initial SSE snapshot returns recent audit entries split by blocked/all");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, _audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Generate a blocked request.
    let _ = client.get("https://blocked.example.com/path").await;

    // Add a rule, then make an allowed request.
    let (_, _) = json_post(
        &http,
        format!("{}/rules", dashboard),
        json!({
            "rules": [{"method": "GET", "url": "https://allowed.example.com/*"}],
            "ttl": "one_hour",
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = client.get("https://allowed.example.com/ping").await;

    // Allow the audit log to flush.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let state = fetch_snapshot(&http, &dashboard).await;
    let blocked = state["recent_blocked"].as_array().unwrap();
    let all = state["recent_all"].as_array().unwrap();

    let has_blocked = blocked.iter().any(|e| {
        e["url"]
            .as_str()
            .unwrap_or("")
            .contains("blocked.example.com")
    });
    t.assert_true("blocked entry present in recent_blocked", has_blocked);

    let has_allowed = all.iter().any(|e| {
        e["url"]
            .as_str()
            .unwrap_or("")
            .contains("allowed.example.com")
    });
    t.assert_true("allowed entry present in recent_all", has_allowed);

    let no_allowed_in_blocked = blocked.iter().all(|e| {
        !e["url"]
            .as_str()
            .unwrap_or("")
            .contains("allowed.example.com")
    });
    t.assert_true(
        "allowed entries are not in recent_blocked",
        no_allowed_in_blocked,
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// /rules/suggest pre-fills `allow_redirects` with the observed
/// redirect target when the audit snapshot carries one. Both an exact
/// URL and a host-wildcard alternative are emitted.
#[tokio::test]
async fn test_rules_suggest_includes_observed_redirect_target() {
    let t = test_report!(
        "/rules/suggest pre-fills allow_redirects from the audit entry's redirect_target"
    );

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("ok"))
        .report(&t, "ok")
        .start()
        .await;
    let (proxy, _rules_file, _audit_file) = start_proxy(&t, &ca, upstream.port()).await;
    let dashboard = format!("http://{}", proxy.dashboard_addr.unwrap());
    let http = http_client();

    // Synthesize an audit snapshot with redirect_target set, matching
    // what the proxy would attach after seeing a 3xx response.
    let entry = json!({
        "timestamp": "2026-06-02T00:00:00Z",
        "event": "request_permitted",
        "method": "GET",
        "url": "https://login.example.com/start",
        "host": "login.example.com",
        "scheme": "https",
        "protocol": "https",
        "decision": "allowed",
        "reason": "no_matching_rule",
        "redirect_target": "https://auth.example.com/callback?ticket=abc",
    });
    let (s, body) = json_post(
        &http,
        format!("{}/rules/suggest", dashboard),
        json!({"audit": entry}),
    )
    .await;
    t.assert_eq("status", &s, &200u16);
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let toml_text = parsed["toml"].as_str().unwrap().to_string();

    t.assert_contains(
        "allow_redirects exact present",
        toml_text.as_str(),
        "allow_redirects = [\"https://auth.example.com/callback?ticket=abc\"]",
    );
    t.assert_contains(
        "wildcard alternative present",
        toml_text.as_str(),
        "https://auth.example.com/*",
    );

    proxy.shutdown();
    upstream.shutdown();
}
