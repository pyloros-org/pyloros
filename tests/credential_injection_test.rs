//! E2E tests for credential injection feature.

mod common;

use common::{echo_handler, rule, test_client, ReportingClient, TestCa, TestProxy, TestUpstream};
use pyloros::config::{Credential, LocalHeaderConfig};
use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

fn cred(url: &str, header: &str, value: &str) -> Credential {
    Credential::Header {
        url: url.to_string(),
        header: header.to_string(),
        value: value.to_string(),
        local: LocalHeaderConfig::Value("test-local".to_string()),
    }
}

#[tokio::test]
async fn test_credential_injected_for_matching_https() {
    let t = test_report!("Credential injected for matching HTTPS request");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![cred(
            "https://localhost/*",
            "x-api-key",
            "real-secret",
        )])
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Send the local credential value; proxy replaces with real value
    let resp = client
        .get_with_header("https://localhost/test", "x-api-key", "test-local")
        .await;
    let body = resp.text().await.unwrap();
    t.assert_contains("header injected", &body, "x-api-key: real-secret");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_credential_replaces_local_with_real() {
    let t = test_report!("Credential replaces local value with real value");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![cred(
            "https://localhost/*",
            "x-api-key",
            "real-secret",
        )])
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Send the local value; verify it gets replaced
    let resp = client
        .get_with_header("https://localhost/test", "x-api-key", "test-local")
        .await;
    let body = resp.text().await.unwrap();
    t.assert_contains("real value present", &body, "x-api-key: real-secret");
    t.assert_not_contains("local value gone", &body, "test-local");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_credential_authorization_bearer() {
    let t = test_report!("Credential with Authorization Bearer format");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![cred(
            "https://localhost/*",
            "authorization",
            "Bearer real-token",
        )])
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Send the local value in the authorization header
    let resp = client
        .get_with_header("https://localhost/test", "authorization", "test-local")
        .await;
    let body = resp.text().await.unwrap();
    t.assert_contains("bearer injected", &body, "authorization: Bearer real-token");

    proxy.shutdown();
    upstream.shutdown();
}

/// When `value = "Bearer ${TOKEN}"`, the proxy parses out the literal "Bearer "
/// prefix during verification: the sandbox is expected to send
/// `Authorization: Bearer <local-token>`, NOT a bare local-token.
#[tokio::test]
async fn test_bearer_template_verifies_against_prefixed_header() {
    let t = test_report!("Bearer ${TOKEN} template strips prefix on verify");
    std::env::set_var("CREDTEST_REAL_TOKEN", "real-bearer-token");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![Credential::Header {
            url: "https://localhost/*".to_string(),
            header: "authorization".to_string(),
            value: "Bearer ${CREDTEST_REAL_TOKEN}".to_string(),
            local: LocalHeaderConfig::Value("local-token".to_string()),
        }])
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Sandbox sends "Bearer local-token" (the standard format with its own
    // env-var substituted). Proxy strips "Bearer ", checks middle == "local-token",
    // then forwards "Bearer real-bearer-token".
    let resp = client
        .get_with_header(
            "https://localhost/test",
            "authorization",
            "Bearer local-token",
        )
        .await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_contains(
        "real bearer token forwarded",
        &body,
        "authorization: Bearer real-bearer-token",
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// A bare token without the "Bearer " prefix must NOT verify, because the
/// real value template includes the prefix and the sandbox is expected to
/// match that shape.
#[tokio::test]
async fn test_bearer_template_rejects_bare_token() {
    let t = test_report!("Bearer ${TOKEN} rejects bare-token header");
    std::env::set_var("CREDTEST_REAL_TOKEN_2", "real-token-2");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![Credential::Header {
            url: "https://localhost/*".to_string(),
            header: "authorization".to_string(),
            value: "Bearer ${CREDTEST_REAL_TOKEN_2}".to_string(),
            local: LocalHeaderConfig::Value("local-token".to_string()),
        }])
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // No "Bearer " prefix → must reject.
    let resp = client
        .get_with_header("https://localhost/test", "authorization", "local-token")
        .await;
    t.assert_eq("status", &resp.status().as_u16(), &403u16);

    proxy.shutdown();
    upstream.shutdown();
}

/// `local_generated = true` with a literal `value` (no ${VAR}) is rejected
/// at config time: there is no env-var name to infer, and the agent has no
/// substitution slot to use the generated secret.
#[test]
fn test_local_generated_with_literal_value_is_rejected() {
    let t = test_report!("local_generated requires ${VAR} in value or explicit local_env_name");
    let toml = r#"
[proxy]
generated_secrets_file = "/tmp/x.env"

[[credentials]]
url = "https://example.com/*"
header = "x-api-key"
value = "literal-no-template"
local_generated = true
"#;
    let cfg = pyloros::Config::parse(toml).unwrap();
    let err = match pyloros::CredentialEngine::new(cfg.credentials, &Default::default()) {
        Ok(_) => panic!("expected config error"),
        Err(e) => e,
    };
    let msg = format!("{}", err);
    t.assert_contains("error mentions local_env_name", &msg, "local_env_name");
}

/// `local_generated = true` with a literal `value` plus explicit
/// `local_env_name` is allowed (operator opted in).
#[test]
fn test_local_generated_with_literal_value_and_explicit_env_name() {
    let t = test_report!("local_generated accepts literal value when local_env_name is given");
    let toml = r#"
[proxy]
generated_secrets_file = "/tmp/x.env"

[[credentials]]
url = "https://example.com/*"
header = "x-api-key"
value = "literal-no-template"
local_generated = true
local_env_name = "EXPLICIT_LOCAL_NAME"
"#;
    let cfg = pyloros::Config::parse(toml).unwrap();
    let (_engine, generated) =
        pyloros::CredentialEngine::new(cfg.credentials, &Default::default()).unwrap();
    t.assert_eq("one secret generated", &generated.len(), &1usize);
    t.assert_eq(
        "env_name from explicit field",
        &generated[0].env_name.as_str(),
        &"EXPLICIT_LOCAL_NAME",
    );
}

#[tokio::test]
async fn test_no_injection_for_non_matching_url() {
    let t = test_report!("No injection for non-matching URL");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![cred(
            "https://other.example.com/*",
            "x-api-key",
            "should-not-appear",
        )])
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // No credential matches → no local check → no injection
    let resp = client.get("https://localhost/test").await;
    let body = resp.text().await.unwrap();
    t.assert_not_contains("no injection", &body, "x-api-key");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_multiple_credentials_different_headers() {
    let t = test_report!("Multiple credentials for different headers both injected");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![
            cred("https://localhost/*", "x-api-key", "key123"),
            cred("https://localhost/*", "x-custom", "custom-val"),
        ])
        .report(&t)
        .start()
        .await;

    // Send both local credential values
    let client = test_client(proxy.addr(), &ca);
    t.action("GET with both local credential headers");
    let resp = client
        .get("https://localhost/test")
        .header("x-api-key", "test-local")
        .header("x-custom", "test-local")
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    t.assert_contains("api key", &body, "x-api-key: key123");
    t.assert_contains("custom", &body, "x-custom: custom-val");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_credential_not_injected_for_blocked_request() {
    let t = test_report!("Credential not injected for blocked request");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    // No rules → everything blocked
    let proxy = TestProxy::builder(&ca, vec![], upstream.port())
        .credentials(vec![cred("https://localhost/*", "x-api-key", "secret")])
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client.get("https://localhost/test").await;
    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_no_injection_over_plain_http() {
    let t = test_report!("No injection over plain HTTP");
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    t.setup("MockServer returning 200 'ok'");
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;

    let plain_port = upstream.address().port();

    // Proxy with credential and an HTTP rule that allows the request
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("*", &format!("http://localhost:{}/*", plain_port))],
        plain_port,
    )
    .credentials(vec![cred(
        &format!("http://localhost:{}/*", plain_port),
        "x-api-key",
        "should-not-inject",
    )])
    .start()
    .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());

    let resp = client
        .get(&format!("http://localhost:{}/test", plain_port))
        .await;
    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);

    // Verify the upstream received the request without the injected header
    let requests = upstream.received_requests().await.unwrap();
    t.assert_eq("one request received", &requests.len(), &1usize);
    let has_api_key = requests[0].headers.get("x-api-key").is_some();
    t.assert_true("no x-api-key header", !has_api_key);

    proxy.shutdown();
}

#[tokio::test]
async fn test_credential_with_env_var() {
    let t = test_report!("Config with env var resolution");
    std::env::set_var("TEST_CRED_E2E_SECRET", "env-resolved-value");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![cred(
            "https://localhost/*",
            "x-api-key",
            "${TEST_CRED_E2E_SECRET}",
        )])
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Send the local credential value
    let resp = client
        .get_with_header("https://localhost/test", "x-api-key", "test-local")
        .await;
    let body = resp.text().await.unwrap();
    t.assert_contains("env var resolved", &body, "x-api-key: env-resolved-value");

    proxy.shutdown();
    upstream.shutdown();
    std::env::remove_var("TEST_CRED_E2E_SECRET");
}

#[tokio::test]
async fn test_local_credential_mismatch_returns_403() {
    let t = test_report!("Wrong local credential returns 403 Forbidden");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![cred(
            "https://localhost/*",
            "x-api-key",
            "real-secret",
        )])
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Send wrong local value
    let resp = client
        .get_with_header("https://localhost/test", "x-api-key", "wrong-local-value")
        .await;
    t.assert_eq("status 403", &resp.status().as_u16(), &403u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_missing_local_credential_returns_403() {
    let t = test_report!("Missing local credential returns 403 Forbidden");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![cred(
            "https://localhost/*",
            "x-api-key",
            "real-secret",
        )])
        .report(&t)
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Send without the header at all
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("status 403", &resp.status().as_u16(), &403u16);

    proxy.shutdown();
    upstream.shutdown();
}
