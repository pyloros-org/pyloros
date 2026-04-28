//! E2E tests for AWS SigV4 credential injection feature.
//!
//! Uses a mock upstream that acts as a fake AWS service to verify
//! that the proxy correctly re-signs requests with real credentials.

mod common;

use bytes::Bytes;
use common::{
    echo_handler, rule, ReportingClient, TestCa, TestProxy, TestUpstream, UpstreamHandler,
};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use pyloros::config::{Credential, LocalHeaderConfig, LocalSigV4Config};
use ring::digest;
use std::sync::Arc;

/// Local SigV4 credentials used by tests.
const LOCAL_KEY_ID: &str = "AKIALOCALTEST1234567";
const LOCAL_SECRET: &str = "LocalSecretAccessKeyForTesting1234567890";

/// Helper to create a header credential.
fn header_cred(url: &str, header: &str, value: &str) -> Credential {
    Credential::Header {
        url: url.to_string(),
        header: header.to_string(),
        value: value.to_string(),
        local: LocalHeaderConfig::Value("test-local".to_string()),
    }
}

/// Helper to create an AWS SigV4 credential.
fn aws_cred(url: &str, key_id: &str, secret: &str, token: Option<&str>) -> Credential {
    Credential::AwsSigV4 {
        url: url.to_string(),
        access_key_id: key_id.to_string(),
        secret_access_key: secret.to_string(),
        session_token: token.map(|s| s.to_string()),
        local: LocalSigV4Config::Explicit {
            access_key_id: LOCAL_KEY_ID.to_string(),
            secret_access_key: LOCAL_SECRET.to_string(),
        },
    }
}

/// Sign a request with local credentials and return the headers to set.
fn local_signed_headers(
    method: &str,
    path: &str,
    body: &[u8],
    region: &str,
    service: &str,
) -> Vec<(String, String)> {
    pyloros::filter::sigv4::sign_request(
        LOCAL_KEY_ID,
        LOCAL_SECRET,
        None,
        method,
        path,
        "",
        &[("host".to_string(), "localhost".to_string())],
        body,
        region,
        service,
    )
}

/// Hex-encode SHA-256 of data.
fn sha256_hex(data: &[u8]) -> String {
    let d = digest::digest(&digest::SHA256, data);
    d.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Create a mock upstream handler that verifies AWS-signed requests.
///
/// The handler:
/// 1. Parses the incoming Authorization header to extract the access key ID
/// 2. Verifies X-Amz-Content-Sha256 matches the body hash
/// 3. Returns JSON with the received auth details for assertions
fn fake_aws_handler() -> UpstreamHandler {
    Arc::new(|req: Request<Incoming>| {
        Box::pin(async move {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let amz_date = req
                .headers()
                .get("x-amz-date")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let content_sha256 = req
                .headers()
                .get("x-amz-content-sha256")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let security_token = req
                .headers()
                .get("x-amz-security-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            // Extract access key ID from Authorization header
            let access_key_id = auth
                .find("Credential=")
                .and_then(|start| {
                    let after = &auth[start + "Credential=".len()..];
                    after.find('/').map(|end| &after[..end])
                })
                .unwrap_or("")
                .to_string();

            // Extract region and service from credential scope
            let credential_scope = auth
                .find("Credential=")
                .map(|start| {
                    let after = &auth[start + "Credential=".len()..];
                    let end = after.find(',').unwrap_or(after.len());
                    after[..end].to_string()
                })
                .unwrap_or_default();

            // Collect all header names
            let header_names: Vec<String> = req
                .headers()
                .keys()
                .map(|k| k.as_str().to_string())
                .collect();

            // Read body for hash verification
            let body_bytes = req.collect().await.unwrap().to_bytes();
            let actual_body_hash = sha256_hex(&body_bytes);

            let response_json = serde_json::json!({
                "access_key_id": access_key_id,
                "credential_scope": credential_scope,
                "amz_date": amz_date,
                "content_sha256": content_sha256,
                "actual_body_hash": actual_body_hash,
                "security_token": security_token,
                "header_names": header_names,
                "body": String::from_utf8_lossy(&body_bytes).to_string(),
                "authorization": auth,
            });

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(
                    Full::new(Bytes::from(response_json.to_string()))
                        .map_err(|e| match e {})
                        .boxed(),
                )
                .unwrap())
        })
    })
}

#[tokio::test]
async fn test_sigv4_resigning_replaces_fake_key() {
    let t = test_report!("SigV4 re-signing replaces local key with real key");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, fake_aws_handler())
        .report(&t, "fake AWS handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![aws_cred(
            "https://localhost/*",
            "AKIAREAL123456789012",
            "RealSecretAccessKeyForTesting123456789012",
            None,
        )])
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Send request signed with local credentials
    let signed = local_signed_headers("GET", "/test", b"", "us-east-1", "sts");
    t.action("GET `https://localhost/test` with local SigV4 credentials");
    let mut req = client.inner().get("https://localhost/test");
    for (name, value) in &signed {
        req = req.header(name.as_str(), value.as_str());
    }
    let resp = req.send().await.unwrap();

    let body = resp.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    // Verify the proxy re-signed with the real key
    t.assert_eq(
        "access key is real",
        &json["access_key_id"].as_str().unwrap(),
        &"AKIAREAL123456789012",
    );
    t.assert_not_contains(
        "local key absent",
        json["authorization"].as_str().unwrap(),
        LOCAL_KEY_ID,
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_sigv4_region_service_preserved() {
    let t = test_report!("Region/service preserved from original signature");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, fake_aws_handler())
        .report(&t, "fake AWS handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![aws_cred(
            "https://localhost/*",
            "AKIAREAL123456789012",
            "RealSecret",
            None,
        )])
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let signed = local_signed_headers("GET", "/test", b"", "eu-west-1", "s3");
    t.action("GET with local SigV4 (eu-west-1/s3)");
    let mut req = client.inner().get("https://localhost/test");
    for (name, value) in &signed {
        req = req.header(name.as_str(), value.as_str());
    }
    let resp = req.send().await.unwrap();

    let body = resp.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    // Verify region and service are preserved in the credential scope
    let scope = json["credential_scope"].as_str().unwrap();
    t.assert_contains("has region", scope, "eu-west-1");
    t.assert_contains("has service", scope, "s3");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_sigv4_session_token_injected() {
    let t = test_report!("Session token injected when configured");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, fake_aws_handler())
        .report(&t, "fake AWS handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![aws_cred(
            "https://localhost/*",
            "AKIAREAL123456789012",
            "RealSecret",
            Some("MySessionToken123"),
        )])
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let signed = local_signed_headers("GET", "/test", b"", "us-east-1", "sts");
    t.action("GET with local SigV4 credentials");
    let mut req = client.inner().get("https://localhost/test");
    for (name, value) in &signed {
        req = req.header(name.as_str(), value.as_str());
    }
    let resp = req.send().await.unwrap();

    let body = resp.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    t.assert_eq(
        "security token",
        &json["security_token"].as_str().unwrap(),
        &"MySessionToken123",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_sigv4_body_hash_correctness_post() {
    let t = test_report!("Body hash correctness (POST with body)");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, fake_aws_handler())
        .report(&t, "fake AWS handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![aws_cred(
            "https://localhost/*",
            "AKIAREAL123456789012",
            "RealSecret",
            None,
        )])
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let post_body = b"Action=GetCallerIdentity&Version=2011-06-15";
    let signed = local_signed_headers("POST", "/", post_body, "us-east-1", "sts");

    t.action("POST `https://localhost/` with body and local SigV4");
    let mut req = client.inner().post("https://localhost/");
    for (name, value) in &signed {
        req = req.header(name.as_str(), value.as_str());
    }
    let resp = req.body(post_body.to_vec()).send().await.unwrap();

    let body = resp.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    // Verify the content hash matches the actual body
    let content_sha256 = json["content_sha256"].as_str().unwrap();
    let actual_hash = json["actual_body_hash"].as_str().unwrap();
    t.assert_eq("content hash matches body", &content_sha256, &actual_hash);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_sigv4_empty_body_hash() {
    let t = test_report!("GET request with empty body has correct hash");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, fake_aws_handler())
        .report(&t, "fake AWS handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![aws_cred(
            "https://localhost/*",
            "AKIAREAL123456789012",
            "RealSecret",
            None,
        )])
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let signed = local_signed_headers("GET", "/test", b"", "us-east-1", "sts");
    t.action("GET with local SigV4 credentials");
    let mut req = client.inner().get("https://localhost/test");
    for (name, value) in &signed {
        req = req.header(name.as_str(), value.as_str());
    }
    let resp = req.send().await.unwrap();

    let body = resp.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    t.assert_eq(
        "empty body hash",
        &json["content_sha256"].as_str().unwrap(),
        &"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_sigv4_mixed_with_header_credential() {
    let t = test_report!("Mixed header + SigV4 credentials both applied");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, fake_aws_handler())
        .report(&t, "fake AWS handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![
            header_cred("https://localhost/*", "x-custom-header", "custom-value"),
            aws_cred(
                "https://localhost/*",
                "AKIAREAL123456789012",
                "RealSecret",
                None,
            ),
        ])
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Need both: local header value for the header credential + signed SigV4 for the AWS credential
    let signed = local_signed_headers("GET", "/test", b"", "us-east-1", "sts");
    t.action("GET with x-custom-header (local) + SigV4 (local)");
    let mut req = client
        .inner()
        .get("https://localhost/test")
        .header("x-custom-header", "test-local");
    for (name, value) in &signed {
        req = req.header(name.as_str(), value.as_str());
    }
    let resp = req.send().await.unwrap();

    let body = resp.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    // Verify both credential types applied
    t.assert_eq(
        "AWS key is real",
        &json["access_key_id"].as_str().unwrap(),
        &"AKIAREAL123456789012",
    );
    let header_names = json["header_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    t.assert_true(
        "custom header present",
        header_names.contains(&"x-custom-header".to_string()),
    );

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_sigv4_no_match_passes_unchanged() {
    let t = test_report!("No match — request passes with original auth");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        // SigV4 credential for a different URL pattern — won't match localhost
        .credentials(vec![aws_cred(
            "https://other.amazonaws.com/*",
            "AKIAREAL123456789012",
            "RealSecret",
            None,
        )])
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // No credential matches this URL, so no local check and no injection
    let resp = client
        .get_with_header(
            "https://localhost/test",
            "authorization",
            "Bearer passthrough",
        )
        .await;

    let body = resp.text().await.unwrap();
    t.assert_contains("original auth preserved", &body, "Bearer passthrough");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_sigv4_backward_compat_header_credential() {
    let t = test_report!("Header credential with local check works for authorization header");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, echo_handler())
        .report(&t, "echo handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![rule("*", "https://localhost/*")], upstream.port())
        .credentials(vec![header_cred(
            "https://localhost/*",
            "authorization",
            "Bearer old-format-token",
        )])
        .start()
        .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // Send the local credential value in the authorization header
    let resp = client
        .get_with_header("https://localhost/test", "authorization", "test-local")
        .await;
    let body = resp.text().await.unwrap();
    t.assert_contains(
        "bearer injected",
        &body,
        "authorization: Bearer old-format-token",
    );

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// E2E test with real awscli (optional — skips if dependencies missing)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_aws_sts_through_proxy() {
    // This test requires awscli + real AWS credentials — skip if not available
    let t = test_report!("Real AWS STS call through proxy (optional)");

    // Check for awscli
    let has_awscli = std::process::Command::new("aws")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_awscli {
        t.action("SKIP: awscli not installed");
        return;
    }

    // Check for real AWS credentials
    let has_creds = std::env::var("AWS_ACCESS_KEY_ID").is_ok()
        && std::env::var("AWS_SECRET_ACCESS_KEY").is_ok();
    if !has_creds {
        t.action("SKIP: AWS credentials not set");
        return;
    }

    let ca = TestCa::generate();
    let real_key = std::env::var("AWS_ACCESS_KEY_ID").unwrap();
    let real_secret = std::env::var("AWS_SECRET_ACCESS_KEY").unwrap();

    // No upstream override — connect to real AWS endpoints.
    let mut config = pyloros::Config::minimal(
        "127.0.0.1:0".to_string(),
        ca.cert_path.clone(),
        ca.key_path.clone(),
    );
    config.rules = vec![rule("*", "https://*.amazonaws.com/*")];
    config.credentials = vec![aws_cred(
        "https://*.amazonaws.com/*",
        &real_key,
        &real_secret,
        std::env::var("AWS_SESSION_TOKEN").ok().as_deref(),
    )];

    let mut server = pyloros::ProxyServer::new(config).unwrap();
    let addr = server.bind().await.unwrap().tcp_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });
    t.setup(format!("Proxy at {}", addr));

    // Run aws sts get-caller-identity. The agent uses the LOCAL keys; the
    // proxy verifies SigV4 with those, then re-signs with the real keys.
    let output = std::process::Command::new("aws")
        .args(["sts", "get-caller-identity"])
        .env("HTTPS_PROXY", format!("http://{}", addr))
        .env("AWS_CA_BUNDLE", &ca.cert_path)
        .env("AWS_ACCESS_KEY_ID", LOCAL_KEY_ID)
        .env("AWS_SECRET_ACCESS_KEY", LOCAL_SECRET)
        .env("AWS_DEFAULT_REGION", "us-east-1")
        .env_remove("AWS_SESSION_TOKEN")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    t.output("stdout", &stdout);
    t.output("stderr", &stderr);

    assert!(
        output.status.success(),
        "aws sts get-caller-identity failed (exit code {:?}):\nstdout: {}\nstderr: {}",
        output.status.code(),
        stdout,
        stderr
    );
    t.assert_contains("output has Account", &stdout, "Account");

    let _ = shutdown_tx.send(());
}
