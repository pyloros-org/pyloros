mod common;

use bytes::Bytes;
use common::{
    ok_handler, read_audit_entries, rule, rule_with_body_log, ReportingClient, TestCa, TestProxy,
    TestUpstream,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response};
use std::sync::Arc;
use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// HTTPS body logging
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_body_logging_https() {
    let t = test_report!("Body logging captures request and response bodies for HTTPS");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("response-body-content"))
        .report(&t, "returns 'response-body-content'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_body_log("*", "https://localhost/*")],
        upstream.port(),
    )
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/api")
        .body("request-body-content")
        .send()
        .await
        .unwrap();
    t.assert_eq("status", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("response", &body.as_str(), &"response-body-content");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "event",
        &entries[0]["event"].as_str().unwrap(),
        &"request_allowed",
    );
    t.assert_eq(
        "request_body",
        &entries[0]["request_body"].as_str().unwrap(),
        &"request-body-content",
    );
    t.assert_eq(
        "response_body",
        &entries[0]["response_body"].as_str().unwrap(),
        &"response-body-content",
    );
    t.assert_true(
        "no request_body_encoding",
        entries[0]["request_body_encoding"].is_null(),
    );
    t.assert_true(
        "no response_body_encoding",
        entries[0]["response_body_encoding"].is_null(),
    );
    t.assert_true("no body_truncated", entries[0]["body_truncated"].is_null());

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Plain HTTP body logging
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_body_logging_plain_http() {
    let t = test_report!("Body logging captures request and response bodies for plain HTTP");
    let ca = TestCa::generate();

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("http-response-body"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_body_log("*", "http://localhost/*")],
        port,
    )
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let url = format!("http://localhost:{}/api", port);
    let resp = client
        .inner()
        .post(&url)
        .body("http-request-body")
        .send()
        .await
        .unwrap();
    t.assert_eq("status", &resp.status().as_u16(), &200u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "request_body",
        &entries[0]["request_body"].as_str().unwrap(),
        &"http-request-body",
    );
    t.assert_eq(
        "response_body",
        &entries[0]["response_body"].as_str().unwrap(),
        &"http-response-body",
    );

    proxy.shutdown();
}

// ---------------------------------------------------------------------------
// Body truncation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_body_logging_truncation() {
    let t = test_report!("Body logging truncates bodies exceeding max_body_log_size");
    let ca = TestCa::generate();

    // Create a 200-byte response body
    let large_response = "R".repeat(200);
    let handler: common::UpstreamHandler = {
        let body = large_response.clone();
        Arc::new(move |_req: Request<Incoming>| {
            let body = body.clone();
            Box::pin(async move {
                Ok(Response::builder()
                    .status(200)
                    .body(
                        Full::new(Bytes::from(body))
                            .map_err(|never: std::convert::Infallible| -> hyper::Error {
                                match never {}
                            })
                            .boxed(),
                    )
                    .unwrap())
            }) as common::UpstreamResponse
        })
    };
    let upstream = TestUpstream::builder(&ca, handler)
        .report(&t, "returns 200-byte body")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_body_log("*", "https://localhost/*")],
        upstream.port(),
    )
    .audit_log(audit_path_str)
    .max_body_log_size(100) // Only 100 bytes
    .report(&t)
    .start()
    .await;

    let large_request = "Q".repeat(200);
    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/api")
        .body(large_request.clone())
        .send()
        .await
        .unwrap();
    t.assert_eq("status", &resp.status().as_u16(), &200u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "body_truncated",
        &entries[0]["body_truncated"].as_bool().unwrap(),
        &true,
    );
    // Request body should be truncated to 100 bytes
    let req_body = entries[0]["request_body"].as_str().unwrap();
    t.assert_eq("request_body length", &req_body.len(), &100usize);
    // Response body should be truncated to 100 bytes
    let resp_body = entries[0]["response_body"].as_str().unwrap();
    t.assert_eq("response_body length", &resp_body.len(), &100usize);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Binary body base64 encoding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_body_logging_binary_base64() {
    let t = test_report!("Body logging encodes binary bodies as base64");
    let ca = TestCa::generate();

    // Create binary response (invalid UTF-8)
    let binary_response: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90];
    let handler: common::UpstreamHandler = {
        let body = binary_response.clone();
        Arc::new(move |_req: Request<Incoming>| {
            let body = body.clone();
            Box::pin(async move {
                Ok(Response::builder()
                    .status(200)
                    .body(
                        Full::new(Bytes::from(body))
                            .map_err(|never: std::convert::Infallible| -> hyper::Error {
                                match never {}
                            })
                            .boxed(),
                    )
                    .unwrap())
            }) as common::UpstreamResponse
        })
    };
    let upstream = TestUpstream::builder(&ca, handler)
        .report(&t, "returns binary body")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule_with_body_log("*", "https://localhost/*")],
        upstream.port(),
    )
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/binary")
        .body(vec![0xDE, 0xAD, 0xBE, 0xEF])
        .send()
        .await
        .unwrap();
    t.assert_eq("status", &resp.status().as_u16(), &200u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_eq(
        "request_body_encoding",
        &entries[0]["request_body_encoding"].as_str().unwrap(),
        &"base64",
    );
    t.assert_eq(
        "response_body_encoding",
        &entries[0]["response_body_encoding"].as_str().unwrap(),
        &"base64",
    );

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Default (no log_body) does not include body fields
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_no_body_logging_by_default() {
    let t = test_report!("Audit entries have no body fields when log_body is false");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello"))
        .report(&t, "returns 'hello'")
        .start()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_path_str = audit_path.to_str().unwrap();

    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .audit_log(audit_path_str)
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("status", &resp.status().as_u16(), &200u16);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = read_audit_entries(audit_path_str);
    t.assert_eq("entry count", &entries.len(), &1usize);
    t.assert_true("no request_body", entries[0]["request_body"].is_null());
    t.assert_true("no response_body", entries[0]["response_body"].is_null());
    t.assert_true("no body_truncated", entries[0]["body_truncated"].is_null());

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// encode_body unit tests
// ---------------------------------------------------------------------------

#[test]
fn test_encode_body_utf8() {
    let t = test_report!("encode_body returns UTF-8 for valid text");
    let (body, encoding, truncated) = pyloros::audit::encode_body(b"hello world", 1024);
    t.assert_eq("body", &body.as_str(), &"hello world");
    t.assert_true("no encoding", encoding.is_none());
    t.assert_true("not truncated", !truncated);
}

#[test]
fn test_encode_body_base64() {
    let t = test_report!("encode_body returns base64 for invalid UTF-8");
    let binary = vec![0xFF, 0xFE, 0x00, 0x01];
    let (body, encoding, truncated) = pyloros::audit::encode_body(&binary, 1024);
    t.assert_eq("encoding", &encoding.unwrap().as_str(), &"base64");
    t.assert_true("not truncated", !truncated);
    // Verify it's valid base64
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&body)
        .unwrap();
    t.assert_eq("decoded length", &decoded.len(), &4usize);
}

#[test]
fn test_encode_body_truncation() {
    let t = test_report!("encode_body truncates to max_size");
    let data = "a".repeat(100);
    let (body, encoding, truncated) = pyloros::audit::encode_body(data.as_bytes(), 50);
    t.assert_eq("body length", &body.len(), &50usize);
    t.assert_true("no encoding", encoding.is_none());
    t.assert_true("truncated", truncated);
}
