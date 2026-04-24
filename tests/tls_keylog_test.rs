mod common;

use common::{ok_handler, rule, ReportingClient, TestCa, TestProxy, TestUpstream};

/// When SSLKEYLOGFILE is set before the proxy starts, the MITM server side
/// writes TLS secrets in NSS Key Log Format so captures can be decrypted.
///
/// Note: cargo test runs test functions in the same binary on multiple threads,
/// and env vars are process-global. This test is the only one in its own test
/// binary (tests/tls_keylog_test.rs), so there's no in-binary race. The env var
/// is set once, never unset, and the path is a unique tempfile so parallel
/// binaries (if scheduled at the same time) can't collide.
#[tokio::test]
async fn keylog_written_when_sslkeylogfile_set() {
    let t = test_report!("SSLKEYLOGFILE captures TLS secrets during MITM");

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let keylog_path = tmp.path().to_path_buf();
    // Remove the temp file itself; rustls will create it fresh on first write.
    drop(tmp);

    // Must be set BEFORE MitmCertificateGenerator is constructed — rustls'
    // KeyLogFile reads the env var at construction time.
    // SAFETY: single-threaded at this point (no other test threads yet touching env).
    unsafe {
        std::env::set_var("SSLKEYLOGFILE", &keylog_path);
    }

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("hello"))
        .report(&t, "returns 'hello'")
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
    t.assert_eq("Response status", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();

    // Give rustls a moment to flush.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let contents = std::fs::read_to_string(&keylog_path)
        .expect("SSLKEYLOGFILE path should exist after a MITM handshake");

    t.assert_true("keylog file is non-empty", !contents.trim().is_empty());
    t.assert_true(
        "keylog contains NSS key-log-format entry",
        contents.lines().any(|line| {
            line.starts_with("CLIENT_RANDOM ")
                || line.starts_with("CLIENT_HANDSHAKE_TRAFFIC_SECRET ")
                || line.starts_with("SERVER_HANDSHAKE_TRAFFIC_SECRET ")
                || line.starts_with("CLIENT_TRAFFIC_SECRET_0 ")
                || line.starts_with("SERVER_TRAFFIC_SECRET_0 ")
                || line.starts_with("EXPORTER_SECRET ")
        }),
    );

    let _ = std::fs::remove_file(&keylog_path);
}
