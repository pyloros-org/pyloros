//! Generated certificates must pass OpenSSL strict X.509 validation, which Python 3.12+
//! enables by default (`ssl.VERIFY_X509_STRICT`). Strict mode rejects certificates without
//! an Authority Key Identifier extension.

mod common;

use base64::Engine;
use common::TestCa;
use rustls::pki_types::PrivateKeyDer;
use std::process::Command;

fn pem(tag: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let body: String = b64
        .as_bytes()
        .chunks(64)
        .map(|c| format!("{}\n", std::str::from_utf8(c).unwrap()))
        .collect();
    format!("-----BEGIN {tag}-----\n{body}-----END {tag}-----\n")
}

#[test]
fn test_strict_x509_validation_accepts_generated_chain() {
    let t = test_report!("Python strict X.509 validation accepts a pyloros-issued cert");

    let ca = TestCa::generate();
    let (cert_der, key_der) = ca.ca.generate_cert_for_host("localhost").unwrap();
    let key_bytes = match &key_der {
        PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
        other => other.secret_der().to_vec(),
    };

    let leaf_crt = ca.dir.path().join("leaf.crt");
    let leaf_key = ca.dir.path().join("leaf.key");
    std::fs::write(&leaf_crt, pem("CERTIFICATE", cert_der.as_ref())).unwrap();
    std::fs::write(&leaf_key, pem("PRIVATE KEY", &key_bytes)).unwrap();

    t.action("Run TLS handshake with ssl.VERIFY_X509_STRICT enabled");
    let out = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/x509_strict_check.py"
        ))
        .arg(&ca.cert_path)
        .arg(&leaf_crt)
        .arg(&leaf_key)
        .output()
        .expect("python3 is required for this test");

    let stderr = String::from_utf8_lossy(&out.stderr);
    t.assert_true(
        &format!("strict handshake succeeded (stderr: {stderr})"),
        out.status.success(),
    );
}
