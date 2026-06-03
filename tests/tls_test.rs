//! Integration tests for TLS certificate generation

#[path = "common/mod.rs"]
mod common;

use common::TestReport;
use pyloros::tls::{CertificateAuthority, GeneratedCa, MitmCertificateGenerator};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Reported wrappers
// ---------------------------------------------------------------------------

fn generate_ca_reported(t: &TestReport) -> GeneratedCa {
    t.action("Generate CA");
    GeneratedCa::generate().unwrap()
}

fn load_ca_from_pem_reported(t: &TestReport, ca: &GeneratedCa) -> CertificateAuthority {
    t.action("Load CA from PEM");
    CertificateAuthority::from_pem(&ca.cert_pem, &ca.key_pem).unwrap()
}

fn load_ca_from_files_reported(
    t: &TestReport,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> CertificateAuthority {
    t.action("Load CA from files");
    CertificateAuthority::from_files(cert_path, key_path).unwrap()
}

fn generate_cert_reported(
    t: &TestReport,
    ca: &CertificateAuthority,
    host: &str,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    t.action(format!("Generate cert for {}", host));
    ca.generate_cert_for_host(host).unwrap()
}

fn create_mitm_reported(t: &TestReport, ca: CertificateAuthority) -> MitmCertificateGenerator {
    t.action("Create MITM generator");
    MitmCertificateGenerator::new(ca)
}

fn get_cert_reported(t: &TestReport, generator: &MitmCertificateGenerator, host: &str) {
    t.action(format!("Get cert for {}", host));
    let _ = generator.get_cert_for_host(host).unwrap();
}

fn server_config_reported(
    t: &TestReport,
    generator: &MitmCertificateGenerator,
    host: &str,
) -> rustls::ServerConfig {
    t.action(format!("Create server config for {}", host));
    generator.server_config_for_host(host).unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_ca_generation() {
    let t = test_report!("CA certificate generation");

    let ca = generate_ca_reported(&t);

    t.assert_contains(
        "Cert PEM has BEGIN CERTIFICATE",
        &ca.cert_pem,
        "BEGIN CERTIFICATE",
    );
    t.assert_contains(
        "Cert PEM has END CERTIFICATE",
        &ca.cert_pem,
        "END CERTIFICATE",
    );
    t.assert_contains(
        "Key PEM has BEGIN PRIVATE KEY",
        &ca.key_pem,
        "BEGIN PRIVATE KEY",
    );
    t.assert_contains(
        "Key PEM has END PRIVATE KEY",
        &ca.key_pem,
        "END PRIVATE KEY",
    );
}

#[test]
fn test_ca_save_and_load() {
    let t = test_report!("CA save to disk and reload");

    let generated = generate_ca_reported(&t);

    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("test_ca.crt");
    let key_path = dir.path().join("test_ca.key");

    t.action(format!("Save CA to {}", dir.path().display()));
    generated.save(&cert_path, &key_path).unwrap();

    t.assert_true("cert file exists", cert_path.exists());
    t.assert_true("key file exists", key_path.exists());

    let ca = load_ca_from_files_reported(&t, &cert_path, &key_path);

    let (cert_der, key_der) = generate_cert_reported(&t, &ca, "test.example.com");
    t.assert_true("cert DER not empty", !cert_der.is_empty());
    t.assert_true("key DER not empty", !key_der.secret_der().is_empty());
}

#[test]
fn test_host_certificate_generation() {
    let t = test_report!("Per-host certificate generation");

    let generated = generate_ca_reported(&t);
    let ca = load_ca_from_pem_reported(&t, &generated);

    let hosts = [
        "example.com",
        "api.example.com",
        "sub.domain.example.com",
        "localhost",
        "my-service.internal",
    ];

    for host in hosts {
        let (cert_der, key_der) = generate_cert_reported(&t, &ca, host);
        t.assert_true(
            &format!("cert for {} not empty", host),
            !cert_der.is_empty(),
        );
        t.assert_true(
            &format!("key for {} not empty", host),
            !key_der.secret_der().is_empty(),
        );
    }
}

#[test]
fn test_mitm_generator_caching() {
    let t = test_report!("MITM generator caches certificates");

    let generated = generate_ca_reported(&t);
    let ca = load_ca_from_pem_reported(&t, &generated);
    let generator = create_mitm_reported(&t, ca);

    t.assert_eq("Initial cache size", &generator.cache_size(), &0usize);

    get_cert_reported(&t, &generator, "example.com");
    t.assert_eq(
        "Cache size after first host",
        &generator.cache_size(),
        &1usize,
    );

    get_cert_reported(&t, &generator, "example.com");
    t.assert_eq("Cache size unchanged", &generator.cache_size(), &1usize);

    get_cert_reported(&t, &generator, "other.com");
    t.assert_eq(
        "Cache size after second host",
        &generator.cache_size(),
        &2usize,
    );
}

#[test]
fn test_mitm_generator_cache_capacity() {
    let t = test_report!("MITM generator evicts oldest when cache full");

    let generated = generate_ca_reported(&t);
    let ca = load_ca_from_pem_reported(&t, &generated);

    t.action("Create MITM generator with capacity=2");
    let generator = MitmCertificateGenerator::with_cache(ca, 2, Duration::from_secs(3600));

    get_cert_reported(&t, &generator, "one.com");
    get_cert_reported(&t, &generator, "two.com");
    t.assert_eq("Cache full at 2", &generator.cache_size(), &2usize);

    get_cert_reported(&t, &generator, "three.com");
    t.assert_eq(
        "Cache still at capacity 2",
        &generator.cache_size(),
        &2usize,
    );
}

#[test]
fn test_server_config_generation() {
    let t = test_report!("Server TLS config with ALPN protocols");

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let generated = generate_ca_reported(&t);
    let ca = load_ca_from_pem_reported(&t, &generated);
    let generator = create_mitm_reported(&t, ca);

    let config = server_config_reported(&t, &generator, "example.com");

    t.assert_eq(
        "ALPN protocols",
        &config.alpn_protocols,
        &vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    );
}

#[test]
fn test_ca_cert_der() {
    let t = test_report!("CA DER export not empty");

    let generated = generate_ca_reported(&t);
    let ca = load_ca_from_pem_reported(&t, &generated);
    let generator = create_mitm_reported(&t, ca);

    let ca_der = generator.ca_cert_der();
    t.assert_true("CA DER not empty", !ca_der.is_empty());
}

#[test]
fn test_invalid_ca_pem() {
    let t = test_report!("Invalid CA PEM rejected");

    t.action("Load invalid PEM data");
    let result = CertificateAuthority::from_pem("not a cert", "not a key");
    t.assert_true("from_pem returns error", result.is_err());
}

#[test]
fn test_file_not_found() {
    let t = test_report!("Non-existent CA files rejected");

    t.action("Load from /nonexistent/ca.crt");
    let result = CertificateAuthority::from_files("/nonexistent/ca.crt", "/nonexistent/ca.key");
    t.assert_true("from_files returns error", result.is_err());
}
