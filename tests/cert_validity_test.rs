//! Certificate validity windows: both CA and per-host certificates are backdated, so a client
//! whose clock lags the proxy's still accepts them.

mod common;

use common::TestCa;
use pyloros::{CertificateAuthority, GeneratedCa};
use rustls::pki_types::CertificateDer;
use std::time::{Duration, SystemTime};

/// A certificate's notBefore/notAfter, as seconds since the Unix epoch.
fn validity_window(cert_der: &CertificateDer<'_>) -> (i64, i64) {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).expect("parse cert");
    let validity = cert.validity();
    (
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    )
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

const HOUR: i64 = 3600;
const DAY: i64 = 24 * HOUR;
/// Wall-clock slack for the test itself, not for the certificate.
const SLOP: i64 = 5 * 60;

#[test]
fn test_host_cert_is_backdated_and_long_lived() {
    let t = test_report!("Per-host certs are backdated 1h and valid for 30 days");

    let ca = TestCa::generate();
    let issued = ca.ca.generate_cert_for_host("example.com").unwrap();

    let (not_before_secs, not_after_secs) = validity_window(&issued.cert);
    let now = now_secs();

    t.assert_true(
        "notBefore is at least 1h in the past",
        not_before_secs <= now - HOUR + SLOP,
    );
    t.assert_true(
        "notBefore is not backdated absurdly far",
        not_before_secs >= now - HOUR - SLOP,
    );
    t.assert_true(
        "notAfter is ~30 days out",
        (not_after_secs - (now + 30 * DAY - HOUR)).abs() <= SLOP,
    );

    // The not_after handed back for caching must be the certificate's own, not a second
    // independently computed deadline: the cache's expiry check is only meaningful if they agree.
    let reported = issued
        .not_after
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    t.assert_eq(
        "returned not_after matches the certificate's notAfter",
        &reported,
        &not_after_secs,
    );
}

#[test]
fn test_ca_cert_is_backdated() {
    let t = test_report!("CA certs are backdated 1h and valid for 10 years");

    let generated = GeneratedCa::generate().unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
    let (not_before_secs, not_after_secs) = validity_window(ca.cert_der());
    let now = now_secs();

    t.assert_true(
        "notBefore is at least 1h in the past",
        not_before_secs <= now - HOUR + SLOP,
    );
    t.assert_true(
        "notAfter is ~10 years out",
        (not_after_secs - (now + 3650 * DAY - HOUR)).abs() <= SLOP,
    );
}

#[test]
fn test_host_cert_outlives_a_long_host_suspend() {
    let t = test_report!("Host cert validity exceeds a long host suspend");

    let ca = TestCa::generate();
    let issued = ca.ca.generate_cert_for_host("example.com").unwrap();

    // The cache will serve a cert across a host suspend, so validity has to outlast one.
    t.assert_true(
        "cert issued now is still valid 60h later",
        issued.not_after > SystemTime::now() + Duration::from_secs(60 * HOUR as u64),
    );
}
