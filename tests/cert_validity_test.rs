//! Certificate validity windows: both CA and per-host certificates are backdated, so a client
//! whose clock lags the proxy's still accepts them.

mod common;

use base64::Engine;
use common::TestCa;
use pyloros::GeneratedCa;
use std::process::Command;
use std::time::{Duration, SystemTime};

/// Read a certificate's notBefore/notAfter as seconds since the Unix epoch, via `openssl`.
fn validity_window(cert_pem: &str) -> (i64, i64) {
    let out = Command::new("openssl")
        .args(["x509", "-noout", "-dates", "-dateopt", "iso_8601"])
        .arg("-in")
        .arg("/dev/stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(cert_pem.as_bytes())?;
            child.wait_with_output()
        })
        .expect("openssl x509 -dates");
    assert!(out.status.success(), "openssl failed: {:?}", out);
    let text = String::from_utf8(out.stdout).unwrap();

    let field = |name: &str| -> i64 {
        let line = text
            .lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("no {name} in {text}"));
        let value = line.split_once('=').unwrap().1.trim();
        let out = Command::new("date")
            .args(["-u", "-d", value, "+%s"])
            .output()
            .expect("date");
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    };
    (field("notBefore"), field("notAfter"))
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
    let (cert_der, _, not_after) = ca.ca.generate_cert_for_host("example.com").unwrap();

    let b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
    let body: String = b64
        .as_bytes()
        .chunks(64)
        .map(|c| format!("{}\n", std::str::from_utf8(c).unwrap()))
        .collect();
    let pem = format!("-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n");

    let (not_before_secs, not_after_secs) = validity_window(&pem);
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
    let reported = not_after
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
    let (not_before_secs, not_after_secs) = validity_window(&generated.cert_pem);
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
    let (_, _, not_after) = ca.ca.generate_cert_for_host("example.com").unwrap();

    // The cache will serve a cert across a host suspend, so validity has to outlast one.
    t.assert_true(
        "cert issued now is still valid 60h later",
        not_after > SystemTime::now() + Duration::from_secs(60 * HOUR as u64),
    );
}
