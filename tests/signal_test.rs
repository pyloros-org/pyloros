//! Tests for signal handling (SIGINT, SIGTERM).
//!
//! Unix-only: these tests send POSIX signals to the proxy process.

#![cfg(unix)]

mod common;

use std::io::BufRead;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;
use wait_timeout::ChildExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawn the proxy binary, wait for it to start listening, return (child, port).
fn spawn_proxy(config_path: &Path) -> (std::process::Child, u16) {
    let bin = assert_cmd::cargo::cargo_bin!("pyloros");

    let mut child = Command::new(bin)
        .args(["run", "--config", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn pyloros binary");

    let stderr = child.stderr.take().expect("no stderr");
    let (tx, rx) = std::sync::mpsc::sync_channel::<u16>(1);

    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stderr);
        let mut sent = false;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if !sent {
                let clean = strip_ansi(&line);
                if let Some(idx) = clean.find("address=") {
                    let addr_str = clean[idx + "address=".len()..].trim();
                    if let Some(colon) = addr_str.rfind(':') {
                        if let Ok(port) = addr_str[colon + 1..].parse::<u16>() {
                            let _ = tx.send(port);
                            sent = true;
                        }
                    }
                }
            }
        }
    });

    let port = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("timed out waiting for proxy to print listening address");

    (child, port)
}

fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn write_minimal_config(dir: &Path, ca_cert: &str, ca_key: &str) -> std::path::PathBuf {
    let config_path = dir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"[proxy]
bind_address = "127.0.0.1:0"
ca_cert = "{ca_cert}"
ca_key = "{ca_key}"
"#
        ),
    )
    .unwrap();
    config_path
}

fn send_signal_and_wait(
    child: &mut std::process::Child,
    signal: libc::c_int,
) -> Option<std::process::ExitStatus> {
    unsafe {
        libc::kill(child.id() as libc::pid_t, signal);
    }
    child
        .wait_timeout(std::time::Duration::from_secs(5))
        .expect("error waiting for child")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn proxy_exits_cleanly_on_sigterm() {
    let t = test_report!("proxy exits cleanly on SIGTERM");

    let tmp = TempDir::new().unwrap();
    let bin = assert_cmd::cargo::cargo_bin!("pyloros");
    let output = Command::new(bin)
        .args(["generate-ca", "--out", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "generate-ca failed");

    let ca_cert = tmp.path().join("ca.crt").to_str().unwrap().to_string();
    let ca_key = tmp.path().join("ca.key").to_str().unwrap().to_string();
    let config_path = write_minimal_config(tmp.path(), &ca_cert, &ca_key);

    let (mut child, _port) = spawn_proxy(&config_path);

    let status = send_signal_and_wait(&mut child, libc::SIGTERM);
    let status = status.expect("proxy did not exit within 5s after SIGTERM");

    t.assert_true("Exit success (code 0)", status.success());
}

#[test]
fn proxy_exits_cleanly_on_sigint() {
    let t = test_report!("proxy exits cleanly on SIGINT");

    let tmp = TempDir::new().unwrap();
    let bin = assert_cmd::cargo::cargo_bin!("pyloros");
    let output = Command::new(bin)
        .args(["generate-ca", "--out", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "generate-ca failed");

    let ca_cert = tmp.path().join("ca.crt").to_str().unwrap().to_string();
    let ca_key = tmp.path().join("ca.key").to_str().unwrap().to_string();
    let config_path = write_minimal_config(tmp.path(), &ca_cert, &ca_key);

    let (mut child, _port) = spawn_proxy(&config_path);

    let status = send_signal_and_wait(&mut child, libc::SIGINT);
    let status = status.expect("proxy did not exit within 5s after SIGINT");

    t.assert_true("Exit success (code 0)", status.success());
}
