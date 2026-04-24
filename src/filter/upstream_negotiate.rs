//! Sidecar want/have negotiation against the upstream git server.
//!
//! When the local pack walk in `src/filter/pack.rs` can't confirm a protected-ref
//! push is a fast-forward (thin pack, empty pack, or pack that doesn't contain
//! `old-sha`'s descendant chain), we fall through to this module. It issues a
//! git protocol v2 `fetch` command (`want=new-sha` + `have=old-sha`, no `done`)
//! against the upstream `POST <repo>/git-upload-pack` endpoint. The server is
//! the authoritative source on its own commit graph and tells us whether
//! `old-sha` is reachable from `new-sha`:
//!
//! - `acknowledgments` → `ACK <have>` → fast-forward (the have is a common
//!   ancestor of the want; server confirmed by reachability walk).
//! - `acknowledgments` → `NAK` → no common ancestor; this is a real force-push.
//! - Anything else (transport error, HTTP error, unparseable response) → fail
//!   closed: caller blocks the push.
//!
//! This module is HTTP-transport agnostic: request construction and response
//! parsing are pure functions, unit-tested here. The HTTP round-trip lives in
//! `src/proxy/tunnel.rs` where the proxy's upstream TLS/host plumbing already
//! exists.

use super::pktline::format_pktline;

/// Outcome of the upstream want/have check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AncestryCheck {
    /// Upstream confirmed `old-sha` is reachable from `new-sha`.
    /// This is a fast-forward; the push should be allowed.
    Acked,
    /// Upstream returned NAK: no common ancestor. This is a force-push;
    /// the push should be blocked.
    Nak,
    /// Transport, HTTP, or parse failure. Caller blocks (fail closed).
    /// The string is a short, loggable reason.
    Error(String),
}

/// Build the request body for a git protocol v2 `fetch` with a single
/// `want`/`have` pair. Bytes are pkt-line encoded and form a complete
/// `POST /git-upload-pack` body.
///
/// Note: we intentionally do **not** send a `done` line. Per the v2 spec,
/// sending `done` tells the server to skip the `acknowledgments` section
/// and go straight to sending a packfile — which defeats the point of this
/// check (we only want the ACK/NAK, not the pack). Omitting `done` makes
/// the server emit `acknowledgments` first, which is all we read before
/// closing the connection.
pub fn build_v2_fetch_body(want: &[u8; 20], have: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend(format_pktline(b"command=fetch\n"));
    // Advertise sha1 as the object format; harmless if server doesn't care.
    out.extend(format_pktline(b"object-format=sha1\n"));
    // Delim-pkt separates the capability list from command args in v2.
    out.extend(b"0001");
    let want_line = format!("want {}\n", hex_encode(want));
    out.extend(format_pktline(want_line.as_bytes()));
    let have_line = format!("have {}\n", hex_encode(have));
    out.extend(format_pktline(have_line.as_bytes()));
    out.extend(b"0000"); // flush-pkt (terminates request; no `done`)
    out
}

/// Parse a git protocol v2 `fetch` response body, returning the ancestry check
/// outcome based on the `acknowledgments` section.
///
/// - If any `ACK <sha>` line appears → `Acked` (the have is reachable from the
///   want).
/// - If `NAK` appears without any ACK → `Nak` (no common ancestor).
/// - If the response cannot be parsed as pkt-lines, or the `acknowledgments`
///   section is missing entirely → `Error` (caller fails closed).
///
/// Note: a `ready` line may follow ACKs; we don't require it. `ACK` alone is
/// sufficient — the server never ACKs a have unless it is reachable from the
/// want.
pub fn parse_fetch_response(body: &[u8]) -> AncestryCheck {
    let mut pos = 0;
    let mut in_ack_section = false;
    let mut saw_ack = false;
    let mut saw_nak = false;
    let mut saw_ack_section_header = false;

    while pos + 4 <= body.len() {
        let len_str = match std::str::from_utf8(&body[pos..pos + 4]) {
            Ok(s) => s,
            Err(_) => return AncestryCheck::Error("non-ascii pkt-line length".into()),
        };

        // Flush or delim-pkt: section boundary.
        if len_str == "0000" {
            if in_ack_section {
                // End of acknowledgments section.
                break;
            }
            pos += 4;
            continue;
        }
        if len_str == "0001" {
            if in_ack_section {
                break;
            }
            pos += 4;
            continue;
        }

        let pkt_len = match usize::from_str_radix(len_str, 16) {
            Ok(n) => n,
            Err(_) => return AncestryCheck::Error("bad pkt-line length".into()),
        };
        if pkt_len < 4 || pos + pkt_len > body.len() {
            return AncestryCheck::Error("truncated pkt-line".into());
        }

        let raw = &body[pos + 4..pos + pkt_len];
        pos += pkt_len;

        let content = match std::str::from_utf8(raw) {
            Ok(s) => s.trim_end_matches('\n'),
            Err(_) => continue, // binary section header for packfile, ignored
        };

        if !in_ack_section {
            if content == "acknowledgments" {
                in_ack_section = true;
                saw_ack_section_header = true;
            }
            // Otherwise: capability lines, preamble — ignore.
            continue;
        }

        // In acknowledgments section.
        if content.starts_with("ACK ") {
            saw_ack = true;
        } else if content == "NAK" {
            saw_nak = true;
        } else if content == "ready" {
            // A `ready` line without any preceding ACK shouldn't happen, but
            // treat it as confirmation that a common ancestor was found.
            saw_ack = true;
        }
        // Ignore anything else inside the section.
    }

    if !saw_ack_section_header {
        return AncestryCheck::Error("no acknowledgments section in response".into());
    }
    if saw_ack {
        AncestryCheck::Acked
    } else if saw_nak {
        AncestryCheck::Nak
    } else {
        AncestryCheck::Error("acknowledgments section without ACK or NAK".into())
    }
}

fn hex_encode(bytes: &[u8; 20]) -> String {
    let mut s = String::with_capacity(40);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    #[test]
    fn test_build_v2_fetch_body_structure() {
        let t = test_report!("v2 fetch body has command, delim, want, have, flush (no `done`)");
        let want = [0xaau8; 20];
        let have = [0xbbu8; 20];
        let body = build_v2_fetch_body(&want, &have);
        let s = std::str::from_utf8(&body).unwrap();

        t.assert_contains("command=fetch", s, "command=fetch\n");
        t.assert_contains("has delim", s, "0001");
        t.assert_contains("want", s, "want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        t.assert_contains("have", s, "have bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        t.assert_not_contains("no `done` (would skip acknowledgments)", s, "done\n");
        t.assert_true("ends with flush-pkt", s.ends_with("0000"));
    }

    /// Hand-craft a v2 acknowledgments response.
    fn make_v2_response(lines: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(format_pktline(b"acknowledgments\n"));
        for l in lines {
            let payload = format!("{}\n", l);
            out.extend(format_pktline(payload.as_bytes()));
        }
        out.extend(b"0000");
        out
    }

    #[test]
    fn test_parse_ack_ready() {
        let t = test_report!("ACK + ready -> Acked");
        let body = make_v2_response(&["ACK aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ready"]);
        t.assert_eq(
            "ACK ready is Acked",
            &parse_fetch_response(&body),
            &AncestryCheck::Acked,
        );
    }

    #[test]
    fn test_parse_ack_only() {
        let t = test_report!("Plain ACK without ready -> Acked");
        let body = make_v2_response(&["ACK aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
        t.assert_eq(
            "ACK is Acked",
            &parse_fetch_response(&body),
            &AncestryCheck::Acked,
        );
    }

    #[test]
    fn test_parse_nak() {
        let t = test_report!("NAK -> Nak");
        let body = make_v2_response(&["NAK"]);
        t.assert_eq(
            "NAK is Nak",
            &parse_fetch_response(&body),
            &AncestryCheck::Nak,
        );
    }

    #[test]
    fn test_parse_missing_section() {
        let t = test_report!("No acknowledgments section -> Error");
        // Just a flush pkt.
        let result = parse_fetch_response(b"0000");
        match result {
            AncestryCheck::Error(_) => {}
            other => panic!("expected Error, got {:?}", other),
        }
        t.assert_true("missing section is Error", true);
    }

    #[test]
    fn test_parse_empty_section() {
        let t = test_report!("acknowledgments section with no ACK/NAK -> Error");
        let mut body = Vec::new();
        body.extend(format_pktline(b"acknowledgments\n"));
        body.extend(b"0000");
        match parse_fetch_response(&body) {
            AncestryCheck::Error(_) => {}
            other => panic!("expected Error, got {:?}", other),
        }
        t.assert_true("empty section is Error", true);
    }

    #[test]
    fn test_parse_truncated_pkt() {
        let t = test_report!("Truncated pkt-line -> Error");
        let result = parse_fetch_response(b"00ffnot enough");
        match result {
            AncestryCheck::Error(_) => {}
            other => panic!("expected Error, got {:?}", other),
        }
        t.assert_true("truncated is Error", true);
    }

    #[test]
    fn test_parse_preamble_before_acks() {
        let t = test_report!("Capability pkt-lines before acknowledgments are skipped");
        let mut body = Vec::new();
        // Some servers send a capability/banner pkt-line before the section header.
        body.extend(format_pktline(b"some-capability=yes\n"));
        body.extend(format_pktline(b"acknowledgments\n"));
        body.extend(format_pktline(b"NAK\n"));
        body.extend(b"0000");
        t.assert_eq(
            "NAK still recognized",
            &parse_fetch_response(&body),
            &AncestryCheck::Nak,
        );
    }
}
