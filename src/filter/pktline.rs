//! Git pkt-line format parser for branch restriction enforcement.
//!
//! The git push protocol sends ref update commands in pkt-line format before
//! the pack data. Each command line has the form:
//!
//! ```text
//! <old-sha> <new-sha> <refname>\0<capabilities>\n   (first line)
//! <old-sha> <new-sha> <refname>\n                   (subsequent lines)
//! ```
//!
//! Lines are prefixed with a 4-hex-digit length. The sequence ends with a
//! flush packet (`0000`). We only need to read the pkt-line prefix to extract
//! ref names for branch checking.

use std::collections::HashSet;

use super::matcher::PatternMatcher;

/// Format a pkt-line with 4-hex-digit length prefix.
pub fn format_pktline(content: &[u8]) -> Vec<u8> {
    let len = content.len() + 4;
    let mut result = format!("{:04x}", len).into_bytes();
    result.extend_from_slice(content);
    result
}

/// Format a sideband pkt-line (band byte + content, wrapped in pkt-line framing).
pub fn format_sideband_pktline(band: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len() + 5; // 4-byte length prefix + 1-byte band
    let mut result = format!("{:04x}", len).into_bytes();
    result.push(band);
    result.extend_from_slice(content);
    result
}

/// Extract capabilities from the first pkt-line's NUL-delimited suffix.
///
/// In git push protocol, the first command line has capabilities appended
/// after a NUL byte: `<old-sha> <new-sha> <refname>\0cap1 cap2 cap3\n`
///
/// Returns a set of capability names (e.g. `"report-status"`, `"side-band-64k"`).
pub fn extract_capabilities(data: &[u8]) -> HashSet<String> {
    let mut caps = HashSet::new();
    let pos = 0;

    // We only need the first pkt-line
    if pos + 4 > data.len() {
        return caps;
    }

    let len_str = match std::str::from_utf8(&data[pos..pos + 4]) {
        Ok(s) => s,
        Err(_) => return caps,
    };

    if len_str == "0000" {
        return caps;
    }

    let pkt_len = match usize::from_str_radix(len_str, 16) {
        Ok(n) => n,
        Err(_) => return caps,
    };

    if pkt_len < 4 || pos + pkt_len > data.len() {
        return caps;
    }

    let content = &data[pos + 4..pos + pkt_len];

    // Strip trailing newline
    let content = if content.last() == Some(&b'\n') {
        &content[..content.len() - 1]
    } else {
        content
    };

    let line = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return caps,
    };

    // Capabilities are after the NUL byte
    if let Some(nul_pos) = line.find('\0') {
        let cap_str = &line[nul_pos + 1..];
        for cap in cap_str.split(' ') {
            if !cap.is_empty() {
                caps.insert(cap.to_string());
            }
        }
    }

    caps
}

/// Return the list of refs that DON'T match any of the given branch patterns.
///
/// Like `check_push_branches` but returns blocked ref names instead of a boolean.
pub fn blocked_refs(data: &[u8], patterns: &[PatternMatcher]) -> Vec<String> {
    let refs = extract_push_refs(data);
    refs.into_iter()
        .filter(|refname| !ref_matches_any_pattern(refname, patterns))
        .collect()
}

/// Return the list of refs blocked by a `BranchFilter` (allow + deny patterns).
///
/// A ref is blocked if:
/// - It matches any deny pattern, OR
/// - The allow list is non-empty and the ref doesn't match any allow pattern.
///
/// If the allow list is empty, all refs are implicitly allowed (before deny check).
pub fn blocked_refs_with_filter(data: &[u8], filter: &super::rules::BranchFilter) -> Vec<String> {
    let refs = extract_push_refs(data);
    refs.into_iter()
        .filter(|refname| {
            // Denied if matches any deny pattern
            if ref_matches_any_pattern(refname, &filter.deny) {
                return true;
            }
            // If allow list is non-empty, must match at least one allow pattern
            if !filter.allow.is_empty() && !ref_matches_any_pattern(refname, &filter.allow) {
                return true;
            }
            false
        })
        .collect()
}

/// Build a git `report-status` response body for blocked refs.
///
/// Constructs a valid receive-pack result that git clients will parse and
/// display as per-ref errors, similar to server-side pre-receive hook rejections.
///
/// The response format depends on client capabilities:
/// - `report-status` + `side-band-64k`: sideband-framed response with stderr message
/// - `report-status` only: plain report-status lines
/// - Neither: fallback to sideband-only message or empty
pub fn build_receive_pack_error(
    blocked: &[String],
    message: &str,
    capabilities: &HashSet<String>,
) -> Vec<u8> {
    let has_report_status =
        capabilities.contains("report-status") || capabilities.contains("report-status-v2");
    let has_sideband = capabilities.contains("side-band-64k");

    if has_report_status && has_sideband {
        build_sideband_report_status(blocked, message)
    } else if has_report_status {
        build_plain_report_status(blocked)
    } else if has_sideband {
        // Sideband-only fallback: send message on band 2 (stderr)
        let mut result = Vec::new();
        let stderr_msg = format!("pyloros: {}\n", message);
        result.extend(format_sideband_pktline(2, stderr_msg.as_bytes()));
        result.extend(b"0000");
        result
    } else {
        // No report-status or sideband: can't communicate error through protocol.
        // Return empty body (git will see an error from the HTTP side).
        Vec::new()
    }
}

/// Build a sideband-framed report-status response.
///
/// Band 2: stderr message (displayed to user)
/// Band 1: report-status data (unpack ok + ng lines + flush)
/// Outer flush
fn build_sideband_report_status(blocked: &[String], message: &str) -> Vec<u8> {
    let mut result = Vec::new();

    // Band 2: stderr message (displayed to user as "remote: ...")
    let stderr_msg = format!("pyloros: {}\n", message);
    result.extend(format_sideband_pktline(2, stderr_msg.as_bytes()));

    // Build the entire report-status buffer (inner pkt-lines + inner flush)
    let mut report = Vec::new();
    report.extend(format_pktline(b"unpack ok\n"));
    for refname in blocked {
        let ng_line = format!("ng {} blocked by proxy policy\n", refname);
        report.extend(format_pktline(ng_line.as_bytes()));
    }
    report.extend(b"0000"); // inner flush (part of report-status)

    // Band 1: entire report-status buffer as one sideband packet
    result.extend(format_sideband_pktline(1, &report));

    // Outer flush (terminates sideband stream)
    result.extend(b"0000");

    result
}

/// Build a plain (non-sideband) report-status response.
fn build_plain_report_status(blocked: &[String]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend(format_pktline(b"unpack ok\n"));
    for refname in blocked {
        let ng_line = format!("ng {} blocked by proxy policy\n", refname);
        result.extend(format_pktline(ng_line.as_bytes()));
    }
    result.extend(b"0000");
    result
}

/// Extract ref names from git push pkt-line data.
///
/// Reads pkt-lines until the flush packet (`0000`), parsing each command
/// line to extract the ref name (third space-separated field, before any
/// NUL-delimited capabilities).
///
/// Returns the list of ref names being pushed (e.g. `refs/heads/main`).
pub fn extract_push_refs(data: &[u8]) -> Vec<String> {
    let mut refs = Vec::new();
    let mut pos = 0;

    while pos + 4 <= data.len() {
        // Read 4-hex-digit length
        let len_str = match std::str::from_utf8(&data[pos..pos + 4]) {
            Ok(s) => s,
            Err(_) => break,
        };

        // Flush packet
        if len_str == "0000" {
            break;
        }

        let pkt_len = match usize::from_str_radix(len_str, 16) {
            Ok(n) => n,
            Err(_) => break,
        };

        if pkt_len < 4 || pos + pkt_len > data.len() {
            break;
        }

        // The pkt-line content (excluding the 4-byte length prefix)
        let content = &data[pos + 4..pos + pkt_len];

        // Parse: "<old-sha> <new-sha> <refname>[\0capabilities][\n]"
        if let Some(refname) = parse_ref_from_command(content) {
            refs.push(refname);
        }

        pos += pkt_len;
    }

    refs
}

/// Parse a single command line to extract the ref name.
fn parse_ref_from_command(content: &[u8]) -> Option<String> {
    // Strip trailing newline if present
    let content = if content.last() == Some(&b'\n') {
        &content[..content.len() - 1]
    } else {
        content
    };

    // Convert to string (command lines are ASCII)
    let line = std::str::from_utf8(content).ok()?;

    // Strip capabilities after NUL
    let line = line.split('\0').next().unwrap_or(line);

    // Split by spaces: old-sha, new-sha, refname
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() == 3 {
        Some(parts[2].to_string())
    } else {
        None
    }
}

/// Check if all push refs match the given branch patterns.
///
/// - Bare patterns (not starting with `refs/`) match against `refs/heads/<pattern>`.
/// - Patterns starting with `refs/` are matched literally.
/// - Returns `true` if all refs are allowed, `false` if any ref is disallowed.
/// - If no refs are found in the data, returns `true` (nothing to block).
pub fn check_push_branches(data: &[u8], patterns: &[PatternMatcher]) -> bool {
    let refs = extract_push_refs(data);
    if refs.is_empty() {
        return true;
    }

    for refname in &refs {
        if !ref_matches_any_pattern(refname, patterns) {
            return false;
        }
    }

    true
}

/// Check if a single ref matches any of the given branch patterns.
fn ref_matches_any_pattern(refname: &str, patterns: &[PatternMatcher]) -> bool {
    for pattern in patterns {
        let pat = pattern.pattern();
        if pat.starts_with("refs/") {
            // Literal ref pattern — match directly
            if pattern.matches(refname) {
                return true;
            }
        } else {
            // Bare branch pattern — only matches refs under refs/heads/
            let branch_name = match refname.strip_prefix("refs/heads/") {
                Some(name) => name,
                None => continue, // Non-branch refs don't match bare patterns
            };
            let full_ref = format!("refs/heads/{}", branch_name);
            let full_pattern = format!("refs/heads/{}", pat);
            // We need to create a temporary PatternMatcher for the full pattern
            if let Ok(full_matcher) = PatternMatcher::new(&full_pattern) {
                if full_matcher.matches(&full_ref) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    /// Build a pkt-line from a string (adds 4-hex-digit length prefix).
    fn pktline(content: &str) -> Vec<u8> {
        let len = content.len() + 4; // content + 4-byte length prefix
        format!("{:04x}{}", len, content).into_bytes()
    }

    /// Flush packet.
    fn flush() -> Vec<u8> {
        b"0000".to_vec()
    }

    #[test]
    fn test_extract_single_ref() {
        let t = test_report!("Extract single ref from push data");
        let mut data = Vec::new();
        data.extend(pktline(
            "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/main\n",
        ));
        data.extend(flush());

        let refs = extract_push_refs(&data);
        t.assert_eq("ref count", &refs.len(), &1usize);
        t.assert_eq("ref name", &refs[0].as_str(), &"refs/heads/main");
    }

    #[test]
    fn test_extract_multiple_refs() {
        let t = test_report!("Extract multiple refs from push data");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/main\0report-status\n",
            old, new
        )));
        data.extend(pktline(&format!(
            "{} {} refs/heads/feature/test\n",
            old, new
        )));
        data.extend(flush());

        let refs = extract_push_refs(&data);
        t.assert_eq("ref count", &refs.len(), &2usize);
        t.assert_eq("ref[0]", &refs[0].as_str(), &"refs/heads/main");
        t.assert_eq("ref[1]", &refs[1].as_str(), &"refs/heads/feature/test");
    }

    #[test]
    fn test_extract_ref_with_capabilities() {
        let t = test_report!("Capabilities stripped from first pkt-line");
        let mut data = Vec::new();
        data.extend(pktline(
            "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/dev\0report-status delete-refs ofs-delta\n",
        ));
        data.extend(flush());

        let refs = extract_push_refs(&data);
        t.assert_eq("ref count", &refs.len(), &1usize);
        t.assert_eq("ref name", &refs[0].as_str(), &"refs/heads/dev");
    }

    #[test]
    fn test_extract_empty_data() {
        let t = test_report!("Empty data returns no refs");
        let refs = extract_push_refs(b"0000");
        t.assert_eq("ref count", &refs.len(), &0usize);
    }

    #[test]
    fn test_extract_flush_only() {
        let t = test_report!("Flush-only data returns no refs");
        let refs = extract_push_refs(b"0000");
        t.assert_eq("ref count", &refs.len(), &0usize);
    }

    #[test]
    fn test_check_branches_allowed() {
        let t = test_report!("Branch check allows matching refs");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/feature/test\n",
            old, new
        )));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        t.assert_true(
            "feature/test allowed",
            check_push_branches(&data, &patterns),
        );
    }

    #[test]
    fn test_check_branches_blocked() {
        let t = test_report!("Branch check blocks non-matching refs");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!("{} {} refs/heads/main\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        t.assert_true("main blocked", !check_push_branches(&data, &patterns));
    }

    #[test]
    fn test_check_branches_mixed_blocked() {
        let t = test_report!("Branch check blocks when any ref is disallowed");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/feature/ok\0report-status\n",
            old, new
        )));
        data.extend(pktline(&format!("{} {} refs/heads/main\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        t.assert_true(
            "mixed refs blocked (main not allowed)",
            !check_push_branches(&data, &patterns),
        );
    }

    #[test]
    fn test_check_branches_tag_blocked() {
        let t = test_report!("Tags blocked when only branch patterns specified");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!("{} {} refs/tags/v1.0\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        t.assert_true("tag blocked", !check_push_branches(&data, &patterns));
    }

    #[test]
    fn test_check_branches_refs_prefix_pattern() {
        let t = test_report!("refs/ prefixed pattern matches literally");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!("{} {} refs/tags/v1.0\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("refs/tags/*").unwrap()];
        t.assert_true(
            "tag allowed by refs/ pattern",
            check_push_branches(&data, &patterns),
        );
    }

    #[test]
    fn test_check_branches_empty_data() {
        let t = test_report!("Empty push data passes branch check");
        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        t.assert_true(
            "empty data allowed",
            check_push_branches(b"0000", &patterns),
        );
    }

    #[test]
    fn test_check_branches_multiple_patterns() {
        let t = test_report!("Multiple branch patterns (OR matching)");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/fix/bug-123\n",
            old, new
        )));
        data.extend(flush());

        let patterns = vec![
            PatternMatcher::new("feature/*").unwrap(),
            PatternMatcher::new("fix/*").unwrap(),
        ];
        t.assert_true(
            "fix/ matches second pattern",
            check_push_branches(&data, &patterns),
        );
    }

    // --- Tests for extract_capabilities ---

    #[test]
    fn test_extract_capabilities_with_caps() {
        let t = test_report!("Extract capabilities from first pkt-line");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/main\0report-status side-band-64k delete-refs\n",
            old, new
        )));
        data.extend(flush());

        let caps = extract_capabilities(&data);
        t.assert_true("has report-status", caps.contains("report-status"));
        t.assert_true("has side-band-64k", caps.contains("side-band-64k"));
        t.assert_true("has delete-refs", caps.contains("delete-refs"));
        t.assert_eq("cap count", &caps.len(), &3usize);
    }

    #[test]
    fn test_extract_capabilities_without_caps() {
        let t = test_report!("No capabilities when NUL absent");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!("{} {} refs/heads/main\n", old, new)));
        data.extend(flush());

        let caps = extract_capabilities(&data);
        t.assert_eq("empty caps", &caps.len(), &0usize);
    }

    #[test]
    fn test_extract_capabilities_empty_data() {
        let t = test_report!("Empty data returns no capabilities");
        let caps = extract_capabilities(b"0000");
        t.assert_eq("empty caps", &caps.len(), &0usize);
    }

    // --- Tests for blocked_refs ---

    #[test]
    fn test_blocked_refs_all_blocked() {
        let t = test_report!("blocked_refs returns all refs when none match");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/main\0report-status\n",
            old, new
        )));
        data.extend(pktline(&format!("{} {} refs/heads/develop\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        let blocked = blocked_refs(&data, &patterns);
        t.assert_eq("blocked count", &blocked.len(), &2usize);
        t.assert_true(
            "main blocked",
            blocked.contains(&"refs/heads/main".to_string()),
        );
        t.assert_true(
            "develop blocked",
            blocked.contains(&"refs/heads/develop".to_string()),
        );
    }

    #[test]
    fn test_blocked_refs_partial() {
        let t = test_report!("blocked_refs returns only non-matching refs");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/feature/ok\0report-status\n",
            old, new
        )));
        data.extend(pktline(&format!("{} {} refs/heads/main\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        let blocked = blocked_refs(&data, &patterns);
        t.assert_eq("blocked count", &blocked.len(), &1usize);
        t.assert_eq("blocked ref", &blocked[0].as_str(), &"refs/heads/main");
    }

    #[test]
    fn test_blocked_refs_none_blocked() {
        let t = test_report!("blocked_refs returns empty when all match");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/feature/a\0report-status\n",
            old, new
        )));
        data.extend(pktline(&format!("{} {} refs/heads/feature/b\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        let blocked = blocked_refs(&data, &patterns);
        t.assert_eq("blocked count", &blocked.len(), &0usize);
    }

    // --- Boundary tests for extract_capabilities ---

    #[test]
    fn test_extract_capabilities_short_data() {
        let t = test_report!("extract_capabilities with 0-3 bytes returns empty");
        t.assert_eq("0 bytes", &extract_capabilities(b"").len(), &0usize);
        t.assert_eq("1 byte", &extract_capabilities(b"0").len(), &0usize);
        t.assert_eq("2 bytes", &extract_capabilities(b"00").len(), &0usize);
        t.assert_eq("3 bytes", &extract_capabilities(b"000").len(), &0usize);
    }

    #[test]
    fn test_extract_capabilities_pktlen_too_small() {
        let t = test_report!("extract_capabilities with pkt_len < 4 returns empty");
        // "0003" means pkt_len=3, which is below minimum 4
        let caps = extract_capabilities(b"0003abc");
        t.assert_eq("empty caps", &caps.len(), &0usize);
        // "0001" means pkt_len=1
        let caps = extract_capabilities(b"0001x");
        t.assert_eq("pkt_len=1 empty", &caps.len(), &0usize);
    }

    #[test]
    fn test_extract_capabilities_pktlen_exceeds_data() {
        let t = test_report!("extract_capabilities with pkt_len exceeding data returns empty");
        // "0010" = 16 bytes, but only 8 bytes of data after length prefix
        let caps = extract_capabilities(b"0010abcd");
        t.assert_eq("empty caps", &caps.len(), &0usize);
    }

    #[test]
    fn test_extract_capabilities_exact_fit() {
        let t = test_report!("extract_capabilities parses packet that fills buffer exactly");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // Build a single pkt-line with capabilities, NO trailing flush
        let content = format!(
            "{} {} refs/heads/main\0report-status side-band-64k\n",
            old, new
        );
        let data = format!("{:04x}{}", content.len() + 4, content);
        let caps = extract_capabilities(data.as_bytes());
        t.assert_true("has report-status", caps.contains("report-status"));
        t.assert_true("has side-band-64k", caps.contains("side-band-64k"));
        t.assert_eq("cap count", &caps.len(), &2usize);
    }

    #[test]
    fn test_extract_capabilities_minimal_packet() {
        let t = test_report!("extract_capabilities with pkt_len=4 (empty content) returns empty");
        // "0004" means pkt_len=4, content is empty (just length prefix)
        let caps = extract_capabilities(b"0004");
        t.assert_eq("empty caps", &caps.len(), &0usize);
    }

    // --- Boundary tests for extract_push_refs ---

    #[test]
    fn test_extract_push_refs_short_data() {
        let t = test_report!("extract_push_refs with 0-3 bytes returns empty");
        t.assert_eq("0 bytes", &extract_push_refs(b"").len(), &0usize);
        t.assert_eq("1 byte", &extract_push_refs(b"0").len(), &0usize);
        t.assert_eq("2 bytes", &extract_push_refs(b"00").len(), &0usize);
        t.assert_eq("3 bytes", &extract_push_refs(b"000").len(), &0usize);
    }

    #[test]
    fn test_extract_push_refs_pktlen_too_small() {
        let t = test_report!("extract_push_refs with pkt_len < 4 returns empty");
        // "0003" means pkt_len=3
        let refs = extract_push_refs(b"0003abc");
        t.assert_eq("empty refs", &refs.len(), &0usize);
    }

    #[test]
    fn test_extract_push_refs_pktlen_exceeds_data() {
        let t = test_report!("extract_push_refs with pkt_len exceeding data returns empty");
        // "0020" = 32 bytes, but only 8 bytes total
        let refs = extract_push_refs(b"0020abcd");
        t.assert_eq("empty refs", &refs.len(), &0usize);
    }

    #[test]
    fn test_extract_push_refs_exact_fit_no_flush() {
        let t =
            test_report!("extract_push_refs parses packet that fills buffer exactly (no flush)");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // Build a single pkt-line without trailing flush
        let content = format!("{} {} refs/heads/main\n", old, new);
        let data = format!("{:04x}{}", content.len() + 4, content);
        let refs = extract_push_refs(data.as_bytes());
        t.assert_eq("ref count", &refs.len(), &1usize);
        t.assert_eq("ref name", &refs[0].as_str(), &"refs/heads/main");
    }

    // --- Tests for format_pktline ---

    #[test]
    fn test_format_pktline() {
        let t = test_report!("format_pktline produces correct length prefix");
        let result = format_pktline(b"unpack ok\n");
        // "unpack ok\n" = 10 bytes, + 4 = 14 = 0x000e
        t.assert_eq(
            "pktline",
            &String::from_utf8_lossy(&result).to_string(),
            &"000eunpack ok\n".to_string(),
        );
    }

    #[test]
    fn test_format_sideband_pktline() {
        let t = test_report!("format_sideband_pktline wraps content with band byte");
        let result = format_sideband_pktline(2, b"hello\n");
        // "hello\n" = 6 bytes, + 1 band + 4 prefix = 11 = 0x000b
        t.assert_eq(
            "length prefix",
            &String::from_utf8_lossy(&result[..4]).to_string(),
            &"000b".to_string(),
        );
        t.assert_eq("band byte", &result[4], &2u8);
        t.assert_eq(
            "content",
            &String::from_utf8_lossy(&result[5..]).to_string(),
            &"hello\n".to_string(),
        );
    }

    // --- Tests for build_receive_pack_error ---

    #[test]
    fn test_build_error_with_sideband_and_report_status() {
        let t = test_report!("build_receive_pack_error with sideband + report-status");
        let blocked = vec!["refs/heads/main".to_string()];
        let mut caps = HashSet::new();
        caps.insert("report-status".to_string());
        caps.insert("side-band-64k".to_string());

        let result = build_receive_pack_error(
            &blocked,
            "push to branch 'main' blocked by proxy policy",
            &caps,
        );

        let result_str = String::from_utf8_lossy(&result);
        // Should contain the stderr message on band 2
        t.assert_true("contains message", result_str.contains("pyloros:"));
        // Should contain unpack ok and ng in the band 1 data
        t.assert_true("contains unpack ok", result_str.contains("unpack ok"));
        t.assert_true(
            "contains ng line",
            result_str.contains("ng refs/heads/main blocked by proxy policy"),
        );
        // Should end with flush
        t.assert_true("ends with flush", result_str.ends_with("0000"));
    }

    #[test]
    fn test_build_error_with_report_status_only() {
        let t = test_report!("build_receive_pack_error with report-status only (no sideband)");
        let blocked = vec!["refs/heads/main".to_string()];
        let mut caps = HashSet::new();
        caps.insert("report-status".to_string());

        let result = build_receive_pack_error(&blocked, "push blocked", &caps);
        let result_str = String::from_utf8_lossy(&result);

        // Plain report-status format
        t.assert_true("contains unpack ok", result_str.contains("unpack ok"));
        t.assert_true(
            "contains ng",
            result_str.contains("ng refs/heads/main blocked by proxy policy"),
        );
        t.assert_true("ends with flush", result_str.ends_with("0000"));
        // Should NOT contain band bytes or stderr message
        t.assert_true("no pyloros prefix", !result_str.contains("pyloros:"));
    }

    #[test]
    fn test_build_error_no_report_status() {
        let t = test_report!("build_receive_pack_error with no capabilities");
        let blocked = vec!["refs/heads/main".to_string()];
        let caps = HashSet::new();

        let result = build_receive_pack_error(&blocked, "push blocked", &caps);
        t.assert_eq("empty result", &result.len(), &0usize);
    }

    #[test]
    fn test_build_error_multiple_blocked_refs() {
        let t = test_report!("build_receive_pack_error with multiple blocked refs");
        let blocked = vec![
            "refs/heads/main".to_string(),
            "refs/heads/develop".to_string(),
        ];
        let mut caps = HashSet::new();
        caps.insert("report-status".to_string());

        let result = build_receive_pack_error(&blocked, "push blocked", &caps);
        let result_str = String::from_utf8_lossy(&result);

        t.assert_true(
            "contains ng for main",
            result_str.contains("ng refs/heads/main blocked by proxy policy"),
        );
        t.assert_true(
            "contains ng for develop",
            result_str.contains("ng refs/heads/develop blocked by proxy policy"),
        );
    }

    #[test]
    fn test_build_error_with_report_status_v2() {
        let t = test_report!("build_receive_pack_error recognizes report-status-v2");
        let blocked = vec!["refs/heads/main".to_string()];
        let mut caps = HashSet::new();
        caps.insert("report-status-v2".to_string());
        caps.insert("side-band-64k".to_string());

        let result = build_receive_pack_error(
            &blocked,
            "push to branch 'main' blocked by proxy policy",
            &caps,
        );

        let result_str = String::from_utf8_lossy(&result);
        // Should produce sideband-wrapped report-status (same as v1)
        t.assert_true("contains message", result_str.contains("pyloros:"));
        t.assert_true("contains unpack ok", result_str.contains("unpack ok"));
        t.assert_true(
            "contains ng line",
            result_str.contains("ng refs/heads/main blocked by proxy policy"),
        );
        t.assert_true("ends with flush", result_str.ends_with("0000"));
    }

    // --- Tests for blocked_refs_with_filter ---

    fn make_branch_filter(allow: &[&str], deny: &[&str]) -> super::super::rules::BranchFilter {
        super::super::rules::BranchFilter {
            allow: allow
                .iter()
                .map(|p| PatternMatcher::new(p).unwrap())
                .collect(),
            deny: deny
                .iter()
                .map(|p| PatternMatcher::new(p).unwrap())
                .collect(),
        }
    }

    fn make_push_data(refs: &[&str]) -> Vec<u8> {
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut data = Vec::new();
        for (i, refname) in refs.iter().enumerate() {
            if i == 0 {
                data.extend(pktline(&format!(
                    "{} {} {}\0report-status side-band-64k\n",
                    old, new, refname
                )));
            } else {
                data.extend(pktline(&format!("{} {} {}\n", old, new, refname)));
            }
        }
        data.extend(flush());
        data
    }

    #[test]
    fn test_branch_filter_deny_blocks_matching() {
        let t = test_report!("BranchFilter deny pattern blocks matching refs");
        let data = make_push_data(&["refs/heads/main"]);
        let filter = make_branch_filter(&["*"], &["main"]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("blocked count", &blocked.len(), &1usize);
        t.assert_eq("blocked ref", &blocked[0].as_str(), &"refs/heads/main");
    }

    #[test]
    fn test_branch_filter_deny_allows_non_matching() {
        let t = test_report!("BranchFilter deny pattern allows non-matching refs");
        let data = make_push_data(&["refs/heads/feature/test"]);
        let filter = make_branch_filter(&["*"], &["main"]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("blocked count", &blocked.len(), &0usize);
    }

    #[test]
    fn test_branch_filter_deny_wins_over_allow() {
        let t = test_report!("BranchFilter deny wins when ref matches both allow and deny");
        let data = make_push_data(&["refs/heads/feature/dangerous"]);
        let filter = make_branch_filter(&["feature/*"], &["feature/dangerous"]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("blocked count", &blocked.len(), &1usize);
        t.assert_eq(
            "blocked ref",
            &blocked[0].as_str(),
            &"refs/heads/feature/dangerous",
        );
    }

    #[test]
    fn test_branch_filter_deny_only_implicit_allow_all() {
        let t = test_report!("BranchFilter with only deny patterns implicitly allows all others");
        let data = make_push_data(&["refs/heads/feature/ok", "refs/heads/main"]);
        let filter = make_branch_filter(&[], &["main"]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("blocked count", &blocked.len(), &1usize);
        t.assert_eq("blocked ref", &blocked[0].as_str(), &"refs/heads/main");
    }

    #[test]
    fn test_branch_filter_deny_wildcard() {
        let t = test_report!("BranchFilter deny wildcard pattern blocks matching refs");
        let data = make_push_data(&[
            "refs/heads/release/1.0",
            "refs/heads/release/2.0",
            "refs/heads/feature/ok",
        ]);
        let filter = make_branch_filter(&["*"], &["release/*"]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("blocked count", &blocked.len(), &2usize);
        t.assert_true(
            "release/1.0 blocked",
            blocked.contains(&"refs/heads/release/1.0".to_string()),
        );
        t.assert_true(
            "release/2.0 blocked",
            blocked.contains(&"refs/heads/release/2.0".to_string()),
        );
    }

    #[test]
    fn test_branch_filter_empty_data() {
        let t = test_report!("BranchFilter with empty push data returns empty");
        let filter = make_branch_filter(&["*"], &["main"]);
        let blocked = blocked_refs_with_filter(b"0000", &filter);
        t.assert_eq("blocked count", &blocked.len(), &0usize);
    }

    #[test]
    fn test_branch_filter_no_deny_patterns() {
        let t = test_report!("BranchFilter with no deny patterns behaves like allow-only");
        let data = make_push_data(&["refs/heads/feature/test", "refs/heads/main"]);
        let filter = make_branch_filter(&["feature/*"], &[]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("blocked count", &blocked.len(), &1usize);
        t.assert_eq("blocked ref", &blocked[0].as_str(), &"refs/heads/main");
    }

    #[test]
    fn test_branch_filter_deny_blocks_full_ref() {
        let t = test_report!("Bare deny !main blocks refs/heads/main (full ref form)");
        let data = make_push_data(&["refs/heads/main"]);
        let filter = make_branch_filter(&["*"], &["main"]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("blocked count", &blocked.len(), &1usize);
        t.assert_eq("blocked ref", &blocked[0].as_str(), &"refs/heads/main");
    }

    #[test]
    fn test_branch_filter_deny_cannot_bypass_via_tag_ref() {
        let t = test_report!("Cannot bypass !main deny by pushing to refs/tags/main");
        let data = make_push_data(&["refs/tags/main"]);
        // branches = ["*", "!main"] — bare * only matches refs/heads/,
        // so refs/tags/main has no allow match and is blocked
        let filter = make_branch_filter(&["*"], &["main"]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("blocked count", &blocked.len(), &1usize);
        t.assert_eq("blocked ref", &blocked[0].as_str(), &"refs/tags/main");
    }

    #[test]
    fn test_branch_filter_deny_cannot_bypass_via_arbitrary_ref() {
        let t = test_report!("Cannot bypass !main deny by pushing to refs/for/main");
        let data = make_push_data(&["refs/for/main"]);
        let filter = make_branch_filter(&["*"], &["main"]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("blocked count", &blocked.len(), &1usize);
        t.assert_eq("blocked ref", &blocked[0].as_str(), &"refs/for/main");
    }

    #[test]
    fn test_branch_filter_refs_prefix_deny_blocks_literally() {
        let t = test_report!("refs/-prefixed deny pattern !refs/tags/* blocks tags");
        let data = make_push_data(&["refs/tags/v1.0", "refs/heads/main"]);
        // Allow all branches, deny all tags
        let filter = make_branch_filter(&["*"], &["refs/tags/*"]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("blocked count", &blocked.len(), &1usize);
        t.assert_eq("blocked ref", &blocked[0].as_str(), &"refs/tags/v1.0");
    }

    #[test]
    fn test_bare_allow_only_matches_branches() {
        let t = test_report!("Bare allow pattern * only matches refs/heads/ refs");
        // Push a tag — bare * should NOT match it
        let data = make_push_data(&["refs/tags/v1.0"]);
        let filter = make_branch_filter(&["*"], &[]);
        let blocked = blocked_refs_with_filter(&data, &filter);
        t.assert_eq("tag blocked (no allow match)", &blocked.len(), &1usize);
    }
}
