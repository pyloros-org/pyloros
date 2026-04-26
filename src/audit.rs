//! Structured JSONL audit logging for request decisions.

use serde::Serialize;
use std::path::Path;

/// Event type for an audit entry.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    RequestAllowed,
    RequestBlocked,
    RequestPermitted,
    AuthFailed,
}

/// Decision outcome.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allowed,
    Blocked,
}

/// Reason for the decision.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReason {
    RuleMatched,
    NoMatchingRule,
    BodyInspectionRequiresHttps,
    BranchRestriction,
    LfsOperationNotAllowed,
    NonHttpsConnect,
    AuthFailed,
    LocalCredentialMismatch,
    /// Request was allowed because its URL is in the short-lived redirect whitelist
    /// (i.e., an earlier rule-matched request returned a 3xx Location pointing here).
    RedirectWhitelisted,
}

/// Credential info attached to an audit entry.
#[derive(Debug, Clone, Serialize)]
pub struct AuditCredential {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub url_pattern: String,
}

/// Git-specific info attached to an audit entry.
#[derive(Debug, Clone, Serialize)]
pub struct AuditGitInfo {
    pub blocked_refs: Vec<String>,
}

/// A single audit log entry.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub event: AuditEvent,
    pub method: String,
    pub url: String,
    pub host: String,
    pub scheme: String,
    pub protocol: String,
    pub decision: AuditDecision,
    pub reason: AuditReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<AuditCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<AuditGitInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_truncated: Option<bool>,
}

/// Encode a body for inclusion in an audit entry.
///
/// Returns `(encoded_body, encoding, truncated)` where encoding is `None`
/// for valid UTF-8 or `Some("base64")` for binary data.
pub fn encode_body(bytes: &[u8], max_size: usize) -> (String, Option<String>, bool) {
    let truncated = bytes.len() > max_size;
    let slice = if truncated { &bytes[..max_size] } else { bytes };
    match std::str::from_utf8(slice) {
        Ok(s) => (s.to_string(), None, truncated),
        Err(_) => {
            use base64::Engine;
            (
                base64::engine::general_purpose::STANDARD.encode(slice),
                Some("base64".to_string()),
                truncated,
            )
        }
    }
}

/// Returns the current UTC time as an ISO 8601 / RFC 3339 string.
pub fn now_iso8601() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Audit logger that writes JSONL entries to a file.
///
/// Uses `std::fs::File` with a `std::sync::Mutex` since writes are small
/// and fast, avoiding the need for tokio's `fs` feature.
pub struct AuditLogger {
    writer: std::sync::Mutex<std::io::BufWriter<std::fs::File>>,
}

impl AuditLogger {
    /// Open (or create) the audit log file in append mode.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            writer: std::sync::Mutex::new(std::io::BufWriter::new(file)),
        })
    }

    /// Write an audit entry as a JSON line. Errors are logged but never propagated.
    pub fn log(&self, entry: &AuditEntry) {
        use std::io::Write;
        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize audit entry");
                return;
            }
        };

        let mut writer = match self.writer.lock() {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "Failed to lock audit log writer");
                return;
            }
        };
        if let Err(e) = writeln!(writer, "{}", json) {
            tracing::error!(error = %e, "Failed to write audit entry");
            return;
        }
        if let Err(e) = writer.flush() {
            tracing::error!(error = %e, "Failed to flush audit log");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    #[test]
    fn test_audit_entry_serialization() {
        let t = test_report!("AuditEntry serializes to valid JSON");
        let entry = AuditEntry {
            timestamp: "2026-02-09T14:30:00Z".to_string(),
            event: AuditEvent::RequestAllowed,
            method: "GET".to_string(),
            url: "https://api.example.com/v1/data".to_string(),
            host: "api.example.com".to_string(),
            scheme: "https".to_string(),
            protocol: "https".to_string(),
            decision: AuditDecision::Allowed,
            reason: AuditReason::RuleMatched,
            credential: None,
            git: None,
            request_body: None,
            request_body_encoding: None,
            response_body: None,
            response_body_encoding: None,
            body_truncated: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        t.assert_contains("has event", &json, "\"event\":\"request_allowed\"");
        t.assert_contains("has decision", &json, "\"decision\":\"allowed\"");
        t.assert_contains("has reason", &json, "\"reason\":\"rule_matched\"");
        // Verify it's valid JSON by parsing it back
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        t.assert_eq("method", &parsed["method"].as_str().unwrap(), &"GET");
    }

    #[test]
    fn test_optional_fields_omitted_when_none() {
        let t = test_report!("Optional fields omitted from JSON when None");
        let entry = AuditEntry {
            timestamp: "2026-02-09T14:30:00Z".to_string(),
            event: AuditEvent::RequestBlocked,
            method: "POST".to_string(),
            url: "https://blocked.example.com/".to_string(),
            host: "blocked.example.com".to_string(),
            scheme: "https".to_string(),
            protocol: "https".to_string(),
            decision: AuditDecision::Blocked,
            reason: AuditReason::NoMatchingRule,
            credential: None,
            git: None,
            request_body: None,
            request_body_encoding: None,
            response_body: None,
            response_body_encoding: None,
            body_truncated: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        t.assert_true("no credential field", !json.contains("\"credential\""));
        t.assert_true("no git field", !json.contains("\"git\""));
    }

    #[test]
    fn test_optional_fields_present_when_some() {
        let t = test_report!("Optional fields present in JSON when Some");
        let entry = AuditEntry {
            timestamp: "2026-02-09T14:30:00Z".to_string(),
            event: AuditEvent::RequestAllowed,
            method: "POST".to_string(),
            url: "https://github.com/org/repo/git-receive-pack".to_string(),
            host: "github.com".to_string(),
            scheme: "https".to_string(),
            protocol: "https".to_string(),
            decision: AuditDecision::Blocked,
            reason: AuditReason::BranchRestriction,
            credential: Some(AuditCredential {
                cred_type: "header".to_string(),
                url_pattern: "https://github.com/*".to_string(),
            }),
            git: Some(AuditGitInfo {
                blocked_refs: vec!["refs/heads/main".to_string()],
            }),
            request_body: None,
            request_body_encoding: None,
            response_body: None,
            response_body_encoding: None,
            body_truncated: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        t.assert_eq(
            "credential type",
            &parsed["credential"]["type"].as_str().unwrap(),
            &"header",
        );
        t.assert_eq(
            "credential url_pattern",
            &parsed["credential"]["url_pattern"].as_str().unwrap(),
            &"https://github.com/*",
        );
        t.assert_eq(
            "blocked_refs[0]",
            &parsed["git"]["blocked_refs"][0].as_str().unwrap(),
            &"refs/heads/main",
        );
    }

    #[test]
    fn test_now_iso8601_format() {
        let t = test_report!("now_iso8601 returns valid RFC 3339 timestamp");
        let ts = now_iso8601();
        // RFC 3339 timestamps contain 'T' and end with 'Z' for UTC
        t.assert_contains("contains T", &ts, "T");
        t.assert_true("ends with Z", ts.ends_with('Z'));
        // Should be parseable
        let parsed =
            time::OffsetDateTime::parse(&ts, &time::format_description::well_known::Rfc3339);
        t.assert_true("parses as RFC 3339", parsed.is_ok());
    }

    #[test]
    fn test_all_event_variants_serialize() {
        let t = test_report!("All AuditEvent variants serialize correctly");
        let allowed = serde_json::to_string(&AuditEvent::RequestAllowed).unwrap();
        let blocked = serde_json::to_string(&AuditEvent::RequestBlocked).unwrap();
        let permitted = serde_json::to_string(&AuditEvent::RequestPermitted).unwrap();
        let auth = serde_json::to_string(&AuditEvent::AuthFailed).unwrap();
        t.assert_eq("allowed", &allowed.as_str(), &"\"request_allowed\"");
        t.assert_eq("blocked", &blocked.as_str(), &"\"request_blocked\"");
        t.assert_eq("permitted", &permitted.as_str(), &"\"request_permitted\"");
        t.assert_eq("auth_failed", &auth.as_str(), &"\"auth_failed\"");
    }

    #[test]
    fn test_all_reason_variants_serialize() {
        let t = test_report!("All AuditReason variants serialize correctly");
        let reasons = vec![
            (AuditReason::RuleMatched, "\"rule_matched\""),
            (AuditReason::NoMatchingRule, "\"no_matching_rule\""),
            (
                AuditReason::BodyInspectionRequiresHttps,
                "\"body_inspection_requires_https\"",
            ),
            (AuditReason::BranchRestriction, "\"branch_restriction\""),
            (
                AuditReason::LfsOperationNotAllowed,
                "\"lfs_operation_not_allowed\"",
            ),
            (AuditReason::NonHttpsConnect, "\"non_https_connect\""),
            (AuditReason::AuthFailed, "\"auth_failed\""),
            (
                AuditReason::LocalCredentialMismatch,
                "\"local_credential_mismatch\"",
            ),
        ];
        for (reason, expected) in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            t.assert_eq(&format!("{:?}", reason), &json.as_str(), &expected);
        }
    }

    #[test]
    fn test_audit_logger_writes_jsonl() {
        let t = test_report!("AuditLogger writes valid JSONL to file");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let logger = AuditLogger::open(&path).unwrap();
        let entry = AuditEntry {
            timestamp: "2026-02-09T14:30:00Z".to_string(),
            event: AuditEvent::RequestAllowed,
            method: "GET".to_string(),
            url: "https://example.com/test".to_string(),
            host: "example.com".to_string(),
            scheme: "https".to_string(),
            protocol: "https".to_string(),
            decision: AuditDecision::Allowed,
            reason: AuditReason::RuleMatched,
            credential: None,
            git: None,
            request_body: None,
            request_body_encoding: None,
            response_body: None,
            response_body_encoding: None,
            body_truncated: None,
        };
        logger.log(&entry);

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        t.assert_eq("one line", &lines.len(), &1usize);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        t.assert_eq("method", &parsed["method"].as_str().unwrap(), &"GET");
    }
}
