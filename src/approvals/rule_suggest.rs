//! Server-side TOML formatting and suggestion for `Rule` values.
//!
//! All TOML serialization of rules lives here so the schema stays
//! single-sourced (via serde + `toml::to_string`); the dashboard never
//! constructs TOML in JS.

use crate::audit::{AuditEntrySnapshot, AuditEvent, AuditGitInfo, AuditReason};
use crate::config::Rule;

/// Format a list of rules as `[[rules]]` TOML blocks. The wrapper
/// struct is required because `toml::to_string` only serializes
/// top-level tables, not bare arrays. Falls back to a
/// `# <serialization error>` comment if `toml::to_string` ever fails
/// (which it should not for any rule that round-trips through
/// `Rule::validate`).
pub fn format_rules_toml(rules: &[Rule]) -> String {
    #[derive(serde::Serialize)]
    struct RulesWrapper<'a> {
        rules: &'a [Rule],
    }
    match toml::to_string(&RulesWrapper { rules }) {
        Ok(s) => s,
        Err(e) => format!("# rule serialization error: {}\n", e),
    }
}

/// Format a single `Rule` as a `[[rules]]` TOML block.
pub fn format_rule_toml(rule: &Rule) -> String {
    format_rules_toml(std::slice::from_ref(rule))
}

/// Suggest TOML for a "create rule from blocked request" flow given a
/// recent blocked audit entry. Emits an exact-match `[[rules]]` block
/// plus a commented broader host-wildcard variant. For git-shaped
/// blocks the suggestion uses a `git = "..."` rule instead; for
/// `branch_restriction` blocks a commented `branches = [...]` line is
/// included so the user can opt into allowing the blocked refs.
pub fn suggest_for_audit_snapshot(entry: &AuditEntrySnapshot) -> String {
    // Permissive-toggle entries aren't request decisions, so there's
    // nothing meaningful to turn into a rule.
    if matches!(
        entry.event,
        AuditEvent::PermissiveEnabled | AuditEvent::PermissiveDisabled
    ) {
        return "# (no rule suggestion: this audit entry is a permissive-mode toggle, not a request)\n".to_string();
    }

    let url = entry.url.as_str();
    let method = entry.method.as_str();

    let git_op = detect_git_op(url, &entry.reason);
    if let Some(op) = git_op {
        return suggest_git(url, op, entry.git.as_ref(), &entry.reason);
    }

    // If we observed a redirect target for this request, pre-fill
    // `allow_redirects` with two alternatives: the exact target URL,
    // and a host-wildcard form. The first form is what serde emits;
    // the second is appended as a commented suggestion the user can
    // un-comment.
    let (allow_redirects_exact, allow_redirects_wildcard) = match entry.redirect_target.as_deref() {
        Some(t) => (vec![t.to_string()], Some(host_wildcard_for(t))),
        None => (Vec::new(), None),
    };
    let host_wildcard_url = host_wildcard_for(url);
    let exact = format_rule_toml(&Rule {
        method: Some(method.to_string()),
        url: url.to_string(),
        websocket: false,
        git: None,
        branches: None,
        allow_redirects: allow_redirects_exact.clone(),
        log_body: false,
    });

    let broader = format_rule_toml(&Rule {
        method: Some(method.to_string()),
        url: host_wildcard_url,
        websocket: false,
        git: None,
        branches: None,
        allow_redirects: allow_redirects_exact,
        log_body: false,
    });
    let broader_commented = comment_block(&broader);

    let mut out = format!("{}\n# Or, broader:\n{}", exact, broader_commented);
    if let Some(wild) = allow_redirects_wildcard {
        out.push_str(&format!(
            "\n# Or, broaden the redirect target to all paths on its host:\n# allow_redirects = [{:?}]\n",
            wild
        ));
    }
    out
}

fn suggest_git(
    url: &str,
    op: &'static str,
    git_info: Option<&AuditGitInfo>,
    reason: &AuditReason,
) -> String {
    // Strip git endpoint suffixes to get the repo URL.
    let repo_url = strip_git_suffix(url).to_string();
    let mut exact = Rule {
        method: None,
        url: repo_url.clone(),
        websocket: false,
        git: Some(op.to_string()),
        branches: None,
        allow_redirects: Vec::new(),
        log_body: false,
    };

    // If this was a branch_restriction block, surface the blocked refs
    // as a commented `branches = [...]` line.
    let blocked_refs = match (reason, git_info) {
        (AuditReason::BranchRestriction, Some(g)) => g.blocked_refs.clone(),
        _ => Vec::new(),
    };

    let exact_toml = format_rule_toml(&exact);
    let exact_with_branches = if blocked_refs.is_empty() {
        exact_toml
    } else {
        format!(
            "{}# branches = [{}]\n",
            exact_toml,
            blocked_refs
                .iter()
                .map(|b| format!("\"{}\"", b.replace('"', "\\\"")))
                .collect::<Vec<_>>()
                .join(", "),
        )
    };

    // Broader form: all repos on this host.
    exact.url = host_wildcard_for(&repo_url);
    let broader = comment_block(&format_rule_toml(&exact));

    format!(
        "{}\n# Or, broader (all repos on this host):\n{}",
        exact_with_branches, broader
    )
}

fn detect_git_op(url: &str, reason: &AuditReason) -> Option<&'static str> {
    if matches!(
        reason,
        AuditReason::BranchRestriction | AuditReason::LfsOperationNotAllowed
    ) {
        // For branch restrictions the original request was a
        // git-receive-pack (push); for LFS we use the conservative
        // "fetch" rule which covers reads.
        return Some(if matches!(reason, AuditReason::BranchRestriction) {
            "push"
        } else {
            "fetch"
        });
    }
    if url.ends_with("/git-receive-pack") {
        Some("push")
    } else if url.ends_with("/git-upload-pack") || url.contains("/info/refs") {
        Some("fetch")
    } else {
        None
    }
}

fn strip_git_suffix(url: &str) -> &str {
    // Strip the query string first so suffix matching works for endpoints
    // like `/info/refs?service=git-upload-pack`.
    let path = url.split_once('?').map(|(p, _)| p).unwrap_or(url);
    for suffix in [
        "/git-upload-pack",
        "/git-receive-pack",
        "/info/refs",
        "/info/lfs/objects/batch",
    ] {
        if let Some(prefix) = path.strip_suffix(suffix) {
            return prefix;
        }
    }
    path
}

fn host_wildcard_for(url: &str) -> String {
    // Parse out "scheme://host" prefix; everything after the host becomes "/*".
    if let Some(rest) = url.strip_prefix("https://") {
        if let Some(slash) = rest.find('/') {
            return format!("https://{}/*", &rest[..slash]);
        }
        return format!("https://{}/*", rest);
    }
    if let Some(rest) = url.strip_prefix("http://") {
        if let Some(slash) = rest.find('/') {
            return format!("http://{}/*", &rest[..slash]);
        }
        return format!("http://{}/*", rest);
    }
    url.to_string()
}

fn comment_block(toml_block: &str) -> String {
    toml_block
        .lines()
        .map(|l| {
            if l.is_empty() {
                "#\n".to_string()
            } else {
                format!("# {}\n", l)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Rule;
    use crate::filter::{FilterEngine, RequestInfo};
    use pyloros_test_support::test_report;

    struct Case {
        label: &'static str,
        method: &'static str,
        url: &'static str,
        reason: &'static str,
        req_path: &'static str,
        req_query: Option<&'static str>,
    }

    fn snapshot(c: &Case) -> AuditEntrySnapshot {
        serde_json::from_value(serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "event": "request_blocked",
            "method": c.method,
            "url": c.url,
            "host": "github.com",
            "scheme": "https",
            "protocol": "https",
            "decision": "blocked",
            "reason": c.reason,
        }))
        .expect("audit snapshot json should deserialize")
    }

    /// Parse the *active* (uncommented) `[[rules]]` blocks from a
    /// suggestion's TOML text. The broader host-wildcard variant and any
    /// branch hints are emitted as `#` comments, which the TOML parser
    /// ignores — so this yields exactly the rule the user would apply.
    fn parse_active_rules(toml_text: &str) -> Vec<Rule> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            #[serde(default)]
            rules: Vec<Rule>,
        }
        toml::from_str::<Wrapper>(toml_text)
            .expect("suggestion TOML should parse")
            .rules
    }

    /// Property: a rule the suggester proposes for a blocked request must,
    /// when applied, actually allow that request.
    #[test]
    fn test_suggested_rule_matches_original_request() {
        let t = test_report!("Suggested rule allows the request that triggered it");

        let cases = [
            Case {
                label: "git fetch discovery (info/refs?service=git-upload-pack)",
                method: "GET",
                url: "https://github.com/octocat/hello-world/info/refs?service=git-upload-pack",
                reason: "no_matching_rule",
                req_path: "/octocat/hello-world/info/refs",
                req_query: Some("service=git-upload-pack"),
            },
            Case {
                label: "git fetch verb pack (git-upload-pack)",
                method: "POST",
                url: "https://github.com/org/repo.git/git-upload-pack",
                reason: "no_matching_rule",
                req_path: "/org/repo.git/git-upload-pack",
                req_query: None,
            },
            Case {
                label: "git push verb pack (git-receive-pack)",
                method: "POST",
                url: "https://github.com/org/repo.git/git-receive-pack",
                reason: "no_matching_rule",
                req_path: "/org/repo.git/git-receive-pack",
                req_query: None,
            },
            Case {
                label: "plain HTTP request",
                method: "GET",
                url: "https://github.com/org/repo/raw/main/README.md",
                reason: "no_matching_rule",
                req_path: "/org/repo/raw/main/README.md",
                req_query: None,
            },
        ];

        for c in &cases {
            let toml_text = suggest_for_audit_snapshot(&snapshot(c));
            let rules = parse_active_rules(&toml_text);
            t.assert_true(
                &format!("{}: suggestion has an active rule", c.label),
                !rules.is_empty(),
            );

            let engine = FilterEngine::new(rules)
                .unwrap_or_else(|e| panic!("{}: engine build failed: {e}", c.label));
            let req = RequestInfo::http(
                c.method,
                "https",
                "github.com",
                None,
                c.req_path,
                c.req_query,
            );
            t.assert_true(
                &format!("{}: suggested rule allows the original request", c.label),
                engine.is_allowed(&req),
            );
        }
    }
}
