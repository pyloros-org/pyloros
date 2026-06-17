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
