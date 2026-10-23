//! Rule-subsumption check for the approvals dedup optimization (I4).
//!
//! If the proposed rules for an approval are already covered by the
//! active ruleset, we can skip the human round-trip and return
//! `approved` immediately. The probe works by synthesizing one or more
//! representative concrete URLs from each proposed rule and running
//! them through the current FilterEngine.
//!
//! For plain method rules one probe suffices. For git rules we probe
//! every smart-HTTP endpoint the rule expands to, so dedup only
//! short-circuits when the active ruleset really covers the full git
//! operation — not just the info/refs preamble.

use crate::config::Rule;
use crate::filter::{FilterEngine, FilterResult, RequestInfo};

use super::types::TriggeredBy;

#[derive(Debug, Clone)]
struct Probe {
    method: String,
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    websocket: bool,
}

impl Probe {
    fn run(&self, engine: &FilterEngine) -> bool {
        let info = if self.websocket {
            RequestInfo::websocket(
                &self.scheme,
                &self.host,
                self.port,
                &self.path,
                self.query.as_deref(),
            )
        } else {
            RequestInfo::http(
                &self.method,
                &self.scheme,
                &self.host,
                self.port,
                &self.path,
                self.query.as_deref(),
            )
        };
        // Only a plain `Allowed` attests full coverage: a covering rule that
        // demands branch or LFS body inspection may still block the request.
        matches!(engine.check(&info), FilterResult::Allowed { .. })
    }
}

/// True iff every rule in `proposed_rules` is already allowed by the
/// current `engine`. Rules we can't construct probes from (wildcard
/// host, malformed URL) are treated as "not subsumed" — when in doubt,
/// ask the human.
///
/// If `triggered_by` is present, its URL is used as the (single) probe
/// for the first proposed rule when that rule is plain method-based.
/// Git rules ignore `triggered_by` because one endpoint isn't enough
/// to attest coverage of all the smart-HTTP endpoints they expand to.
///
/// A proposal carrying `allow_redirects`, `branches` or `log_body` asks
/// for behaviour an allow/block probe cannot attest, so it is never
/// subsumed — those go to the human even when the method+URL is already
/// allowed.
pub fn all_subsumed(
    engine: &FilterEngine,
    proposed_rules: &[Rule],
    triggered_by: Option<&TriggeredBy>,
) -> bool {
    if proposed_rules.is_empty() {
        return false;
    }
    for (i, rule) in proposed_rules.iter().enumerate() {
        if !rule.allow_redirects.is_empty() || rule.branches.is_some() || rule.log_body {
            return false;
        }
        let probes = if i == 0 && rule.git.is_none() {
            triggered_by
                .and_then(|tb| probe_from_triggered_by(tb, rule.websocket))
                .map(|p| vec![p])
                .or_else(|| probes_from_rule(rule))
        } else {
            probes_from_rule(rule)
        };
        let Some(probes) = probes else {
            return false;
        };
        if probes.is_empty() {
            return false;
        }
        for p in &probes {
            if !p.run(engine) {
                return false;
            }
        }
    }
    true
}

fn probe_from_triggered_by(tb: &TriggeredBy, websocket: bool) -> Option<Probe> {
    let url = url::Url::parse(&tb.url).ok()?;
    Some(Probe {
        method: tb.method.clone(),
        scheme: url.scheme().to_string(),
        host: url.host_str()?.to_string(),
        port: url.port(),
        path: url.path().to_string(),
        query: url.query().map(|q| q.to_string()),
        websocket,
    })
}

/// Synthesize the set of probes that must all pass for `rule` to be
/// considered subsumed. Returns `None` if the rule can't be parsed
/// into at least one concrete probe (wildcard host, missing scheme).
fn probes_from_rule(rule: &Rule) -> Option<Vec<Probe>> {
    let (scheme, host, port, base_path) = parse_url(&rule.url)?;

    if let Some(op) = rule.git.as_deref() {
        return Some(probes_for_git(op, &scheme, &host, port, &base_path));
    }

    let probe_method = match rule.method.as_deref() {
        None | Some("*") | Some("") => "GET".to_string(),
        Some(m) => m.to_string(),
    };
    let path = base_path.replace('*', "x");
    Some(vec![Probe {
        method: probe_method,
        scheme,
        host,
        port,
        path,
        query: None,
        websocket: rule.websocket,
    }])
}

/// Parse `https://host[:port][/path-with-wildcards]` into its parts.
/// We can't use `url::Url::parse` because rule URLs may contain `*` in
/// the path, which is fine, but we want to keep the host as-is.
fn parse_url(url_str: &str) -> Option<(String, String, Option<u16>, String)> {
    let (scheme, rest) = url_str.split_once("://")?;
    let (host_and_port, path_rest) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, "/"),
    };
    if host_and_port.contains('*') {
        return None;
    }
    let (host, port) = match host_and_port.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
        None => (host_and_port.to_string(), None),
    };
    Some((scheme.to_string(), host, port, path_rest.to_string()))
}

/// Build the probe set for a git rule. Endpoints mirror
/// `CompiledRule::compile_git_rules`: smart-HTTP info/refs + verb pack
/// for each direction. We only probe one canonical endpoint per
/// direction — a permissive method rule that covers /info/refs but
/// not /git-upload-pack will fail the second probe and bail to the
/// human, which is the right call.
fn probes_for_git(
    op: &str,
    scheme: &str,
    host: &str,
    port: Option<u16>,
    base_path: &str,
) -> Vec<Probe> {
    let base = base_path.replace('*', "x");
    let base = base.strip_suffix(".git").unwrap_or(&base).to_string();
    let mut probes = Vec::new();

    let want_fetch = op == "fetch" || op == "*";
    let want_push = op == "push" || op == "*";

    if want_fetch {
        probes.push(Probe {
            method: "GET".into(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path: format!("{}/info/refs", base),
            query: Some("service=git-upload-pack".into()),
            websocket: false,
        });
        probes.push(Probe {
            method: "POST".into(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path: format!("{}/git-upload-pack", base),
            query: None,
            websocket: false,
        });
    }
    if want_push {
        probes.push(Probe {
            method: "GET".into(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path: format!("{}/info/refs", base),
            query: Some("service=git-receive-pack".into()),
            websocket: false,
        });
        probes.push(Probe {
            method: "POST".into(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path: format!("{}/git-receive-pack", base),
            query: None,
            websocket: false,
        });
    }

    probes
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    fn mk_method_rule(method: &str, url: &str) -> Rule {
        Rule {
            method: Some(method.to_string()),
            url: url.to_string(),
            websocket: false,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        }
    }

    fn mk_git_rule(op: &str, url: &str) -> Rule {
        Rule {
            method: None,
            url: url.to_string(),
            websocket: false,
            git: Some(op.to_string()),
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        }
    }

    #[test]
    fn test_probe_parsing() {
        let t = test_report!("probes_from_rule parses method, host, port, path");
        let probes = probes_from_rule(&mk_method_rule("GET", "https://api.foo.com/*")).unwrap();
        t.assert_eq("count", &probes.len(), &1);
        let p = &probes[0];
        t.assert_eq("method", &p.method.as_str(), &"GET");
        t.assert_eq("scheme", &p.scheme.as_str(), &"https");
        t.assert_eq("host", &p.host.as_str(), &"api.foo.com");
        t.assert_eq("port", &p.port, &None);
        t.assert_eq("path", &p.path.as_str(), &"/x");

        let probes = probes_from_rule(&mk_method_rule("POST", "http://x.com:8080/v1/*")).unwrap();
        t.assert_eq("custom port", &probes[0].port, &Some(8080u16));

        t.assert_true(
            "wildcard host rejected",
            probes_from_rule(&mk_method_rule("GET", "https://*.foo.com/")).is_none(),
        );
    }

    #[test]
    fn test_subsumed_positive() {
        let t = test_report!("all_subsumed: proposed rule already covered");
        let engine =
            FilterEngine::new(vec![mk_method_rule("GET", "https://api.foo.com/*")]).unwrap();
        t.assert_true(
            "broader proposed covered",
            all_subsumed(
                &engine,
                &[mk_method_rule("GET", "https://api.foo.com/*")],
                None,
            ),
        );
        t.assert_true(
            "narrower proposed covered",
            all_subsumed(
                &engine,
                &[mk_method_rule("GET", "https://api.foo.com/v1/weather")],
                None,
            ),
        );
    }

    #[test]
    fn test_subsumed_negative() {
        let t = test_report!("all_subsumed: proposed rule NOT covered");
        let engine =
            FilterEngine::new(vec![mk_method_rule("GET", "https://api.foo.com/*")]).unwrap();
        t.assert_true(
            "different host not covered",
            !all_subsumed(
                &engine,
                &[mk_method_rule("GET", "https://api.bar.com/*")],
                None,
            ),
        );
        t.assert_true(
            "different method not covered",
            !all_subsumed(
                &engine,
                &[mk_method_rule("POST", "https://api.foo.com/*")],
                None,
            ),
        );
    }

    #[test]
    fn test_option_fields_never_subsumed() {
        let t = test_report!("Proposals carrying extra options are never deduped");
        let engine =
            FilterEngine::new(vec![mk_method_rule("GET", "https://api.foo.com/*")]).unwrap();

        let mut redirects = mk_method_rule("GET", "https://api.foo.com/*");
        redirects.allow_redirects = vec!["https://cdn.foo.com/*".to_string()];
        t.assert_true(
            "allow_redirects not subsumed",
            !all_subsumed(&engine, &[redirects], None),
        );

        let mut log_body = mk_method_rule("GET", "https://api.foo.com/*");
        log_body.log_body = true;
        t.assert_true(
            "log_body not subsumed",
            !all_subsumed(&engine, &[log_body], None),
        );

        let mut branches = mk_git_rule("push", "https://github.com/foo/bar");
        branches.branches = Some(vec!["main".to_string()]);
        t.assert_true(
            "branches not subsumed",
            !all_subsumed(
                &FilterEngine::new(vec![mk_git_rule("push", "https://github.com/foo/bar")])
                    .unwrap(),
                &[branches],
                None,
            ),
        );
    }

    #[test]
    fn test_option_fields_not_subsumed_even_with_triggered_by() {
        // triggered_by supplies the probe URL for the first rule — it must not
        // let an allow_redirects proposal slip past the option check.
        let t = test_report!("triggered_by doesn't bypass the extra-options check");
        let engine =
            FilterEngine::new(vec![mk_method_rule("GET", "https://api.foo.com/*")]).unwrap();
        let mut rule = mk_method_rule("GET", "https://api.foo.com/dl/*");
        rule.allow_redirects = vec!["https://cdn.foo.com/*".to_string()];
        let tb = TriggeredBy {
            method: "GET".to_string(),
            url: "https://api.foo.com/dl/x".to_string(),
        };
        t.assert_true("not subsumed", !all_subsumed(&engine, &[rule], Some(&tb)));
    }

    #[test]
    fn test_websocket_rule_not_subsumed_by_http_rule() {
        let t = test_report!("WebSocket proposal isn't covered by a plain HTTP rule");
        let engine =
            FilterEngine::new(vec![mk_method_rule("GET", "https://api.foo.com/*")]).unwrap();
        let mut ws = mk_method_rule("GET", "https://api.foo.com/socket");
        ws.websocket = true;
        t.assert_true(
            "ws not subsumed by http",
            !all_subsumed(&engine, &[ws], None),
        );

        let mut ws_rule = mk_method_rule("GET", "https://api.foo.com/*");
        ws_rule.websocket = true;
        let ws_engine = FilterEngine::new(vec![ws_rule.clone()]).unwrap();
        t.assert_true(
            "ws subsumed by ws",
            all_subsumed(&ws_engine, &[ws_rule], None),
        );
    }

    #[test]
    fn test_branch_restricted_rule_is_not_full_coverage() {
        // Active rule only permits pushes to main; a proposal for unrestricted
        // push must still reach the human.
        let t = test_report!("Branch-restricted active rule doesn't subsume an open push");
        let mut restricted = mk_git_rule("push", "https://github.com/foo/bar");
        restricted.branches = Some(vec!["main".to_string()]);
        let engine = FilterEngine::new(vec![restricted]).unwrap();
        t.assert_true(
            "open push not subsumed",
            !all_subsumed(
                &engine,
                &[mk_git_rule("push", "https://github.com/foo/bar")],
                None,
            ),
        );
    }

    #[test]
    fn test_subsumed_empty_not_subsumed() {
        let t = test_report!("Empty proposed is NOT subsumed (defensive)");
        let engine = FilterEngine::empty();
        t.assert_true("empty is not subsumed", !all_subsumed(&engine, &[], None));
    }

    #[test]
    fn test_git_fetch_subsumed_by_existing_git_fetch() {
        let t = test_report!("git=fetch subsumed when an active git=fetch covers it");
        let engine =
            FilterEngine::new(vec![mk_git_rule("fetch", "https://github.com/foo/bar")]).unwrap();
        t.assert_true(
            "same repo, .git suffix tolerated",
            all_subsumed(
                &engine,
                &[mk_git_rule("fetch", "https://github.com/foo/bar.git")],
                None,
            ),
        );
        t.assert_true(
            "git=push not covered by git=fetch",
            !all_subsumed(
                &engine,
                &[mk_git_rule("push", "https://github.com/foo/bar")],
                None,
            ),
        );
    }

    #[test]
    fn test_git_fetch_not_subsumed_by_get_only_method_rule() {
        // A method rule that only matches GETs would let /info/refs through
        // but block POST /git-upload-pack. Dedup must NOT short-circuit.
        let t = test_report!("git=fetch needs POST too — GET-only method rule is not enough");
        let engine = FilterEngine::new(vec![mk_method_rule(
            "GET",
            "https://github.com/foo/bar.git/*",
        )])
        .unwrap();
        t.assert_true(
            "GET-only doesn't cover git=fetch",
            !all_subsumed(
                &engine,
                &[mk_git_rule("fetch", "https://github.com/foo/bar.git")],
                None,
            ),
        );
    }

    #[test]
    fn test_git_star_subsumed_by_existing_git_star() {
        let t = test_report!("git=* subsumed when an active git=* covers it");
        let engine =
            FilterEngine::new(vec![mk_git_rule("*", "https://github.com/foo/bar")]).unwrap();
        t.assert_true(
            "git=* covers git=*",
            all_subsumed(
                &engine,
                &[mk_git_rule("*", "https://github.com/foo/bar")],
                None,
            ),
        );
        t.assert_true(
            "git=* covers git=fetch",
            all_subsumed(
                &engine,
                &[mk_git_rule("fetch", "https://github.com/foo/bar")],
                None,
            ),
        );
        t.assert_true(
            "git=fetch does NOT cover git=*",
            !all_subsumed(
                &FilterEngine::new(vec![mk_git_rule("fetch", "https://github.com/foo/bar")])
                    .unwrap(),
                &[mk_git_rule("*", "https://github.com/foo/bar")],
                None,
            ),
        );
    }
}
