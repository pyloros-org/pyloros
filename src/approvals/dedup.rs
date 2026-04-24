//! Rule-subsumption check for the approvals dedup optimization (I4).
//!
//! If the proposed rules for an approval are already covered by the
//! active ruleset, we can skip the human round-trip and return
//! `approved` immediately. The probe works by synthesizing a
//! representative concrete URL from each proposed rule pattern and
//! running it through the current FilterEngine.

use crate::filter::{FilterEngine, RequestInfo};

use super::types::TriggeredBy;

/// True iff every rule in `proposed_rules` (in short-form, e.g.
/// `"GET https://api.foo.com/*"`) is already allowed by the current
/// `engine`. Rules we can't construct a probe URL from are treated as
/// "not subsumed" — when in doubt, ask the human.
///
/// If `triggered_by` is present, its URL is used as the probe for the
/// first proposed rule (most precise: it's the URL the agent actually
/// wanted). Extra proposed rules are probed from the rule pattern.
pub fn all_subsumed(
    engine: &FilterEngine,
    proposed_rules: &[String],
    triggered_by: Option<&TriggeredBy>,
) -> bool {
    if proposed_rules.is_empty() {
        return false;
    }
    for (i, rule_str) in proposed_rules.iter().enumerate() {
        let probe = if i == 0 {
            triggered_by
                .and_then(probe_from_triggered_by)
                .or_else(|| probe_from_rule(rule_str))
        } else {
            probe_from_rule(rule_str)
        };
        let Some((method, scheme, host, port, path)) = probe else {
            // Unable to derive a probe → treat as not subsumed.
            return false;
        };
        let info = RequestInfo::http(&method, &scheme, &host, port, &path, None);
        if !engine.is_allowed(&info) {
            return false;
        }
    }
    true
}

fn probe_from_triggered_by(
    tb: &TriggeredBy,
) -> Option<(String, String, String, Option<u16>, String)> {
    let url = url::Url::parse(&tb.url).ok()?;
    let scheme = url.scheme().to_string();
    let host = url.host_str()?.to_string();
    let port = url.port();
    let path = url.path().to_string();
    Some((tb.method.clone(), scheme, host, port, path))
}

/// Parse a short-form rule string into a concrete probe URL. Wildcards
/// in the path are replaced with a placeholder segment.
///
/// Examples:
/// - `"GET https://api.foo.com/*"`      → (GET, https, api.foo.com, None, /x)
/// - `"POST https://api.foo.com/v1/*"`  → (POST, https, api.foo.com, None, /v1/x)
/// - `"* https://api.foo.com/v1/x"`     → (GET, https, api.foo.com, None, /v1/x)  (method `*` → probe as GET)
///
/// Returns `None` if the URL has wildcards in the host (we can't pick
/// a concrete host, so dedup bails and asks the human).
fn probe_from_rule(rule_str: &str) -> Option<(String, String, String, Option<u16>, String)> {
    let (method, url_str) = rule_str.trim().split_once(char::is_whitespace)?;
    let method = method.trim();
    let url_str = url_str.trim();
    let probe_method = if method == "*" {
        "GET".to_string()
    } else {
        method.to_string()
    };

    // The URL may contain `*` wildcards. `url::Url::parse` accepts `*`
    // in the path portion; it only rejects it in the host. Replace
    // path wildcards with `x` so the probe is a concrete URL.
    let (scheme, rest) = url_str.split_once("://")?;
    let (host_and_port, path_rest) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, "/"),
    };

    if host_and_port.contains('*') {
        // Can't probe wildcard hosts meaningfully.
        return None;
    }

    let (host, port) = match host_and_port.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
        None => (host_and_port.to_string(), None),
    };

    // Replace any `*` in the path with a concrete segment.
    let path = path_rest.replace('*', "x");

    Some((probe_method, scheme.to_string(), host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Rule;
    use pyloros_test_support::test_report;

    fn mk_rule(method: &str, url: &str) -> Rule {
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

    #[test]
    fn test_probe_parsing() {
        let t = test_report!("probe_from_rule parses method, host, port, path");
        let (m, s, h, p, path) = probe_from_rule("GET https://api.foo.com/*").unwrap();
        t.assert_eq("method", &m.as_str(), &"GET");
        t.assert_eq("scheme", &s.as_str(), &"https");
        t.assert_eq("host", &h.as_str(), &"api.foo.com");
        t.assert_eq("port", &p, &None);
        t.assert_eq("path", &path.as_str(), &"/x");

        let (_, _, _, p, _) = probe_from_rule("POST http://x.com:8080/v1/*").unwrap();
        t.assert_eq("custom port", &p, &Some(8080u16));

        t.assert_true(
            "wildcard host rejected",
            probe_from_rule("GET https://*.foo.com/").is_none(),
        );
    }

    #[test]
    fn test_subsumed_positive() {
        let t = test_report!("all_subsumed: proposed rule already covered");
        let engine = FilterEngine::new(vec![mk_rule("GET", "https://api.foo.com/*")]).unwrap();
        t.assert_true(
            "broader proposed covered",
            all_subsumed(&engine, &["GET https://api.foo.com/*".to_string()], None),
        );
        t.assert_true(
            "narrower proposed covered",
            all_subsumed(
                &engine,
                &["GET https://api.foo.com/v1/weather".to_string()],
                None,
            ),
        );
    }

    #[test]
    fn test_subsumed_negative() {
        let t = test_report!("all_subsumed: proposed rule NOT covered");
        let engine = FilterEngine::new(vec![mk_rule("GET", "https://api.foo.com/*")]).unwrap();
        t.assert_true(
            "different host not covered",
            !all_subsumed(&engine, &["GET https://api.bar.com/*".to_string()], None),
        );
        t.assert_true(
            "different method not covered",
            !all_subsumed(&engine, &["POST https://api.foo.com/*".to_string()], None),
        );
    }

    #[test]
    fn test_subsumed_empty_not_subsumed() {
        let t = test_report!("Empty proposed is NOT subsumed (defensive)");
        let engine = FilterEngine::empty();
        t.assert_true("empty is not subsumed", !all_subsumed(&engine, &[], None));
    }
}
