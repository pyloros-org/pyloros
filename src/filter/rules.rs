//! Rule compilation and filter engine

use super::matcher::{PatternMatcher, UrlPattern};
use super::redirect_whitelist::RedirectWhitelist;
use crate::config::Rule;
use crate::error::Result;
use std::sync::Arc;

/// Information about a request to be filtered
#[derive(Debug, Clone)]
pub struct RequestInfo<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: Option<u16>,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub is_websocket: bool,
}

impl<'a> RequestInfo<'a> {
    /// Create a new RequestInfo for an HTTP request
    pub fn http(
        method: &'a str,
        scheme: &'a str,
        host: &'a str,
        port: Option<u16>,
        path: &'a str,
        query: Option<&'a str>,
    ) -> Self {
        Self {
            method,
            scheme,
            host,
            port,
            path,
            query,
            is_websocket: false,
        }
    }

    /// Create a new RequestInfo for a WebSocket upgrade
    pub fn websocket(
        scheme: &'a str,
        host: &'a str,
        port: Option<u16>,
        path: &'a str,
        query: Option<&'a str>,
    ) -> Self {
        Self {
            method: "GET",
            scheme,
            host,
            port,
            path,
            query,
            is_websocket: true,
        }
    }

    /// Get the full URL for logging
    pub fn full_url(&self) -> String {
        let port_str = match (self.scheme, self.port) {
            ("https", Some(443)) | ("https", None) => String::new(),
            ("http", Some(80)) | ("http", None) => String::new(),
            (_, Some(p)) => format!(":{}", p),
            (_, None) => String::new(),
        };

        match self.query {
            Some(q) => format!(
                "{}://{}{}{}?{}",
                self.scheme, self.host, port_str, self.path, q
            ),
            None => format!("{}://{}{}{}", self.scheme, self.host, port_str, self.path),
        }
    }
}

/// Branch filter with allow and deny pattern lists.
///
/// A ref is allowed if:
/// 1. It does NOT match any deny pattern, AND
/// 2. Either the allow list is empty (implicit allow-all) or it matches at least one allow pattern.
#[derive(Debug, Clone)]
pub struct BranchFilter {
    pub allow: Vec<PatternMatcher>,
    pub deny: Vec<PatternMatcher>,
}

/// A compiled rule ready for efficient matching
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Method matcher (or None for "*" which matches any method)
    method: Option<PatternMatcher>,
    /// URL pattern matcher
    url: UrlPattern,
    /// Whether this rule is for WebSocket connections
    websocket: bool,
    /// Branch filter for git push restriction (if Some, body inspection required)
    branch_filter: Option<BranchFilter>,
    /// Allowed LFS operations (if Some, body inspection required for LFS batch endpoint)
    lfs_operations: Option<Vec<String>>,
    /// Compiled redirect URL patterns; empty means "do not follow redirects".
    /// Shared across all endpoints compiled from the same git rule.
    allow_redirects: Arc<Vec<UrlPattern>>,
}

/// Compile the `allow_redirects` patterns of a config `Rule`. Accepts bare `"*"` as
/// a shorthand for "match any URL" (otherwise `UrlPattern` requires a scheme).
fn compile_redirect_patterns(rule: &Rule) -> Result<Arc<Vec<UrlPattern>>> {
    let patterns: Result<Vec<UrlPattern>> = rule
        .allow_redirects
        .iter()
        .map(|p| {
            if p == "*" {
                UrlPattern::new("*://*/*")
            } else {
                UrlPattern::new(p)
            }
        })
        .collect();
    Ok(Arc::new(patterns?))
}

impl CompiledRule {
    /// Compile a rule from configuration (for non-git HTTP rules)
    pub fn compile(rule: &Rule) -> Result<Self> {
        let method_str = rule
            .method
            .as_deref()
            .expect("compile() called on git rule — use compile_git_rules() instead");
        let method = if method_str == "*" {
            None
        } else {
            Some(PatternMatcher::new(&method_str.to_uppercase())?)
        };

        let url = UrlPattern::new(&rule.url)?;
        let allow_redirects = compile_redirect_patterns(rule)?;

        Ok(Self {
            method,
            url,
            websocket: rule.websocket,
            branch_filter: None,
            lfs_operations: None,
            allow_redirects,
        })
    }

    /// Compile a git rule into multiple CompiledRules for the smart HTTP endpoints.
    pub fn compile_git_rules(rule: &Rule) -> Result<Vec<Self>> {
        let git_op = rule
            .git
            .as_deref()
            .expect("compile_git_rules called on non-git rule");
        let base_url = &rule.url;
        let redirects = compile_redirect_patterns(rule)?;

        let mut rules = Vec::new();

        let needs_fetch = git_op == "fetch" || git_op == "*";
        let needs_push = git_op == "push" || git_op == "*";

        if needs_fetch {
            rules.push(Self::compile_git_endpoint(
                base_url,
                "/info/refs",
                Some("service=git-upload-pack"),
                "GET",
                None,
                redirects.clone(),
            )?);
            rules.push(Self::compile_git_endpoint(
                base_url,
                "/git-upload-pack",
                None,
                "POST",
                None,
                redirects.clone(),
            )?);
        }

        if needs_push {
            rules.push(Self::compile_git_endpoint(
                base_url,
                "/info/refs",
                Some("service=git-receive-pack"),
                "GET",
                None,
                redirects.clone(),
            )?);
            let branch_filter = rule
                .branches
                .as_ref()
                .map(|branches| {
                    let mut allow = Vec::new();
                    let mut deny = Vec::new();
                    for b in branches {
                        if let Some(stripped) = b.strip_prefix('!') {
                            deny.push(PatternMatcher::new(stripped)?);
                        } else {
                            allow.push(PatternMatcher::new(b)?);
                        }
                    }
                    Ok::<BranchFilter, crate::error::Error>(BranchFilter { allow, deny })
                })
                .transpose()?;
            rules.push(Self::compile_git_endpoint(
                base_url,
                "/git-receive-pack",
                None,
                "POST",
                branch_filter,
                redirects.clone(),
            )?);
        }

        if needs_push {
            rules.push(Self::compile_git_endpoint(
                base_url,
                "/info/lfs/locks",
                None,
                "GET",
                None,
                redirects.clone(),
            )?);
            rules.push(Self::compile_git_endpoint(
                base_url,
                "/info/lfs/locks",
                None,
                "POST",
                None,
                redirects.clone(),
            )?);
            rules.push(Self::compile_git_endpoint(
                base_url,
                "/info/lfs/locks/verify",
                None,
                "POST",
                None,
                redirects.clone(),
            )?);
            rules.push(Self::compile_git_endpoint(
                base_url,
                "/info/lfs/locks/*/unlock",
                None,
                "POST",
                None,
                redirects.clone(),
            )?);
        } else if needs_fetch {
            rules.push(Self::compile_git_endpoint(
                base_url,
                "/info/lfs/locks",
                None,
                "GET",
                None,
                redirects.clone(),
            )?);
            rules.push(Self::compile_git_endpoint(
                base_url,
                "/info/lfs/locks/verify",
                None,
                "POST",
                None,
                redirects.clone(),
            )?);
        }

        {
            let mut lfs_ops = Vec::new();
            if needs_fetch {
                lfs_ops.push("download".to_string());
            }
            if needs_push {
                lfs_ops.push("upload".to_string());
            }
            rules.push(Self::compile_lfs_batch_endpoint(
                base_url,
                lfs_ops,
                redirects.clone(),
            )?);
        }

        Ok(rules)
    }

    /// Compile a single git smart HTTP endpoint rule.
    fn compile_git_endpoint(
        base_url: &str,
        path_suffix: &str,
        query: Option<&str>,
        method: &str,
        branch_filter: Option<BranchFilter>,
        allow_redirects: Arc<Vec<UrlPattern>>,
    ) -> Result<Self> {
        let full_url = match query {
            Some(q) => format!("{}{}?{}", base_url, path_suffix, q),
            None => format!("{}{}", base_url, path_suffix),
        };

        let method_matcher = Some(PatternMatcher::new(&method.to_uppercase())?);
        let url = UrlPattern::new(&full_url)?;

        Ok(Self {
            method: method_matcher,
            url,
            websocket: false,
            branch_filter,
            lfs_operations: None,
            allow_redirects,
        })
    }

    /// Compile the LFS batch endpoint rule for a git rule.
    fn compile_lfs_batch_endpoint(
        base_url: &str,
        lfs_operations: Vec<String>,
        allow_redirects: Arc<Vec<UrlPattern>>,
    ) -> Result<Self> {
        let full_url = format!("{}/info/lfs/objects/batch", base_url);
        let method_matcher = Some(PatternMatcher::new("POST")?);
        let url = UrlPattern::new(&full_url)?;

        Ok(Self {
            method: method_matcher,
            url,
            websocket: false,
            branch_filter: None,
            lfs_operations: Some(lfs_operations),
            allow_redirects,
        })
    }

    /// Check if this rule matches the given request
    pub fn matches(&self, request: &RequestInfo) -> bool {
        // Check WebSocket flag
        if self.websocket != request.is_websocket {
            return false;
        }

        // Check method
        if let Some(ref method_matcher) = self.method {
            if !method_matcher.matches(request.method) {
                return false;
            }
        }

        // Check URL
        self.url.matches(
            request.scheme,
            request.host,
            request.port,
            request.path,
            request.query,
        )
    }
}

/// Result of checking a request against the filter engine
#[derive(Debug)]
pub enum FilterResult {
    /// Request is blocked (no rule matched)
    Blocked,
    /// Request is allowed (a rule matched with no branch restriction)
    Allowed,
    /// Request is allowed but requires branch-level body inspection
    AllowedWithBranchCheck(BranchFilter),
    /// Request is allowed but requires LFS operation body inspection.
    /// Carries the merged list of allowed operations (e.g., ["download", "upload"]).
    AllowedWithLfsCheck(Vec<String>),
    /// Request is allowed because its URL is present in the redirect whitelist.
    /// Carries the origin rule's redirect patterns so a chained redirect from
    /// this response can be validated against the same policy.
    AllowedByRedirect {
        origin_patterns: Arc<Vec<UrlPattern>>,
    },
}

/// The filter engine that evaluates requests against rules
#[derive(Debug, Clone)]
pub struct FilterEngine {
    /// Compiled rules
    rules: Vec<CompiledRule>,
}

impl FilterEngine {
    /// Create a new filter engine with the given rules
    pub fn new(rules: Vec<Rule>) -> Result<Self> {
        let mut compiled = Vec::new();
        for rule in &rules {
            if rule.git.is_some() {
                compiled.extend(CompiledRule::compile_git_rules(rule)?);
            } else {
                compiled.push(CompiledRule::compile(rule)?);
            }
        }
        Ok(Self { rules: compiled })
    }

    /// Create an empty filter engine (blocks everything)
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Check a request against rules, returning detailed result.
    ///
    /// For LFS batch endpoint rules, multiple matching rules are merged: their allowed
    /// operations are accumulated so that separate fetch + push rules for the same repo
    /// don't block each other. For all other rule types, first-match wins.
    pub fn check(&self, request: &RequestInfo) -> FilterResult {
        let mut accumulated_lfs_ops: Vec<String> = Vec::new();

        for rule in &self.rules {
            if rule.matches(request) {
                if let Some(ref filter) = rule.branch_filter {
                    return FilterResult::AllowedWithBranchCheck(filter.clone());
                }
                if let Some(ref ops) = rule.lfs_operations {
                    // Accumulate LFS operations across matching rules (merged-scan)
                    for op in ops {
                        if !accumulated_lfs_ops.contains(op) {
                            accumulated_lfs_ops.push(op.clone());
                        }
                    }
                    continue;
                }
                return FilterResult::Allowed;
            }
        }

        if !accumulated_lfs_ops.is_empty() {
            return FilterResult::AllowedWithLfsCheck(accumulated_lfs_ops);
        }

        FilterResult::Blocked
    }

    /// Check if a request is allowed (convenience wrapper around check())
    ///
    /// Returns true if the request matches at least one rule.
    /// Note: AllowedWithBranchCheck is treated as allowed here — callers
    /// that need branch-level inspection should use check() directly.
    pub fn is_allowed(&self, request: &RequestInfo) -> bool {
        !matches!(self.check(request), FilterResult::Blocked)
    }

    /// Return the redirect patterns of the first matching rule, if any.
    /// Used after a request is allowed to determine whether a 3xx response
    /// should extend the whitelist.
    pub fn redirect_policy_for(&self, request: &RequestInfo) -> Option<Arc<Vec<UrlPattern>>> {
        for rule in &self.rules {
            if rule.matches(request) {
                if rule.allow_redirects.is_empty() {
                    return None;
                }
                return Some(rule.allow_redirects.clone());
            }
        }
        None
    }

    /// Like `check()` but consults the redirect whitelist first. If the request's
    /// full URL is whitelisted (and unexpired), returns `AllowedByRedirect` carrying
    /// the origin rule's redirect patterns.
    pub fn check_with_redirect_whitelist(
        &self,
        request: &RequestInfo,
        whitelist: &RedirectWhitelist,
    ) -> FilterResult {
        let full_url = request.full_url();
        if let Some(origin_patterns) = whitelist.get(&full_url) {
            return FilterResult::AllowedByRedirect { origin_patterns };
        }
        self.check(request)
    }

    /// Get the number of rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for FilterEngine {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    fn make_rule(method: &str, url: &str) -> Rule {
        Rule {
            method: Some(method.to_string()),
            url: url.to_string(),
            websocket: false,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
        }
    }

    fn make_ws_rule(url: &str) -> Rule {
        Rule {
            method: Some("GET".to_string()),
            url: url.to_string(),
            websocket: true,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
        }
    }

    #[test]
    fn test_empty_engine_blocks_all() {
        let t = test_report!("Empty engine blocks all requests");
        let engine = FilterEngine::empty();
        let request = RequestInfo::http("GET", "https", "example.com", None, "/", None);
        t.assert_true("GET / blocked", !engine.is_allowed(&request));
    }

    #[test]
    fn test_exact_match() {
        let t = test_report!("Exact URL match");
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://api.example.com/health")]).unwrap();

        let allowed = RequestInfo::http("GET", "https", "api.example.com", None, "/health", None);
        let wrong_method =
            RequestInfo::http("POST", "https", "api.example.com", None, "/health", None);
        let wrong_path = RequestInfo::http("GET", "https", "api.example.com", None, "/other", None);
        let wrong_host = RequestInfo::http("GET", "https", "other.com", None, "/health", None);

        t.assert_true("exact match allowed", engine.is_allowed(&allowed));
        t.assert_true("wrong method blocked", !engine.is_allowed(&wrong_method));
        t.assert_true("wrong path blocked", !engine.is_allowed(&wrong_path));
        t.assert_true("wrong host blocked", !engine.is_allowed(&wrong_host));
    }

    #[test]
    fn test_wildcard_method() {
        let t = test_report!("Wildcard method * matches all");
        let engine = FilterEngine::new(vec![make_rule("*", "https://cdn.example.com/*")]).unwrap();

        for method in ["GET", "POST", "DELETE"] {
            let req = RequestInfo::http(method, "https", "cdn.example.com", None, "/file", None);
            t.assert_true(&format!("{} allowed", method), engine.is_allowed(&req));
        }
    }

    #[test]
    fn test_wildcard_host() {
        let t = test_report!("Wildcard host *.github.com");
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://*.github.com/api/*")]).unwrap();

        let api = RequestInfo::http("GET", "https", "api.github.com", None, "/api/repos", None);
        let raw = RequestInfo::http("GET", "https", "raw.github.com", None, "/api/files", None);
        let bare = RequestInfo::http("GET", "https", "github.com", None, "/api/repos", None);

        t.assert_true("api.github.com allowed", engine.is_allowed(&api));
        t.assert_true("raw.github.com allowed", engine.is_allowed(&raw));
        t.assert_true("github.com blocked", !engine.is_allowed(&bare));
    }

    #[test]
    fn test_wildcard_path() {
        let t = test_report!("Wildcard path /users/*/comments");
        let engine = FilterEngine::new(vec![make_rule(
            "POST",
            "https://api.example.com/users/*/comments",
        )])
        .unwrap();

        let single = RequestInfo::http(
            "POST",
            "https",
            "api.example.com",
            None,
            "/users/123/comments",
            None,
        );
        let multi = RequestInfo::http(
            "POST",
            "https",
            "api.example.com",
            None,
            "/users/abc/def/comments",
            None,
        );
        let empty = RequestInfo::http(
            "POST",
            "https",
            "api.example.com",
            None,
            "/users/comments",
            None,
        );

        t.assert_true("single segment allowed", engine.is_allowed(&single));
        t.assert_true("multi segment allowed", engine.is_allowed(&multi));
        t.assert_true("no segment blocked", !engine.is_allowed(&empty));
    }

    #[test]
    fn test_query_matching() {
        let t = test_report!("Query string wildcard matching");
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://api.example.com/search?q=*")])
                .unwrap();

        let with_q = RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/search",
            Some("q=test"),
        );
        let no_q = RequestInfo::http("GET", "https", "api.example.com", None, "/search", None);
        let wrong_q = RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/search",
            Some("other=param"),
        );

        t.assert_true("q=test allowed", engine.is_allowed(&with_q));
        t.assert_true("no query blocked", !engine.is_allowed(&no_q));
        t.assert_true("wrong query blocked", !engine.is_allowed(&wrong_q));
    }

    #[test]
    fn test_multiple_rules() {
        let t = test_report!("Multiple rules OR matching");
        let engine = FilterEngine::new(vec![
            make_rule("GET", "https://api.example.com/public/*"),
            make_rule("POST", "https://api.example.com/data"),
            make_rule("*", "https://cdn.example.com/*"),
        ])
        .unwrap();

        let public = RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/public/info",
            None,
        );
        let data = RequestInfo::http("POST", "https", "api.example.com", None, "/data", None);
        let cdn = RequestInfo::http("PUT", "https", "cdn.example.com", None, "/file", None);
        let blocked = RequestInfo::http("DELETE", "https", "api.example.com", None, "/data", None);

        t.assert_true("GET /public/* allowed", engine.is_allowed(&public));
        t.assert_true("POST /data allowed", engine.is_allowed(&data));
        t.assert_true("PUT cdn/* allowed", engine.is_allowed(&cdn));
        t.assert_true("DELETE /data blocked", !engine.is_allowed(&blocked));
    }

    #[test]
    fn test_websocket_rules() {
        let t = test_report!("WebSocket vs HTTP rule isolation");
        let engine = FilterEngine::new(vec![
            make_rule("GET", "https://api.example.com/http"),
            make_ws_rule("wss://api.example.com/socket"),
        ])
        .unwrap();

        let http_req = RequestInfo::http("GET", "https", "api.example.com", None, "/http", None);
        let ws_req = RequestInfo::websocket("https", "api.example.com", None, "/socket", None);
        let ws_on_http = RequestInfo::websocket("https", "api.example.com", None, "/http", None);
        let http_on_ws =
            RequestInfo::http("GET", "https", "api.example.com", None, "/socket", None);

        t.assert_true("HTTP matches HTTP rule", engine.is_allowed(&http_req));
        t.assert_true("WS matches WS rule", engine.is_allowed(&ws_req));
        t.assert_true(
            "WS does NOT match HTTP rule",
            !engine.is_allowed(&ws_on_http),
        );
        t.assert_true(
            "HTTP does NOT match WS rule",
            !engine.is_allowed(&http_on_ws),
        );
    }

    #[test]
    fn test_port_matching() {
        let t = test_report!("Port matching in rules");
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://api.example.com:8443/api")]).unwrap();

        let correct =
            RequestInfo::http("GET", "https", "api.example.com", Some(8443), "/api", None);
        let wrong = RequestInfo::http("GET", "https", "api.example.com", Some(443), "/api", None);
        let none = RequestInfo::http("GET", "https", "api.example.com", None, "/api", None);

        t.assert_true("port 8443 allowed", engine.is_allowed(&correct));
        t.assert_true("port 443 blocked", !engine.is_allowed(&wrong));
        t.assert_true("no port blocked", !engine.is_allowed(&none));
    }

    #[test]
    fn test_case_insensitive_method() {
        let t = test_report!("Case-insensitive method matching");
        let engine =
            FilterEngine::new(vec![make_rule("get", "https://api.example.com/test")]).unwrap();

        let req = RequestInfo::http("GET", "https", "api.example.com", None, "/test", None);
        t.assert_true("GET matches 'get'", engine.is_allowed(&req));
    }

    #[test]
    fn test_request_info_full_url() {
        let t = test_report!("RequestInfo::full_url() formatting");

        let r1 = RequestInfo::http("GET", "https", "example.com", None, "/path", None);
        t.assert_eq(
            "basic",
            &r1.full_url().as_str(),
            &"https://example.com/path",
        );

        let r2 = RequestInfo::http(
            "GET",
            "https",
            "example.com",
            Some(8443),
            "/path",
            Some("q=1"),
        );
        t.assert_eq(
            "with port+query",
            &r2.full_url().as_str(),
            &"https://example.com:8443/path?q=1",
        );

        let r3 = RequestInfo::http("GET", "https", "example.com", Some(443), "/path", None);
        t.assert_eq(
            "default port omitted",
            &r3.full_url().as_str(),
            &"https://example.com/path",
        );
    }

    #[test]
    fn test_rule_count() {
        let t = test_report!("FilterEngine::rule_count()");
        let engine = FilterEngine::new(vec![
            make_rule("GET", "https://a.com/"),
            make_rule("GET", "https://b.com/"),
        ])
        .unwrap();

        t.assert_eq("rule count", &engine.rule_count(), &2usize);
    }

    #[test]
    fn test_git_rule_branch_check_on_http_scheme() {
        let t = test_report!(
            "Git rule with branches returns AllowedWithBranchCheck for http:// requests"
        );
        let rule = Rule {
            method: None,
            url: "http://example.com/repo.git".to_string(),
            websocket: false,
            git: Some("push".to_string()),
            branches: Some(vec!["feature/*".to_string()]),
            allow_redirects: Vec::new(),
        };
        let engine = FilterEngine::new(vec![rule]).unwrap();

        // POST to the git-receive-pack endpoint over http://
        let req = RequestInfo::http(
            "POST",
            "http",
            "example.com",
            None,
            "/repo.git/git-receive-pack",
            None,
        );
        let result = engine.check(&req);
        t.assert_true(
            "returns AllowedWithBranchCheck (not Allowed or Blocked)",
            matches!(result, FilterResult::AllowedWithBranchCheck(_)),
        );

        // GET discovery endpoint has no branch restriction → Allowed
        let discovery = RequestInfo::http(
            "GET",
            "http",
            "example.com",
            None,
            "/repo.git/info/refs",
            Some("service=git-receive-pack"),
        );
        let result = engine.check(&discovery);
        t.assert_true(
            "discovery endpoint returns Allowed (no branch check)",
            matches!(result, FilterResult::Allowed),
        );
    }

    #[test]
    fn test_complex_github_pattern() {
        let t = test_report!("Complex GitHub-like wildcard patterns");
        let engine = FilterEngine::new(vec![
            make_rule("*", "https://*.github.com/*"),
            make_rule("*", "https://*.githubusercontent.com/*"),
        ])
        .unwrap();

        let api = RequestInfo::http(
            "GET",
            "https",
            "api.github.com",
            None,
            "/repos/owner/repo",
            None,
        );
        let graphql = RequestInfo::http("POST", "https", "api.github.com", None, "/graphql", None);
        let raw = RequestInfo::http(
            "GET",
            "https",
            "raw.githubusercontent.com",
            None,
            "/owner/repo/main/file.txt",
            None,
        );

        t.assert_true("api.github.com GET", engine.is_allowed(&api));
        t.assert_true("api.github.com POST", engine.is_allowed(&graphql));
        t.assert_true("raw.githubusercontent.com", engine.is_allowed(&raw));
    }

    fn make_git_rule(git_op: &str, url: &str) -> Rule {
        Rule {
            method: None,
            url: url.to_string(),
            websocket: false,
            git: Some(git_op.to_string()),
            branches: None,
            allow_redirects: Vec::new(),
        }
    }

    #[test]
    fn test_git_fetch_rule_generates_lfs_endpoint() {
        let t = test_report!("Git fetch rule generates LFS batch endpoint with download op");
        let engine =
            FilterEngine::new(vec![make_git_rule("fetch", "https://github.com/org/repo")]).unwrap();

        // fetch = 2 smart HTTP + 2 lock (GET list, POST verify) + 1 LFS batch = 5
        t.assert_eq("rule count", &engine.rule_count(), &5usize);

        let lfs_req = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/objects/batch",
            None,
        );
        let result = engine.check(&lfs_req);
        match result {
            FilterResult::AllowedWithLfsCheck(ops) => {
                t.assert_eq("allowed ops", &ops, &vec!["download".to_string()]);
            }
            other => panic!("expected AllowedWithLfsCheck, got {:?}", other),
        }
    }

    #[test]
    fn test_git_push_rule_generates_lfs_endpoint() {
        let t = test_report!("Git push rule generates LFS batch endpoint with upload op");
        let engine =
            FilterEngine::new(vec![make_git_rule("push", "https://github.com/org/repo")]).unwrap();

        // push = 2 smart HTTP + 4 lock (GET list, POST create, POST verify, POST unlock) + 1 LFS batch = 7
        t.assert_eq("rule count", &engine.rule_count(), &7usize);

        let lfs_req = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/objects/batch",
            None,
        );
        let result = engine.check(&lfs_req);
        match result {
            FilterResult::AllowedWithLfsCheck(ops) => {
                t.assert_eq("allowed ops", &ops, &vec!["upload".to_string()]);
            }
            other => panic!("expected AllowedWithLfsCheck, got {:?}", other),
        }
    }

    #[test]
    fn test_git_star_rule_generates_lfs_endpoint() {
        let t = test_report!("Git * rule generates LFS batch endpoint with both ops");
        let engine =
            FilterEngine::new(vec![make_git_rule("*", "https://github.com/org/repo")]).unwrap();

        // star = 4 smart HTTP + 4 lock + 1 LFS batch = 9
        t.assert_eq("rule count", &engine.rule_count(), &9usize);

        let lfs_req = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/objects/batch",
            None,
        );
        let result = engine.check(&lfs_req);
        match result {
            FilterResult::AllowedWithLfsCheck(ops) => {
                t.assert_eq(
                    "allowed ops",
                    &ops,
                    &vec!["download".to_string(), "upload".to_string()],
                );
            }
            other => panic!("expected AllowedWithLfsCheck, got {:?}", other),
        }
    }

    #[test]
    fn test_lfs_merged_scan_separate_fetch_push() {
        let t = test_report!("Separate fetch+push rules merge LFS operations");
        let engine = FilterEngine::new(vec![
            make_git_rule("fetch", "https://github.com/org/repo"),
            make_git_rule("push", "https://github.com/org/repo"),
        ])
        .unwrap();

        let lfs_req = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/objects/batch",
            None,
        );
        let result = engine.check(&lfs_req);
        match result {
            FilterResult::AllowedWithLfsCheck(ops) => {
                t.assert_true(
                    "download in merged ops",
                    ops.contains(&"download".to_string()),
                );
                t.assert_true("upload in merged ops", ops.contains(&"upload".to_string()));
            }
            other => panic!("expected AllowedWithLfsCheck, got {:?}", other),
        }
    }

    #[test]
    fn test_lfs_get_method_blocked() {
        let t = test_report!("GET to LFS batch endpoint is blocked (only POST allowed)");
        let engine =
            FilterEngine::new(vec![make_git_rule("*", "https://github.com/org/repo")]).unwrap();

        let get_lfs = RequestInfo::http(
            "GET",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/objects/batch",
            None,
        );
        t.assert_true(
            "GET to LFS batch blocked",
            matches!(engine.check(&get_lfs), FilterResult::Blocked),
        );
    }

    #[test]
    fn test_lfs_branch_restricted_push_still_allows_lfs() {
        let t = test_report!("Branch-restricted push rule still generates LFS upload rule");
        let rule = Rule {
            method: None,
            url: "https://github.com/org/repo".to_string(),
            websocket: false,
            git: Some("push".to_string()),
            branches: Some(vec!["feature/*".to_string()]),
            allow_redirects: Vec::new(),
        };
        let engine = FilterEngine::new(vec![rule]).unwrap();

        let lfs_req = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/objects/batch",
            None,
        );
        let result = engine.check(&lfs_req);
        match result {
            FilterResult::AllowedWithLfsCheck(ops) => {
                t.assert_eq("allowed ops", &ops, &vec!["upload".to_string()]);
            }
            other => panic!("expected AllowedWithLfsCheck, got {:?}", other),
        }
    }

    #[test]
    fn test_lfs_locks_fetch_allows_list_and_verify() {
        let t = test_report!("Git fetch rule allows lock list (GET) and verify (POST)");
        let engine =
            FilterEngine::new(vec![make_git_rule("fetch", "https://github.com/org/repo")]).unwrap();

        let list = RequestInfo::http(
            "GET",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks",
            None,
        );
        t.assert_true(
            "GET /info/lfs/locks allowed",
            matches!(engine.check(&list), FilterResult::Allowed),
        );

        let verify = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks/verify",
            None,
        );
        t.assert_true(
            "POST /info/lfs/locks/verify allowed",
            matches!(engine.check(&verify), FilterResult::Allowed),
        );
    }

    #[test]
    fn test_lfs_locks_fetch_blocks_create_and_unlock() {
        let t = test_report!("Git fetch rule blocks lock create (POST) and unlock");
        let engine =
            FilterEngine::new(vec![make_git_rule("fetch", "https://github.com/org/repo")]).unwrap();

        let create = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks",
            None,
        );
        t.assert_true(
            "POST /info/lfs/locks blocked (create)",
            matches!(engine.check(&create), FilterResult::Blocked),
        );

        let unlock = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks/123/unlock",
            None,
        );
        t.assert_true(
            "POST /info/lfs/locks/123/unlock blocked",
            matches!(engine.check(&unlock), FilterResult::Blocked),
        );
    }

    #[test]
    fn test_lfs_locks_push_allows_all() {
        let t = test_report!("Git push rule allows all lock endpoints");
        let engine =
            FilterEngine::new(vec![make_git_rule("push", "https://github.com/org/repo")]).unwrap();

        let list = RequestInfo::http(
            "GET",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks",
            None,
        );
        t.assert_true(
            "GET /info/lfs/locks allowed",
            matches!(engine.check(&list), FilterResult::Allowed),
        );

        let create = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks",
            None,
        );
        t.assert_true(
            "POST /info/lfs/locks allowed (create)",
            matches!(engine.check(&create), FilterResult::Allowed),
        );

        let verify = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks/verify",
            None,
        );
        t.assert_true(
            "POST /info/lfs/locks/verify allowed",
            matches!(engine.check(&verify), FilterResult::Allowed),
        );

        let unlock = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks/42/unlock",
            None,
        );
        t.assert_true(
            "POST /info/lfs/locks/42/unlock allowed",
            matches!(engine.check(&unlock), FilterResult::Allowed),
        );
    }

    #[test]
    fn test_lfs_locks_star_allows_all() {
        let t = test_report!("Git * rule allows all lock endpoints");
        let engine =
            FilterEngine::new(vec![make_git_rule("*", "https://github.com/org/repo")]).unwrap();

        let list = RequestInfo::http(
            "GET",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks",
            None,
        );
        t.assert_true(
            "GET /info/lfs/locks allowed",
            matches!(engine.check(&list), FilterResult::Allowed),
        );

        let create = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks",
            None,
        );
        t.assert_true(
            "POST /info/lfs/locks allowed (create)",
            matches!(engine.check(&create), FilterResult::Allowed),
        );

        let verify = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks/verify",
            None,
        );
        t.assert_true(
            "POST /info/lfs/locks/verify allowed",
            matches!(engine.check(&verify), FilterResult::Allowed),
        );

        let unlock = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks/999/unlock",
            None,
        );
        t.assert_true(
            "POST /info/lfs/locks/999/unlock allowed",
            matches!(engine.check(&unlock), FilterResult::Allowed),
        );
    }

    #[test]
    fn test_lfs_locks_return_allowed_not_lfs_check() {
        let t =
            test_report!("Lock endpoints return FilterResult::Allowed (not AllowedWithLfsCheck)");
        let engine =
            FilterEngine::new(vec![make_git_rule("push", "https://github.com/org/repo")]).unwrap();

        let list = RequestInfo::http(
            "GET",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks",
            None,
        );
        let result = engine.check(&list);
        t.assert_true(
            "lock list returns Allowed (not AllowedWithLfsCheck)",
            matches!(result, FilterResult::Allowed),
        );

        let verify = RequestInfo::http(
            "POST",
            "https",
            "github.com",
            None,
            "/org/repo/info/lfs/locks/verify",
            None,
        );
        let result = engine.check(&verify);
        t.assert_true(
            "lock verify returns Allowed (not AllowedWithLfsCheck)",
            matches!(result, FilterResult::Allowed),
        );
    }

    fn rule_with_redirects(method: &str, url: &str, redirects: &[&str]) -> Rule {
        Rule {
            method: Some(method.to_string()),
            url: url.to_string(),
            websocket: false,
            git: None,
            branches: None,
            allow_redirects: redirects.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_redirect_policy_for_rule_without_redirects() {
        let t = test_report!("redirect_policy_for returns None for rule without allow_redirects");
        let engine = FilterEngine::new(vec![make_rule("GET", "https://a.example.com/*")]).unwrap();
        let req = RequestInfo::http("GET", "https", "a.example.com", None, "/x", None);
        t.assert_true("no policy", engine.redirect_policy_for(&req).is_none());
    }

    #[test]
    fn test_redirect_policy_for_rule_with_redirects() {
        let t = test_report!(
            "redirect_policy_for returns compiled patterns for matching rule with allow_redirects"
        );
        let engine = FilterEngine::new(vec![rule_with_redirects(
            "GET",
            "https://a.example.com/*",
            &["https://cdn.example.com/*"],
        )])
        .unwrap();
        let req = RequestInfo::http("GET", "https", "a.example.com", None, "/x", None);
        let policy = engine.redirect_policy_for(&req);
        t.assert_true("policy present", policy.is_some());
        t.assert_eq("one pattern", &policy.unwrap().len(), &1usize);
    }

    #[test]
    fn test_redirect_policy_for_star_shorthand() {
        let t = test_report!(
            "redirect_policy_for accepts bare \"*\" shorthand and returns a catch-all pattern"
        );
        let engine = FilterEngine::new(vec![rule_with_redirects(
            "GET",
            "https://a.example.com/*",
            &["*"],
        )])
        .unwrap();
        let req = RequestInfo::http("GET", "https", "a.example.com", None, "/x", None);
        let policy = engine.redirect_policy_for(&req).unwrap();
        // The catch-all pattern should match an unrelated URL
        t.assert_true(
            "star matches any URL",
            policy[0].matches(
                "https",
                "release-assets.githubusercontent.com",
                None,
                "/anything",
                None,
            ),
        );
    }

    #[test]
    fn test_check_with_redirect_whitelist_hit() {
        let t = test_report!(
            "check_with_redirect_whitelist returns AllowedByRedirect on whitelist hit"
        );
        let engine = FilterEngine::empty();
        let wl = RedirectWhitelist::new(std::time::Duration::from_secs(60), 10);
        let patterns = Arc::new(vec![UrlPattern::new("*://*/*").unwrap()]);
        wl.insert("https://cdn.example.com/file".to_string(), patterns);

        let req = RequestInfo::http("GET", "https", "cdn.example.com", None, "/file", None);
        let result = engine.check_with_redirect_whitelist(&req, &wl);
        t.assert_true(
            "AllowedByRedirect",
            matches!(result, FilterResult::AllowedByRedirect { .. }),
        );
    }

    #[test]
    fn test_check_with_redirect_whitelist_miss_falls_through() {
        let t = test_report!(
            "check_with_redirect_whitelist falls through to check() on whitelist miss"
        );
        let engine = FilterEngine::new(vec![make_rule("GET", "https://a.example.com/*")]).unwrap();
        let wl = RedirectWhitelist::new(std::time::Duration::from_secs(60), 10);

        // Matching normal rule
        let req = RequestInfo::http("GET", "https", "a.example.com", None, "/x", None);
        let result = engine.check_with_redirect_whitelist(&req, &wl);
        t.assert_true(
            "Allowed (via rule)",
            matches!(result, FilterResult::Allowed),
        );

        // Not matching any rule and not in whitelist
        let req2 = RequestInfo::http("GET", "https", "other.example.com", None, "/x", None);
        let result2 = engine.check_with_redirect_whitelist(&req2, &wl);
        t.assert_true("Blocked", matches!(result2, FilterResult::Blocked));
    }
}
