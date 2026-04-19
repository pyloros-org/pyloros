//! Integration tests for the filter engine

#[path = "common/mod.rs"]
mod common;

use pyloros::config::Rule;
use pyloros::filter::{FilterEngine, RequestInfo};

fn rule(method: &str, url: &str) -> Rule {
    Rule {
        method: Some(method.to_string()),
        url: url.to_string(),
        websocket: false,
        git: None,
        branches: None,
        log_body: false,
        protected_branches: None,
    }
}

fn ws_rule(url: &str) -> Rule {
    Rule {
        method: Some("GET".to_string()),
        url: url.to_string(),
        websocket: true,
        git: None,
        branches: None,
        log_body: false,
        protected_branches: None,
    }
}

#[test]
fn test_empty_ruleset_blocks_everything() {
    let t = test_report!("Empty ruleset blocks all requests");

    t.setup("FilterEngine with no rules");
    let engine = FilterEngine::empty();

    let requests = vec![
        ("GET", "https", "example.com", None, "/", None),
        ("POST", "https", "api.example.com", None, "/data", None),
        ("DELETE", "http", "localhost", Some(8080), "/resource", None),
    ];

    for (method, scheme, host, port, path, query) in &requests {
        let req = RequestInfo::http(method, scheme, host, *port, path, *query);
        t.assert_true(
            &format!("{} {} blocked", method, req.full_url()),
            !engine.is_allowed(&req),
        );
    }
}

#[test]
fn test_exact_url_matching() {
    let t = test_report!("Exact URL matching");

    t.setup("Rule: GET https://api.example.com/health");
    let engine = FilterEngine::new(vec![rule("GET", "https://api.example.com/health")]).unwrap();

    let req = RequestInfo::http("GET", "https", "api.example.com", None, "/health", None);
    t.assert_true("Exact match allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("POST", "https", "api.example.com", None, "/health", None);
    t.assert_true("Wrong method blocked", !engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "api.example.com", None, "/other", None);
    t.assert_true("Wrong path blocked", !engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "other.com", None, "/health", None);
    t.assert_true("Wrong host blocked", !engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "http", "api.example.com", None, "/health", None);
    t.assert_true("Wrong scheme blocked", !engine.is_allowed(&req));
}

#[test]
fn test_wildcard_method() {
    let t = test_report!("Wildcard method matches all HTTP methods");

    t.setup("Rule: * https://cdn.example.com/*");
    let engine = FilterEngine::new(vec![rule("*", "https://cdn.example.com/*")]).unwrap();

    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    for method in methods {
        let req = RequestInfo::http(method, "https", "cdn.example.com", None, "/file.js", None);
        t.assert_true(&format!("{} allowed", method), engine.is_allowed(&req));
    }
}

#[test]
fn test_wildcard_host() {
    let t = test_report!("Wildcard host matching");

    t.setup("Rule: GET https://*.github.com/*");
    let engine = FilterEngine::new(vec![rule("GET", "https://*.github.com/*")]).unwrap();

    let req = RequestInfo::http("GET", "https", "api.github.com", None, "/repos", None);
    t.assert_true("api.github.com allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "raw.github.com", None, "/file", None);
    t.assert_true("raw.github.com allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "a.b.c.github.com", None, "/deep", None);
    t.assert_true("a.b.c.github.com allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "github.com", None, "/repos", None);
    t.assert_true(
        "github.com (no subdomain) blocked",
        !engine.is_allowed(&req),
    );
}

#[test]
fn test_wildcard_path() {
    let t = test_report!("Wildcard path matching");

    t.setup("Rule: GET https://api.example.com/users/*/profile");
    let engine =
        FilterEngine::new(vec![rule("GET", "https://api.example.com/users/*/profile")]).unwrap();

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/users/123/profile",
        None,
    );
    t.assert_true("/users/123/profile allowed", engine.is_allowed(&req));

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/users/org/team/member/profile",
        None,
    );
    t.assert_true(
        "/users/org/team/member/profile allowed",
        engine.is_allowed(&req),
    );

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/users/profile",
        None,
    );
    t.assert_true("/users/profile blocked", !engine.is_allowed(&req));
}

#[test]
fn test_query_string_matching() {
    let t = test_report!("Query string matching");

    t.setup("Rule: GET https://api.example.com/search?q=*");
    let engine =
        FilterEngine::new(vec![rule("GET", "https://api.example.com/search?q=*")]).unwrap();

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/search",
        Some("q=test"),
    );
    t.assert_true("q=test allowed", engine.is_allowed(&req));

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/search",
        Some("q=anything%20here"),
    );
    t.assert_true("q=anything allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "api.example.com", None, "/search", None);
    t.assert_true("No query blocked", !engine.is_allowed(&req));

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/search",
        Some("other=param"),
    );
    t.assert_true("Wrong query blocked", !engine.is_allowed(&req));
}

#[test]
fn test_port_matching() {
    let t = test_report!("Port matching");

    t.setup("Rule: GET https://api.example.com:8443/api");
    let engine = FilterEngine::new(vec![rule("GET", "https://api.example.com:8443/api")]).unwrap();

    let req = RequestInfo::http("GET", "https", "api.example.com", Some(8443), "/api", None);
    t.assert_true("Port 8443 allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "api.example.com", Some(443), "/api", None);
    t.assert_true("Port 443 blocked", !engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "api.example.com", None, "/api", None);
    t.assert_true("No port (443) blocked", !engine.is_allowed(&req));
}

#[test]
fn test_default_port_matching() {
    let t = test_report!("Default port 443 matching");

    t.setup("Rule: GET https://api.example.com:443/api");
    let engine = FilterEngine::new(vec![rule("GET", "https://api.example.com:443/api")]).unwrap();

    let req = RequestInfo::http("GET", "https", "api.example.com", Some(443), "/api", None);
    t.assert_true("Explicit 443 allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "api.example.com", None, "/api", None);
    t.assert_true("No port (defaults 443) allowed", engine.is_allowed(&req));
}

#[test]
fn test_multiple_rules() {
    let t = test_report!("Multiple rules matching");

    t.setup("Rules: GET /public/*, POST /data, * cdn.example.com/*");
    let engine = FilterEngine::new(vec![
        rule("GET", "https://api.example.com/public/*"),
        rule("POST", "https://api.example.com/data"),
        rule("*", "https://cdn.example.com/*"),
    ])
    .unwrap();

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/public/info",
        None,
    );
    t.assert_true("GET /public/info allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("POST", "https", "api.example.com", None, "/data", None);
    t.assert_true("POST /data allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("PUT", "https", "cdn.example.com", None, "/file", None);
    t.assert_true("PUT cdn/file allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("DELETE", "https", "api.example.com", None, "/data", None);
    t.assert_true("DELETE /data blocked", !engine.is_allowed(&req));
}

#[test]
fn test_websocket_rules() {
    let t = test_report!("WebSocket vs HTTP rule matching");

    t.setup("Rules: GET /http, ws /socket");
    let engine = FilterEngine::new(vec![
        rule("GET", "https://api.example.com/http"),
        ws_rule("wss://api.example.com/socket"),
    ])
    .unwrap();

    let req = RequestInfo::http("GET", "https", "api.example.com", None, "/http", None);
    t.assert_true("HTTP matches HTTP rule", engine.is_allowed(&req));

    let req = RequestInfo::websocket("https", "api.example.com", None, "/socket", None);
    t.assert_true("WS matches WS rule", engine.is_allowed(&req));

    let req = RequestInfo::websocket("https", "api.example.com", None, "/http", None);
    t.assert_true("WS does NOT match HTTP rule", !engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "api.example.com", None, "/socket", None);
    t.assert_true("HTTP does NOT match WS rule", !engine.is_allowed(&req));
}

#[test]
fn test_case_insensitive_method() {
    let t = test_report!("Case-insensitive method matching");

    t.setup("Rule: get (lowercase) https://api.example.com/test");
    let engine = FilterEngine::new(vec![rule("get", "https://api.example.com/test")]).unwrap();

    let req = RequestInfo::http("GET", "https", "api.example.com", None, "/test", None);
    t.assert_true("GET matches lowercase 'get'", engine.is_allowed(&req));
}

#[test]
fn test_github_like_rules() {
    let t = test_report!("GitHub-like ruleset");

    t.setup("Rules: * api.github.com/*, * *.githubusercontent.com/*, * github.com/*");
    let engine = FilterEngine::new(vec![
        rule("*", "https://api.github.com/*"),
        rule("*", "https://*.githubusercontent.com/*"),
        rule("*", "https://github.com/*"),
    ])
    .unwrap();

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.github.com",
        None,
        "/repos/owner/repo",
        None,
    );
    t.assert_true("GitHub API GET allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("POST", "https", "api.github.com", None, "/graphql", None);
    t.assert_true("GitHub API POST allowed", engine.is_allowed(&req));

    let req = RequestInfo::http(
        "GET",
        "https",
        "raw.githubusercontent.com",
        None,
        "/owner/repo/main/file.txt",
        None,
    );
    t.assert_true("Raw content allowed", engine.is_allowed(&req));

    let req = RequestInfo::http("GET", "https", "github.com", None, "/owner/repo", None);
    t.assert_true("Main site allowed", engine.is_allowed(&req));
}

#[test]
fn test_complex_path_patterns() {
    let t = test_report!("Complex multi-wildcard path patterns");

    t.setup("Rule: GET https://api.example.com/v*/users/*/posts/*");
    let engine = FilterEngine::new(vec![rule(
        "GET",
        "https://api.example.com/v*/users/*/posts/*",
    )])
    .unwrap();

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/v1/users/123/posts/456",
        None,
    );
    t.assert_true("/v1/users/123/posts/456 allowed", engine.is_allowed(&req));

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/v2/users/abc/posts/latest",
        None,
    );
    t.assert_true(
        "/v2/users/abc/posts/latest allowed",
        engine.is_allowed(&req),
    );

    let req = RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/v10/users/org/team/user/posts/2024/01/post",
        None,
    );
    t.assert_true("Deep nested path allowed", engine.is_allowed(&req));
}

#[test]
fn test_request_info_full_url() {
    let t = test_report!("RequestInfo::full_url() formatting");

    let r1 = RequestInfo::http("GET", "https", "example.com", None, "/path", None);
    t.assert_eq(
        "Basic URL",
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
        "URL with port and query",
        &r2.full_url().as_str(),
        &"https://example.com:8443/path?q=1",
    );

    let r3 = RequestInfo::http("GET", "http", "example.com", Some(80), "/path", None);
    t.assert_eq(
        "HTTP default port omitted",
        &r3.full_url().as_str(),
        &"http://example.com/path",
    );

    let r4 = RequestInfo::http("GET", "https", "example.com", Some(443), "/path", None);
    t.assert_eq(
        "HTTPS default port omitted",
        &r4.full_url().as_str(),
        &"https://example.com/path",
    );
}
