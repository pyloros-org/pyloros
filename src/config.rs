//! Configuration parsing and management

use serde::{Deserialize, Deserializer, Serialize};
use std::path::Path;

use crate::error::{Error, Result};

/// Main configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Proxy settings
    #[serde(default)]
    pub proxy: ProxyConfig,

    /// Logging settings
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Allowlist rules
    #[serde(default)]
    pub rules: Vec<Rule>,

    /// Credential injection entries
    #[serde(default)]
    pub credentials: Vec<Credential>,

    /// Approvals feature (opt-in). When present, enables the agent API at
    /// `https://pyloros.internal/` and binds a dashboard listener.
    #[serde(default)]
    pub approvals: Option<ApprovalsConfig>,
}

/// Configuration for the approvals feature.
///
/// Both fields are required when the `[approvals]` section is present.
/// Without the section, the feature is disabled: the agent API returns 404
/// and no dashboard listener is bound.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalsConfig {
    /// Path to the sidecar TOML file where permanent approvals are persisted.
    pub sidecar_file: String,

    /// Address to bind the dashboard listener (plain HTTP).
    /// MUST be an address the sandbox cannot reach — the dashboard has no
    /// built-in authentication; bind isolation is the trust boundary.
    pub dashboard_bind: String,
}

/// A credential to inject into matching outgoing requests.
///
/// Two variants:
/// - `Header`: injects/overwrites a single HTTP header (original behavior)
/// - `AwsSigV4`: re-signs the request with real AWS credentials via SigV4
#[derive(Debug, Clone, Serialize)]
pub enum Credential {
    Header {
        url: String,
        header: String,
        value: String,
    },
    AwsSigV4 {
        url: String,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
}

impl Credential {
    /// The URL pattern for this credential.
    pub fn url(&self) -> &str {
        match self {
            Credential::Header { url, .. } => url,
            Credential::AwsSigV4 { url, .. } => url,
        }
    }
}

/// Raw struct for deserializing credentials from TOML.
/// Detects variant from optional `type` field (default: "header").
#[derive(Deserialize)]
struct CredentialRaw {
    url: String,
    #[serde(default)]
    r#type: Option<String>,
    // header fields
    header: Option<String>,
    value: Option<String>,
    // aws-sigv4 fields
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    session_token: Option<String>,
}

impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = CredentialRaw::deserialize(deserializer)?;
        let cred_type = raw.r#type.as_deref().unwrap_or("header");
        match cred_type {
            "header" => {
                let header = raw.header.ok_or_else(|| {
                    serde::de::Error::custom("header credential requires `header` field")
                })?;
                let value = raw.value.ok_or_else(|| {
                    serde::de::Error::custom("header credential requires `value` field")
                })?;
                Ok(Credential::Header {
                    url: raw.url,
                    header,
                    value,
                })
            }
            "aws-sigv4" => {
                let access_key_id = raw.access_key_id.ok_or_else(|| {
                    serde::de::Error::custom("aws-sigv4 credential requires `access_key_id` field")
                })?;
                let secret_access_key = raw.secret_access_key.ok_or_else(|| {
                    serde::de::Error::custom(
                        "aws-sigv4 credential requires `secret_access_key` field",
                    )
                })?;
                Ok(Credential::AwsSigV4 {
                    url: raw.url,
                    access_key_id,
                    secret_access_key,
                    session_token: raw.session_token,
                })
            }
            other => Err(serde::de::Error::custom(format!(
                "unknown credential type {:?} — must be \"header\" or \"aws-sigv4\"",
                other
            ))),
        }
    }
}

/// Proxy-specific configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// Address to bind the proxy server
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Path to CA certificate for MITM
    pub ca_cert: Option<String>,

    /// Path to CA private key for MITM
    pub ca_key: Option<String>,

    /// Username for proxy authentication (HTTP Basic)
    #[serde(default)]
    pub auth_username: Option<String>,

    /// Password for proxy authentication (supports `${ENV_VAR}` placeholders)
    #[serde(default)]
    pub auth_password: Option<String>,

    /// Override upstream port for all CONNECT forwards (testing only)
    #[serde(default)]
    pub upstream_override_port: Option<u16>,

    /// Path to PEM CA cert to trust for upstream TLS (testing only)
    #[serde(default)]
    pub upstream_tls_ca: Option<String>,

    /// Address to bind the direct HTTPS listener (optional).
    /// When set, the proxy accepts raw TLS connections (not proxy protocol)
    /// and uses SNI to determine the target hostname.
    #[serde(default)]
    pub direct_https_bind: Option<String>,

    /// Address to bind the direct HTTP listener (optional).
    /// When set, the proxy accepts plain HTTP connections (not proxy protocol)
    /// and uses the `Host` header to determine the target hostname.
    #[serde(default)]
    pub direct_http_bind: Option<String>,

    /// Permissive mode: allow unmatched requests through while logging them
    /// as "request_permitted" for traffic discovery. Default: false.
    #[serde(default)]
    pub permissive: bool,

    /// TTL (seconds) for redirect-whitelist entries. See `allow_redirects` on rules.
    #[serde(default = "default_redirect_whitelist_ttl_secs")]
    pub redirect_whitelist_ttl_secs: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            ca_cert: None,
            ca_key: None,
            auth_username: None,
            auth_password: None,
            upstream_override_port: None,
            upstream_tls_ca: None,
            direct_https_bind: None,
            direct_http_bind: None,
            permissive: false,
            redirect_whitelist_ttl_secs: default_redirect_whitelist_ttl_secs(),
        }
    }
}

fn default_bind_address() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_redirect_whitelist_ttl_secs() -> u64 {
    60
}

/// Logging configuration
#[derive(Debug, Clone, Serialize)]
pub struct LoggingConfig {
    /// Log level (error, warn, info, debug, trace)
    pub level: String,

    /// Whether to log allowed requests
    pub log_allowed_requests: bool,

    /// Whether to log blocked requests
    pub log_blocked_requests: bool,

    /// Optional path to structured JSONL audit log file
    pub audit_log: Option<String>,

    /// Maximum bytes to capture per body for log_body rules (default 1 MB)
    pub max_body_log_size: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            log_allowed_requests: true,
            log_blocked_requests: true,
            audit_log: None,
            max_body_log_size: 1_048_576,
        }
    }
}

/// Helper for deserializing `log_requests` as either a bool or a table.
#[derive(Deserialize)]
#[serde(untagged)]
enum LogRequestsValue {
    Bool(bool),
    Table {
        #[serde(default = "default_true")]
        allowed: bool,
        #[serde(default = "default_true")]
        blocked: bool,
    },
}

fn default_true() -> bool {
    true
}

/// Raw helper struct for deserializing LoggingConfig from TOML.
#[derive(Deserialize)]
struct LoggingConfigRaw {
    #[serde(default = "default_log_level")]
    level: String,
    #[serde(default)]
    log_requests: Option<LogRequestsValue>,
    #[serde(default)]
    audit_log: Option<String>,
    #[serde(default = "default_max_body_log_size")]
    max_body_log_size: usize,
}

fn default_max_body_log_size() -> usize {
    1_048_576
}

fn default_log_level() -> String {
    "info".to_string()
}

impl<'de> Deserialize<'de> for LoggingConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = LoggingConfigRaw::deserialize(deserializer)?;
        let (log_allowed, log_blocked) = match raw.log_requests {
            None => (true, true),
            Some(LogRequestsValue::Bool(b)) => (b, b),
            Some(LogRequestsValue::Table { allowed, blocked }) => (allowed, blocked),
        };
        Ok(LoggingConfig {
            level: raw.level,
            log_allowed_requests: log_allowed,
            log_blocked_requests: log_blocked,
            audit_log: raw.audit_log,
            max_body_log_size: raw.max_body_log_size,
        })
    }
}

/// A single allowlist rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    /// HTTP method to match (or "*" for any). Required for HTTP rules, absent for git rules.
    #[serde(default)]
    pub method: Option<String>,

    /// URL pattern to match (supports wildcards)
    pub url: String,

    /// Whether this rule applies to WebSocket connections
    #[serde(default)]
    pub websocket: bool,

    /// Git operation: "fetch", "push", or "*". Mutually exclusive with `method`.
    #[serde(default)]
    pub git: Option<String>,

    /// Branch patterns for git push restriction. Only valid with git = "push" or git = "*".
    #[serde(default)]
    pub branches: Option<Vec<String>>,

    /// URL patterns for redirect targets that should be temporarily whitelisted
    /// when a rule-matched request returns a 3xx response with a matching `Location`.
    /// Use `["*"]` to accept any redirect target. Empty/omitted = redirects not followed.
    #[serde(default)]
    pub allow_redirects: Vec<String>,

    /// Log request and response bodies in the audit log when this rule matches.
    #[serde(default)]
    pub log_body: bool,
}

impl Rule {
    /// Parse a rule from its short-form string representation.
    ///
    /// Examples:
    /// - `"GET https://api.foo.com/*"`
    /// - `"POST https://api.foo.com/v1/*"`
    /// - `"* https://api.foo.com/*"` (any method)
    ///
    /// Used by the approvals feature where agents submit rule strings
    /// rather than full TOML. Git-style rules (`git=fetch …`) are not
    /// supported in v1 of the approvals feature — an agent that needs
    /// one should ask the user to add it to the main config.
    pub fn parse_shortform(s: &str) -> Result<Rule> {
        let trimmed = s.trim();
        let (method, url) = trimmed.split_once(char::is_whitespace).ok_or_else(|| {
            Error::config(format!(
                "approval rule must be 'METHOD URL' (got {:?})",
                trimmed
            ))
        })?;
        let method = method.trim();
        let url = url.trim();
        if method.is_empty() || url.is_empty() {
            return Err(Error::config(format!(
                "approval rule must be 'METHOD URL' (got {:?})",
                trimmed
            )));
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(Error::config(format!(
                "approval rule URL must start with http:// or https:// (got {:?})",
                url
            )));
        }
        Ok(Rule {
            method: Some(method.to_string()),
            url: url.to_string(),
            websocket: false,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        })
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            Error::config(format!(
                "Failed to read config file '{}': {}",
                path.as_ref().display(),
                e
            ))
        })?;

        Self::parse(&content)
    }

    /// Parse configuration from a TOML string
    pub fn parse(content: &str) -> Result<Self> {
        let config: Self =
            toml::from_str(content).map_err(|e| Error::config(format!("Invalid TOML: {}", e)))?;

        // Validate each rule
        for (i, rule) in config.rules.iter().enumerate() {
            Self::validate_rule(i, rule)?;
        }

        // Validate each credential
        for (i, cred) in config.credentials.iter().enumerate() {
            Self::validate_credential(i, cred)?;
        }

        // Validate auth config
        config.validate_auth()?;

        Ok(config)
    }

    /// Validate a single rule for consistency
    fn validate_rule(index: usize, rule: &Rule) -> Result<()> {
        let ctx = |msg: &str| Error::config(format!("Rule #{}: {}", index + 1, msg));

        match (&rule.method, &rule.git) {
            (Some(_), Some(_)) => {
                return Err(ctx(
                    "cannot have both `method` and `git` — use one or the other",
                ));
            }
            (None, None) => {
                return Err(ctx("must have either `method` or `git`"));
            }
            _ => {}
        }

        if rule.websocket && rule.git.is_some() {
            return Err(ctx("`websocket` and `git` are mutually exclusive"));
        }

        if let Some(ref git) = rule.git {
            match git.as_str() {
                "fetch" | "push" | "*" => {}
                other => {
                    return Err(ctx(&format!(
                        "invalid `git` value {:?} — must be \"fetch\", \"push\", or \"*\"",
                        other
                    )));
                }
            }

            if rule.branches.is_some() && git == "fetch" {
                return Err(ctx(
                    "`branches` is only valid with `git = \"push\"` or `git = \"*\"`",
                ));
            }
        }

        if rule.branches.is_some() && rule.git.is_none() {
            return Err(ctx("`branches` is only valid on git rules"));
        }

        // Validate redirect URL patterns. Bare "*" is a shorthand for "any URL"
        // and does not need to parse as a UrlPattern.
        {
            use crate::filter::matcher::UrlPattern;
            for (j, pattern) in rule.allow_redirects.iter().enumerate() {
                if pattern == "*" {
                    continue;
                }
                UrlPattern::new(pattern).map_err(|e| {
                    ctx(&format!(
                        "allow_redirects pattern #{} ({:?}) invalid: {}",
                        j + 1,
                        pattern,
                        e
                    ))
                })?;
            }
        }

        // Validate branch patterns: bare "!" (empty after prefix strip) is an error
        if let Some(ref branches) = rule.branches {
            for (j, pattern) in branches.iter().enumerate() {
                if pattern == "!" {
                    return Err(ctx(&format!(
                        "branch pattern #{} is bare `!` (empty pattern after prefix strip)",
                        j + 1
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate a single credential entry
    fn validate_credential(index: usize, cred: &Credential) -> Result<()> {
        let ctx = |msg: &str| Error::config(format!("Credential #{}: {}", index + 1, msg));

        // Validate URL pattern syntax
        use crate::filter::matcher::UrlPattern;
        UrlPattern::new(cred.url()).map_err(|e| ctx(&format!("invalid URL pattern: {}", e)))?;

        match cred {
            Credential::Header { header, .. } => {
                if header.is_empty() {
                    return Err(ctx("header name must not be empty"));
                }
            }
            Credential::AwsSigV4 {
                access_key_id,
                secret_access_key,
                ..
            } => {
                if access_key_id.is_empty() {
                    return Err(ctx("access_key_id must not be empty"));
                }
                if secret_access_key.is_empty() {
                    return Err(ctx("secret_access_key must not be empty"));
                }
            }
        }

        Ok(())
    }

    /// Validate proxy authentication config: both fields must be set or both absent.
    fn validate_auth(&self) -> Result<()> {
        match (&self.proxy.auth_username, &self.proxy.auth_password) {
            (Some(_), None) => Err(Error::config(
                "auth_username is set but auth_password is missing",
            )),
            (None, Some(_)) => Err(Error::config(
                "auth_password is set but auth_username is missing",
            )),
            _ => Ok(()),
        }
    }

    /// Resolve proxy authentication credentials.
    ///
    /// Returns `None` if auth is not configured.
    /// Resolves `${ENV_VAR}` placeholders in `auth_password`.
    pub fn resolved_auth(&self) -> Result<Option<(String, String)>> {
        match (&self.proxy.auth_username, &self.proxy.auth_password) {
            (Some(username), Some(password)) => {
                let resolved_password = resolve_credential_value(password)?;
                Ok(Some((username.clone(), resolved_password)))
            }
            _ => Ok(None),
        }
    }

    /// Create a minimal configuration with just the essentials
    pub fn minimal(bind_address: String, ca_cert: String, ca_key: String) -> Self {
        Self {
            proxy: ProxyConfig {
                bind_address,
                ca_cert: Some(ca_cert),
                ca_key: Some(ca_key),
                auth_username: None,
                auth_password: None,
                upstream_override_port: None,
                upstream_tls_ca: None,
                direct_https_bind: None,
                direct_http_bind: None,
                permissive: false,
                redirect_whitelist_ttl_secs: default_redirect_whitelist_ttl_secs(),
            },
            logging: LoggingConfig::default(),
            rules: Vec::new(),
            credentials: Vec::new(),
            approvals: None,
        }
    }

    /// Extract literal hostnames from all rule URL patterns.
    ///
    /// Returns `(literal_hosts, wildcard_hosts)`:
    /// - `literal_hosts`: hostnames that can go in `/etc/hosts` (no wildcards)
    /// - `wildcard_hosts`: host patterns containing `*` (skipped, for user warnings)
    ///
    /// Hostnames are deduplicated and sorted.
    pub fn extract_hosts(&self) -> (Vec<String>, Vec<String>) {
        let mut literal = std::collections::BTreeSet::new();
        let mut wildcard = std::collections::BTreeSet::new();

        for rule in &self.rules {
            if let Some(host) = extract_host_from_url(&rule.url) {
                if host.contains('*') {
                    wildcard.insert(host);
                } else {
                    literal.insert(host);
                }
            }
        }

        for cred in &self.credentials {
            if let Some(host) = extract_host_from_url(cred.url()) {
                if host.contains('*') {
                    wildcard.insert(host);
                } else {
                    literal.insert(host);
                }
            }
        }

        (
            literal.into_iter().collect(),
            wildcard.into_iter().collect(),
        )
    }
}

/// Extract the host portion from a URL pattern like `https://host.example.com/path`.
/// Returns the host without port, or None if the URL can't be parsed.
fn extract_host_from_url(url: &str) -> Option<String> {
    // Strip scheme (e.g. "https://", "http://", "wss://")
    let after_scheme = url.find("://").map(|i| &url[i + 3..])?;
    // Take up to the next '/' or ':'
    let host = after_scheme
        .split(['/', ':'])
        .next()
        .unwrap_or(after_scheme);
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

/// Resolve `${ENV_VAR}` placeholders in a credential value string.
///
/// Replaces all `${...}` patterns with the corresponding environment variable value.
/// Returns an error if any referenced variable is not set.
pub fn resolve_credential_value(value: &str) -> Result<String> {
    let mut result = String::with_capacity(value.len());
    let mut rest = value;

    while let Some(start) = rest.find("${") {
        result.push_str(&rest[..start]);
        let after_open = &rest[start + 2..];
        let end = after_open
            .find('}')
            .ok_or_else(|| Error::config("unclosed ${...} in credential value"))?;
        let var_name = &after_open[..end];
        if var_name.is_empty() {
            return Err(Error::config("empty variable name in ${} placeholder"));
        }
        let var_value = std::env::var(var_name).map_err(|_| {
            Error::config(format!(
                "environment variable '{}' is not set (required by credential)",
                var_name
            ))
        })?;
        result.push_str(&var_value);
        rest = &after_open[end + 1..];
    }
    result.push_str(rest);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    fn assert_config_rejects(title: &str, toml_input: &str, expected_substr: Option<&str>) {
        let t = pyloros_test_support::TestReport::new(
            &format!("pyloros::config::tests::{}", title.replace(' ', "_")),
            title,
            file!(),
            line!(),
        );
        t.setup(format!("Parse TOML config:\n```\n{}\n```", toml_input));
        let result = Config::parse(toml_input);
        t.assert_true("should be error", result.is_err());
        if let Some(needle) = expected_substr {
            t.assert_contains("error message", &result.unwrap_err().to_string(), needle);
        }
    }

    #[test]
    fn test_parse_minimal_config() {
        let t = test_report!("Parse minimal config");
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:3128"
ca_cert = "/path/to/ca.crt"
ca_key = "/path/to/ca.key"
"#;

        let config = Config::parse(toml).unwrap();
        t.assert_eq(
            "bind_address",
            &config.proxy.bind_address.as_str(),
            &"127.0.0.1:3128",
        );
        t.assert_eq(
            "ca_cert",
            &config.proxy.ca_cert,
            &Some("/path/to/ca.crt".to_string()),
        );
        t.assert_eq(
            "ca_key",
            &config.proxy.ca_key,
            &Some("/path/to/ca.key".to_string()),
        );
        t.assert_true("no rules", config.rules.is_empty());
    }

    #[test]
    fn test_parse_config_with_rules() {
        let t = test_report!("Parse config with rules");
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:8080"

[[rules]]
method = "GET"
url = "https://api.example.com/health"

[[rules]]
method = "POST"
url = "https://api.example.com/users/*/profile"

[[rules]]
method = "*"
url = "https://*.github.com/*"

[[rules]]
method = "GET"
url = "wss://realtime.example.com/socket"
websocket = true
"#;

        let config = Config::parse(toml).unwrap();
        t.assert_eq("rule count", &config.rules.len(), &4usize);
        t.assert_eq(
            "rule[0] method",
            &config.rules[0].method.as_deref(),
            &Some("GET"),
        );
        t.assert_eq(
            "rule[0] url",
            &config.rules[0].url.as_str(),
            &"https://api.example.com/health",
        );
        t.assert_true("rule[0] not websocket", !config.rules[0].websocket);
        t.assert_eq(
            "rule[1] method",
            &config.rules[1].method.as_deref(),
            &Some("POST"),
        );
        t.assert_eq(
            "rule[2] method",
            &config.rules[2].method.as_deref(),
            &Some("*"),
        );
        t.assert_true("rule[3] websocket", config.rules[3].websocket);
    }

    #[test]
    fn test_default_values() {
        let t = test_report!("Default config values");
        let config = Config::parse("").unwrap();

        t.assert_eq(
            "bind_address",
            &config.proxy.bind_address.as_str(),
            &"127.0.0.1:8080",
        );
        t.assert_eq("log level", &config.logging.level.as_str(), &"info");
        t.assert_true("log allowed default", config.logging.log_allowed_requests);
        t.assert_true("log blocked default", config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_section_without_level_defaults_to_info() {
        let t = test_report!("Logging section without level key defaults to info");
        let toml = r#"
[logging]
log_requests = true
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("level", &config.logging.level.as_str(), &"info");
    }

    #[test]
    fn test_logging_config_bool_false() {
        let t = test_report!("log_requests = false disables both");
        let toml = r#"
[logging]
level = "debug"
log_requests = false
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("level", &config.logging.level.as_str(), &"debug");
        t.assert_true("allowed disabled", !config.logging.log_allowed_requests);
        t.assert_true("blocked disabled", !config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_bool_true() {
        let t = test_report!("log_requests = true enables both");
        let toml = r#"
[logging]
log_requests = true
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true("allowed enabled", config.logging.log_allowed_requests);
        t.assert_true("blocked enabled", config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_table_mixed() {
        let t = test_report!("log_requests table with mixed values");
        let toml = r#"
[logging]
log_requests = { allowed = true, blocked = false }
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true("allowed enabled", config.logging.log_allowed_requests);
        t.assert_true("blocked disabled", !config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_table_partial_defaults() {
        let t = test_report!("log_requests table with partial keys defaults missing");
        let toml = r#"
[logging]
log_requests = { blocked = false }
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true(
            "allowed defaults to true",
            config.logging.log_allowed_requests,
        );
        t.assert_true("blocked set to false", !config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_omitted() {
        let t = test_report!("Omitted log_requests defaults to both true");
        let toml = r#"
[logging]
level = "warn"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true("allowed enabled", config.logging.log_allowed_requests);
        t.assert_true("blocked enabled", config.logging.log_blocked_requests);
    }

    #[test]
    fn test_upstream_override_fields() {
        let t = test_report!("Upstream override config fields");
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:0"
ca_cert = "/path/to/ca.crt"
ca_key = "/path/to/ca.key"
upstream_override_port = 9443
upstream_tls_ca = "/path/to/upstream-ca.crt"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq(
            "override port",
            &config.proxy.upstream_override_port,
            &Some(9443),
        );
        t.assert_eq(
            "upstream TLS CA",
            &config.proxy.upstream_tls_ca,
            &Some("/path/to/upstream-ca.crt".to_string()),
        );
    }

    #[test]
    fn test_upstream_override_fields_default_to_none() {
        let t = test_report!("Upstream overrides default to None");
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:8080"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq(
            "override port None",
            &config.proxy.upstream_override_port,
            &None,
        );
        t.assert_eq(
            "upstream TLS CA None",
            &config.proxy.upstream_tls_ca,
            &None::<String>,
        );
    }

    #[test]
    fn test_invalid_toml() {
        assert_config_rejects("Invalid TOML rejected", "this is not valid toml [[[", None);
    }

    #[test]
    fn test_git_rule_fetch() {
        let t = test_report!("Git fetch rule parses correctly");
        let toml = r#"
[[rules]]
git = "fetch"
url = "https://github.com/myorg/*"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("rule count", &config.rules.len(), &1usize);
        t.assert_eq("git", &config.rules[0].git.as_deref(), &Some("fetch"));
        t.assert_true("method is None", config.rules[0].method.is_none());
        t.assert_true("branches is None", config.rules[0].branches.is_none());
    }

    #[test]
    fn test_git_rule_push_with_branches() {
        let t = test_report!("Git push rule with branches parses correctly");
        let toml = r#"
[[rules]]
git = "push"
url = "https://github.com/myorg/repo"
branches = ["feature/*", "fix/*"]
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("rule count", &config.rules.len(), &1usize);
        t.assert_eq("git", &config.rules[0].git.as_deref(), &Some("push"));
        let branches = config.rules[0].branches.as_ref().unwrap();
        t.assert_eq("branch count", &branches.len(), &2usize);
        t.assert_eq("branch[0]", &branches[0].as_str(), &"feature/*");
        t.assert_eq("branch[1]", &branches[1].as_str(), &"fix/*");
    }

    #[test]
    fn test_git_rule_star() {
        let t = test_report!("Git * rule parses correctly");
        let toml = r#"
[[rules]]
git = "*"
url = "https://github.com/*"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("git", &config.rules[0].git.as_deref(), &Some("*"));
    }

    #[test]
    fn test_git_rule_validation_both_method_and_git() {
        assert_config_rejects(
            "Reject rule with both method and git",
            "[[rules]]\nmethod = \"GET\"\ngit = \"fetch\"\nurl = \"https://example.com/*\"",
            Some("both"),
        );
    }

    #[test]
    fn test_git_rule_validation_neither_method_nor_git() {
        assert_config_rejects(
            "Reject rule with neither method nor git",
            "[[rules]]\nurl = \"https://example.com/*\"",
            Some("either"),
        );
    }

    #[test]
    fn test_git_rule_validation_websocket_with_git() {
        assert_config_rejects(
            "Reject rule with websocket and git",
            "[[rules]]\ngit = \"fetch\"\nurl = \"https://example.com/*\"\nwebsocket = true",
            Some("mutually exclusive"),
        );
    }

    #[test]
    fn test_git_rule_validation_invalid_git_value() {
        assert_config_rejects(
            "Reject invalid git operation value",
            "[[rules]]\ngit = \"clone\"\nurl = \"https://example.com/*\"",
            Some("invalid"),
        );
    }

    #[test]
    fn test_git_rule_validation_branches_with_fetch() {
        assert_config_rejects(
            "Reject branches on fetch-only rule",
            "[[rules]]\ngit = \"fetch\"\nurl = \"https://example.com/*\"\nbranches = [\"main\"]",
            Some("branches"),
        );
    }

    #[test]
    fn test_git_rule_validation_branches_on_http_rule() {
        assert_config_rejects(
            "Reject branches on HTTP rule",
            "[[rules]]\nmethod = \"POST\"\nurl = \"https://example.com/*\"\nbranches = [\"main\"]",
            Some("git rules"),
        );
    }

    #[test]
    fn test_git_rule_validation_bare_bang_branch() {
        assert_config_rejects(
            "Reject bare ! branch pattern",
            "[[rules]]\ngit = \"push\"\nurl = \"https://example.com/*\"\nbranches = [\"!\"]",
            Some("bare `!`"),
        );
    }

    #[test]
    fn test_git_rule_with_deny_branch_patterns_parses() {
        let t = test_report!("Git push rule with deny branch patterns parses correctly");
        let toml = r#"
[[rules]]
git = "push"
url = "https://github.com/myorg/repo"
branches = ["*", "!main", "!release/*"]
"#;
        let config = Config::parse(toml).unwrap();
        let branches = config.rules[0].branches.as_ref().unwrap();
        t.assert_eq("branch count", &branches.len(), &3usize);
        t.assert_eq("branch[0]", &branches[0].as_str(), &"*");
        t.assert_eq("branch[1]", &branches[1].as_str(), &"!main");
        t.assert_eq("branch[2]", &branches[2].as_str(), &"!release/*");
    }

    #[test]
    fn test_git_rule_deny_only_branches_parses() {
        let t = test_report!("Git push rule with deny-only branch patterns parses correctly");
        let toml = r#"
[[rules]]
git = "push"
url = "https://github.com/myorg/repo"
branches = ["!main"]
"#;
        let config = Config::parse(toml).unwrap();
        let branches = config.rules[0].branches.as_ref().unwrap();
        t.assert_eq("branch count", &branches.len(), &1usize);
        t.assert_eq("branch[0]", &branches[0].as_str(), &"!main");
    }

    // --- Credential config tests ---

    #[test]
    fn test_parse_credentials() {
        let t = test_report!("Parse [[credentials]] with all fields");
        let toml = r#"
[[credentials]]
url = "https://api.example.com/*"
header = "x-api-key"
value = "my-secret-key"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("credential count", &config.credentials.len(), &1usize);
        t.assert_eq(
            "url",
            &config.credentials[0].url(),
            &"https://api.example.com/*",
        );
        match &config.credentials[0] {
            Credential::Header { header, value, .. } => {
                t.assert_eq("header", &header.as_str(), &"x-api-key");
                t.assert_eq("value", &value.as_str(), &"my-secret-key");
            }
            other => panic!("expected Header, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_credentials_backward_compat() {
        let t = test_report!("Header credential without type field (backward compat)");
        let toml = r#"
[[credentials]]
url = "https://api.example.com/*"
header = "x-api-key"
value = "my-secret-key"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true(
            "parsed as Header",
            matches!(&config.credentials[0], Credential::Header { .. }),
        );
    }

    #[test]
    fn test_parse_credentials_explicit_header_type() {
        let t = test_report!("Header credential with explicit type = header");
        let toml = r#"
[[credentials]]
type = "header"
url = "https://api.example.com/*"
header = "x-api-key"
value = "my-secret-key"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true(
            "parsed as Header",
            matches!(&config.credentials[0], Credential::Header { .. }),
        );
    }

    #[test]
    fn test_parse_aws_sigv4_credential() {
        let t = test_report!("Parse AWS SigV4 credential");
        let toml = r#"
[[credentials]]
type = "aws-sigv4"
url = "https://*.amazonaws.com/*"
access_key_id = "AKIAIOSFODNN7EXAMPLE"
secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
session_token = "FwoGZXIvYXdzEBYaD..."
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("credential count", &config.credentials.len(), &1usize);
        match &config.credentials[0] {
            Credential::AwsSigV4 {
                url,
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                t.assert_eq("url", &url.as_str(), &"https://*.amazonaws.com/*");
                t.assert_eq("key", &access_key_id.as_str(), &"AKIAIOSFODNN7EXAMPLE");
                t.assert_eq(
                    "secret",
                    &secret_access_key.as_str(),
                    &"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                );
                t.assert_eq(
                    "token",
                    &session_token.as_deref(),
                    &Some("FwoGZXIvYXdzEBYaD..."),
                );
            }
            other => panic!("expected AwsSigV4, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_aws_sigv4_no_session_token() {
        let t = test_report!("AWS SigV4 credential without session_token");
        let toml = r#"
[[credentials]]
type = "aws-sigv4"
url = "https://*.amazonaws.com/*"
access_key_id = "AKIAIOSFODNN7EXAMPLE"
secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"#;
        let config = Config::parse(toml).unwrap();
        match &config.credentials[0] {
            Credential::AwsSigV4 { session_token, .. } => {
                t.assert_true("no session token", session_token.is_none());
            }
            other => panic!("expected AwsSigV4, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_mixed_credentials() {
        let t = test_report!("Mixed header and aws-sigv4 credentials");
        let toml = r#"
[[credentials]]
url = "https://api.example.com/*"
header = "x-api-key"
value = "my-secret"

[[credentials]]
type = "aws-sigv4"
url = "https://*.amazonaws.com/*"
access_key_id = "AKID"
secret_access_key = "SECRET"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("credential count", &config.credentials.len(), &2usize);
        t.assert_true(
            "first is Header",
            matches!(&config.credentials[0], Credential::Header { .. }),
        );
        t.assert_true(
            "second is AwsSigV4",
            matches!(&config.credentials[1], Credential::AwsSigV4 { .. }),
        );
    }

    #[test]
    fn test_parse_no_credentials() {
        let t = test_report!("Config with no credentials (backward compat)");
        let config = Config::parse("").unwrap();
        t.assert_true("empty credentials", config.credentials.is_empty());
    }

    #[test]
    fn test_credential_reject_empty_header() {
        assert_config_rejects(
            "Reject credential with empty header name",
            "[[credentials]]\nurl = \"https://api.example.com/*\"\nheader = \"\"\nvalue = \"secret\"",
            Some("header"),
        );
    }

    #[test]
    fn test_credential_reject_invalid_url_pattern() {
        assert_config_rejects(
            "Reject credential with invalid URL pattern",
            "[[credentials]]\nurl = \"not-a-url\"\nheader = \"x-api-key\"\nvalue = \"secret\"",
            Some("URL pattern"),
        );
    }

    #[test]
    fn test_credential_reject_unknown_type() {
        assert_config_rejects(
            "Reject credential with unknown type",
            "[[credentials]]\ntype = \"oauth2\"\nurl = \"https://api.example.com/*\"",
            None,
        );
    }

    #[test]
    fn test_credential_reject_aws_empty_access_key() {
        assert_config_rejects(
            "Reject aws-sigv4 credential with empty access_key_id",
            "[[credentials]]\ntype = \"aws-sigv4\"\nurl = \"https://*.amazonaws.com/*\"\naccess_key_id = \"\"\nsecret_access_key = \"SECRET\"",
            Some("access_key_id"),
        );
    }

    #[test]
    fn test_credential_reject_aws_missing_secret() {
        assert_config_rejects(
            "Reject aws-sigv4 credential missing secret_access_key",
            "[[credentials]]\ntype = \"aws-sigv4\"\nurl = \"https://*.amazonaws.com/*\"\naccess_key_id = \"AKID\"",
            None,
        );
    }

    #[test]
    fn test_resolve_credential_value_env_var() {
        let t = test_report!("${ENV_VAR} resolution works");
        std::env::set_var("TEST_CRED_KEY_ABC", "resolved-value");
        let result = resolve_credential_value("${TEST_CRED_KEY_ABC}").unwrap();
        t.assert_eq("resolved", &result.as_str(), &"resolved-value");
        std::env::remove_var("TEST_CRED_KEY_ABC");
    }

    #[test]
    fn test_resolve_credential_value_unset_var() {
        let t = test_report!("${UNSET_VAR} fails with descriptive error");
        std::env::remove_var("TEST_CRED_UNSET_XYZ");
        let result = resolve_credential_value("${TEST_CRED_UNSET_XYZ}");
        t.assert_true("error", result.is_err());
        let err = result.unwrap_err().to_string();
        t.assert_contains("names the variable", &err, "TEST_CRED_UNSET_XYZ");
    }

    #[test]
    fn test_resolve_credential_value_mixed() {
        let t = test_report!("Mixed literal + env var resolves correctly");
        std::env::set_var("TEST_CRED_TOKEN_MIX", "tok123");
        let result = resolve_credential_value("Bearer ${TEST_CRED_TOKEN_MIX}").unwrap();
        t.assert_eq("resolved", &result.as_str(), &"Bearer tok123");
        std::env::remove_var("TEST_CRED_TOKEN_MIX");
    }

    #[test]
    fn test_resolve_credential_value_literal_only() {
        let t = test_report!("Plain literal with no placeholders passes through");
        let result = resolve_credential_value("just-a-literal").unwrap();
        t.assert_eq("passthrough", &result.as_str(), &"just-a-literal");
    }

    #[test]
    fn test_audit_log_config() {
        let t = test_report!("Parse config with audit_log path");
        let toml = r#"
[logging]
level = "info"
audit_log = "/var/log/pyloros/audit.jsonl"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq(
            "audit_log",
            &config.logging.audit_log,
            &Some("/var/log/pyloros/audit.jsonl".to_string()),
        );
    }

    #[test]
    fn test_audit_log_defaults_to_none() {
        let t = test_report!("Omitted audit_log defaults to None");
        let config = Config::parse("").unwrap();
        t.assert_eq("audit_log", &config.logging.audit_log, &None::<String>);
    }

    // --- Proxy auth config tests ---

    #[test]
    fn test_parse_auth_config() {
        let t = test_report!("Parse config with auth fields");
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:8080"
auth_username = "admin"
auth_password = "secret"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq(
            "auth_username",
            &config.proxy.auth_username,
            &Some("admin".to_string()),
        );
        t.assert_eq(
            "auth_password",
            &config.proxy.auth_password,
            &Some("secret".to_string()),
        );
    }

    #[test]
    fn test_parse_auth_config_only_username() {
        let t = test_report!("Reject config with only auth_username");
        let toml = r#"
[proxy]
auth_username = "admin"
"#;
        let result = Config::parse(toml);
        t.assert_true("parse error", result.is_err());
        let err = result.unwrap_err().to_string();
        t.assert_contains("error mentions auth_password", &err, "auth_password");
    }

    #[test]
    fn test_parse_auth_config_only_password() {
        let t = test_report!("Reject config with only auth_password");
        let toml = r#"
[proxy]
auth_password = "secret"
"#;
        let result = Config::parse(toml);
        t.assert_true("parse error", result.is_err());
        let err = result.unwrap_err().to_string();
        t.assert_contains("error mentions auth_username", &err, "auth_username");
    }

    #[test]
    fn test_parse_auth_config_none() {
        let t = test_report!("Config without auth fields works (backward compat)");
        let config = Config::parse("").unwrap();
        t.assert_true(
            "auth_username is None",
            config.proxy.auth_username.is_none(),
        );
        t.assert_true(
            "auth_password is None",
            config.proxy.auth_password.is_none(),
        );
    }

    #[test]
    fn test_resolved_auth_env_var() {
        let t = test_report!("resolved_auth resolves ${ENV_VAR} in password");
        std::env::set_var("TEST_PROXY_AUTH_PW_123", "resolved-pw");
        let toml = r#"
[proxy]
auth_username = "user1"
auth_password = "${TEST_PROXY_AUTH_PW_123}"
"#;
        let config = Config::parse(toml).unwrap();
        let auth = config.resolved_auth().unwrap();
        t.assert_eq(
            "resolved auth",
            &auth,
            &Some(("user1".to_string(), "resolved-pw".to_string())),
        );
        std::env::remove_var("TEST_PROXY_AUTH_PW_123");
    }

    #[test]
    fn test_resolved_auth_none() {
        let t = test_report!("resolved_auth returns None when not configured");
        let config = Config::parse("").unwrap();
        let auth = config.resolved_auth().unwrap();
        t.assert_eq("no auth", &auth, &None);
    }

    #[test]
    fn test_allow_redirects_defaults_empty() {
        let t = test_report!("Rule allow_redirects defaults to empty vec");
        let toml = r#"
[[rules]]
method = "GET"
url = "https://example.com/*"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true(
            "allow_redirects empty",
            config.rules[0].allow_redirects.is_empty(),
        );
    }

    #[test]
    fn test_allow_redirects_parses_list() {
        let t = test_report!("Rule allow_redirects parses a list of URL patterns");
        let toml = r#"
[[rules]]
method = "GET"
url = "https://github.com/*/releases/download/*"
allow_redirects = ["https://release-assets.githubusercontent.com/*", "*"]
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq(
            "allow_redirects length",
            &config.rules[0].allow_redirects.len(),
            &2usize,
        );
        t.assert_eq(
            "first pattern",
            &config.rules[0].allow_redirects[0].as_str(),
            &"https://release-assets.githubusercontent.com/*",
        );
        t.assert_eq(
            "second pattern",
            &config.rules[0].allow_redirects[1].as_str(),
            &"*",
        );
    }

    #[test]
    fn test_allow_redirects_rejects_invalid_pattern() {
        assert_config_rejects(
            "Invalid allow_redirects pattern rejected",
            r#"
[[rules]]
method = "GET"
url = "https://example.com/*"
allow_redirects = ["not a url"]
"#,
            Some("allow_redirects pattern"),
        );
    }

    #[test]
    fn test_redirect_whitelist_ttl_default() {
        let t = test_report!("redirect_whitelist_ttl_secs defaults to 60");
        let config = Config::parse("").unwrap();
        t.assert_eq(
            "ttl default",
            &config.proxy.redirect_whitelist_ttl_secs,
            &60u64,
        );
    }

    #[test]
    fn test_redirect_whitelist_ttl_override() {
        let t = test_report!("redirect_whitelist_ttl_secs can be overridden in config");
        let toml = r#"
[proxy]
redirect_whitelist_ttl_secs = 120
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq(
            "ttl override",
            &config.proxy.redirect_whitelist_ttl_secs,
            &120u64,
        );
    }
}
