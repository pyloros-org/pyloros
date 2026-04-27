//! Short-lived global whitelist of follow-up URLs permitted by inspecting
//! responses from already-allowed requests.
//!
//! Two sources currently feed this whitelist:
//!
//! - **Redirects**: when a rule-matched request returns a 3xx with a `Location`
//!   header that matches the rule's `allow_redirects` patterns, the resolved
//!   target URL is inserted (method-agnostic, carrying the origin rule's
//!   redirect patterns so further redirects in the chain can be evaluated
//!   against the same policy).
//! - **LFS batch responses**: when a successful Git-LFS batch response advertises
//!   `objects[*].actions.{download,upload,verify}.href` URLs (often on a different
//!   host), each is inserted method-pinned (`download`→GET, `upload`→PUT,
//!   `verify`→POST) so the LFS client can complete the transfer.
//!
//! Subsequent requests to a whitelisted URL are allowed regardless of other
//! rules, provided the method matches (when the entry is method-pinned) and
//! the entry has not expired.

use crate::filter::matcher::UrlPattern;
use hyper::http::Method;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

/// What populated a whitelist entry. Surfaced on lookup so callers can record
/// the right audit reason and pick the correct `FilterResult` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhitelistSource {
    Redirect,
    LfsAction,
}

struct Entry {
    expires_at: Instant,
    /// `None` = matches any method (redirect entries). `Some(m)` = method-pinned.
    method: Option<Method>,
    source: WhitelistSource,
    /// Origin rule's `allow_redirects` patterns — only meaningful for redirect entries
    /// so chained redirects can be validated against the same policy.
    redirect_patterns: Option<Arc<Vec<UrlPattern>>>,
}

/// Result of a successful whitelist lookup.
pub struct WhitelistHit {
    pub source: WhitelistSource,
    pub redirect_patterns: Option<Arc<Vec<UrlPattern>>>,
}

/// Global, TTL-bounded whitelist of URLs permitted via response inspection.
pub struct DynamicWhitelist {
    inner: Mutex<LruCache<String, Entry>>,
    default_ttl: Duration,
}

impl DynamicWhitelist {
    pub fn new(default_ttl: Duration, capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1024).unwrap());
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
            default_ttl,
        }
    }

    /// Look up a URL for the given request method. Returns the entry if present,
    /// unexpired, and the entry's method matches (or the entry is method-agnostic).
    pub fn get(&self, url: &str, method: &Method) -> Option<WhitelistHit> {
        let mut cache = self.inner.lock().unwrap();
        if let Some(entry) = cache.get(url) {
            if Instant::now() >= entry.expires_at {
                cache.pop(url);
                return None;
            }
            let method_ok = match &entry.method {
                None => true,
                Some(m) => m == method,
            };
            if !method_ok {
                return None;
            }
            return Some(WhitelistHit {
                source: entry.source,
                redirect_patterns: entry.redirect_patterns.clone(),
            });
        }
        None
    }

    /// Insert a redirect-sourced whitelist entry. Method-agnostic; uses the
    /// configured default TTL. `redirect_patterns` carries the origin rule's
    /// `allow_redirects` so chained redirects can be validated.
    pub fn insert_redirect(&self, url: String, redirect_patterns: Arc<Vec<UrlPattern>>) {
        let entry = Entry {
            expires_at: Instant::now() + self.default_ttl,
            method: None,
            source: WhitelistSource::Redirect,
            redirect_patterns: Some(redirect_patterns),
        };
        self.inner.lock().unwrap().put(url, entry);
    }

    /// Insert an LFS-action whitelist entry, pinned to a specific method.
    /// `ttl` overrides the default when provided (typically from the LFS action's
    /// `expires_at`/`expires_in`); falls back to the default TTL otherwise.
    pub fn insert_lfs_action(&self, url: String, method: Method, ttl: Option<Duration>) {
        let entry = Entry {
            expires_at: Instant::now() + ttl.unwrap_or(self.default_ttl),
            method: Some(method),
            source: WhitelistSource::LfsAction,
            redirect_patterns: None,
        };
        self.inner.lock().unwrap().put(url, entry);
    }
}

/// Resolve a `Location` header value against a request URL. Absolute URLs are
/// returned as-is; relative URLs are joined against the base. Returns None if
/// the resulting URL cannot be parsed (malformed header).
pub fn resolve_location(request_url: &str, location: &str) -> Option<String> {
    let base = Url::parse(request_url).ok()?;
    base.join(location).ok().map(|u| u.to_string())
}

/// Check whether a URL matches any of the given patterns.
pub fn url_matches_any(url_str: &str, patterns: &[UrlPattern]) -> bool {
    let Ok(url) = Url::parse(url_str) else {
        return false;
    };
    let scheme = url.scheme();
    let host = match url.host_str() {
        Some(h) => h,
        None => return false,
    };
    let port = url.port();
    let path = url.path();
    let query = url.query();
    patterns
        .iter()
        .any(|p| p.matches(scheme, host, port, path, query))
}

/// If `status` is a redirect and `location` is present, resolve the target,
/// check it against `patterns`, and insert into `whitelist` on match.
/// Returns the resolved URL (if any action was taken) for logging.
pub fn maybe_whitelist_redirect(
    status: u16,
    location: Option<&str>,
    request_url: &str,
    patterns: &Arc<Vec<UrlPattern>>,
    whitelist: &DynamicWhitelist,
) -> Option<String> {
    if !(300..400).contains(&status) {
        return None;
    }
    let loc = location?;
    let resolved = resolve_location(request_url, loc)?;
    if !url_matches_any(&resolved, patterns) {
        return None;
    }
    whitelist.insert_redirect(resolved.clone(), patterns.clone());
    Some(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    fn make_patterns(patterns: &[&str]) -> Arc<Vec<UrlPattern>> {
        Arc::new(
            patterns
                .iter()
                .map(|p| UrlPattern::new(p).unwrap())
                .collect(),
        )
    }

    #[test]
    fn test_insert_get_roundtrip() {
        let t = test_report!("Insert redirect then get returns the same redirect patterns");
        let wl = DynamicWhitelist::new(Duration::from_secs(60), 10);
        let patterns = make_patterns(&["https://cdn.example.com/*"]);
        wl.insert_redirect("https://cdn.example.com/x".to_string(), patterns.clone());

        let got = wl.get("https://cdn.example.com/x", &Method::GET);
        t.assert_true("entry found", got.is_some());
        let hit = got.unwrap();
        t.assert_true(
            "source=Redirect",
            matches!(hit.source, WhitelistSource::Redirect),
        );
        t.assert_eq(
            "pattern count",
            &hit.redirect_patterns.unwrap().len(),
            &1usize,
        );
    }

    #[test]
    fn test_redirect_entry_method_agnostic() {
        let t = test_report!("Redirect entries match any method");
        let wl = DynamicWhitelist::new(Duration::from_secs(60), 10);
        wl.insert_redirect(
            "https://cdn.example.com/x".to_string(),
            make_patterns(&["*://*/*"]),
        );
        for m in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
            t.assert_true(
                &format!("method {} accepted", m),
                wl.get("https://cdn.example.com/x", &m).is_some(),
            );
        }
    }

    #[test]
    fn test_lfs_entry_method_pinned() {
        let t = test_report!("LFS-action entries reject other methods");
        let wl = DynamicWhitelist::new(Duration::from_secs(60), 10);
        wl.insert_lfs_action(
            "https://lfs.example.com/objects/abc/verify".to_string(),
            Method::POST,
            None,
        );
        t.assert_true(
            "POST accepted",
            wl.get("https://lfs.example.com/objects/abc/verify", &Method::POST)
                .is_some(),
        );
        t.assert_true(
            "GET rejected",
            wl.get("https://lfs.example.com/objects/abc/verify", &Method::GET)
                .is_none(),
        );
        t.assert_true(
            "PUT rejected",
            wl.get("https://lfs.example.com/objects/abc/verify", &Method::PUT)
                .is_none(),
        );
    }

    #[test]
    fn test_lfs_entry_uses_explicit_ttl() {
        let t = test_report!("insert_lfs_action ttl override is honored over default");
        let wl = DynamicWhitelist::new(Duration::from_secs(3600), 10);
        wl.insert_lfs_action(
            "https://x.example.com/upload".to_string(),
            Method::PUT,
            Some(Duration::from_millis(1)),
        );
        std::thread::sleep(Duration::from_millis(10));
        t.assert_true(
            "explicit short ttl expired despite long default",
            wl.get("https://x.example.com/upload", &Method::PUT)
                .is_none(),
        );
    }

    #[test]
    fn test_lfs_source_surfaced_on_hit() {
        let t = test_report!("LFS-action hits report WhitelistSource::LfsAction");
        let wl = DynamicWhitelist::new(Duration::from_secs(60), 10);
        wl.insert_lfs_action("https://lfs.example.com/x".to_string(), Method::PUT, None);
        let hit = wl
            .get("https://lfs.example.com/x", &Method::PUT)
            .expect("hit");
        t.assert_true(
            "source=LfsAction",
            matches!(hit.source, WhitelistSource::LfsAction),
        );
        t.assert_true(
            "no redirect patterns attached",
            hit.redirect_patterns.is_none(),
        );
    }

    #[test]
    fn test_miss_returns_none() {
        let t = test_report!("Lookup of unknown URL returns None");
        let wl = DynamicWhitelist::new(Duration::from_secs(60), 10);
        t.assert_true(
            "miss",
            wl.get("https://nope.example.com/", &Method::GET).is_none(),
        );
    }

    #[test]
    fn test_expired_entry_returns_none() {
        let t = test_report!("Entries past TTL are treated as misses and evicted");
        let wl = DynamicWhitelist::new(Duration::from_millis(1), 10);
        wl.insert_redirect(
            "https://x.example.com/a".to_string(),
            make_patterns(&["*://*/*"]),
        );
        std::thread::sleep(Duration::from_millis(10));
        t.assert_true(
            "expired entry gone",
            wl.get("https://x.example.com/a", &Method::GET).is_none(),
        );
    }

    #[test]
    fn test_lru_capacity_eviction() {
        let t = test_report!("Cache evicts least-recently-used entry at capacity");
        let wl = DynamicWhitelist::new(Duration::from_secs(60), 2);
        let p = make_patterns(&["*://*/*"]);
        wl.insert_redirect("https://a.example.com/".to_string(), p.clone());
        wl.insert_redirect("https://b.example.com/".to_string(), p.clone());
        wl.insert_redirect("https://c.example.com/".to_string(), p.clone());

        t.assert_true(
            "a evicted",
            wl.get("https://a.example.com/", &Method::GET).is_none(),
        );
        t.assert_true(
            "b present",
            wl.get("https://b.example.com/", &Method::GET).is_some(),
        );
        t.assert_true(
            "c present",
            wl.get("https://c.example.com/", &Method::GET).is_some(),
        );
    }

    #[test]
    fn test_resolve_absolute_location() {
        let t = test_report!("resolve_location returns absolute URL unchanged");
        let r = resolve_location(
            "https://example.com/foo",
            "https://other.example.com/bar?x=1",
        );
        t.assert_eq(
            "absolute passthrough",
            &r.as_deref(),
            &Some("https://other.example.com/bar?x=1"),
        );
    }

    #[test]
    fn test_resolve_relative_location() {
        let t = test_report!("resolve_location joins relative path against request URL");
        let r = resolve_location("https://example.com/a/b", "/c/d");
        t.assert_eq(
            "relative joined",
            &r.as_deref(),
            &Some("https://example.com/c/d"),
        );
        let r2 = resolve_location("https://example.com/a/b", "sibling");
        t.assert_eq(
            "sibling joined",
            &r2.as_deref(),
            &Some("https://example.com/a/sibling"),
        );
    }

    #[test]
    fn test_url_matches_any() {
        let t = test_report!("url_matches_any matches against UrlPattern list");
        let pats = vec![UrlPattern::new("https://cdn.example.com/*").unwrap()];
        t.assert_true(
            "match",
            url_matches_any("https://cdn.example.com/file.bin?x=1", &pats),
        );
        t.assert_true(
            "no match different host",
            !url_matches_any("https://other.example.com/x", &pats),
        );
        t.assert_true("malformed url", !url_matches_any("not a url", &pats));
    }

    #[test]
    fn test_maybe_whitelist_redirect_matching() {
        let t = test_report!("maybe_whitelist_redirect inserts when Location matches patterns");
        let wl = DynamicWhitelist::new(Duration::from_secs(60), 10);
        let pats = make_patterns(&["https://cdn.example.com/*"]);
        let inserted = maybe_whitelist_redirect(
            302,
            Some("https://cdn.example.com/file?sig=xyz"),
            "https://github.com/releases/download/x",
            &pats,
            &wl,
        );
        t.assert_eq(
            "returned resolved url",
            &inserted.as_deref(),
            &Some("https://cdn.example.com/file?sig=xyz"),
        );
        t.assert_true(
            "whitelist has entry",
            wl.get("https://cdn.example.com/file?sig=xyz", &Method::GET)
                .is_some(),
        );
    }

    #[test]
    fn test_maybe_whitelist_redirect_nonmatching() {
        let t = test_report!(
            "maybe_whitelist_redirect does nothing when Location does not match patterns"
        );
        let wl = DynamicWhitelist::new(Duration::from_secs(60), 10);
        let pats = make_patterns(&["https://cdn.example.com/*"]);
        let inserted = maybe_whitelist_redirect(
            302,
            Some("https://elsewhere.example.com/path"),
            "https://github.com/x",
            &pats,
            &wl,
        );
        t.assert_true("no result", inserted.is_none());
        t.assert_true(
            "whitelist has no entry",
            wl.get("https://elsewhere.example.com/path", &Method::GET)
                .is_none(),
        );
    }

    #[test]
    fn test_maybe_whitelist_redirect_nonredirect_status() {
        let t = test_report!("maybe_whitelist_redirect no-ops on non-3xx status");
        let wl = DynamicWhitelist::new(Duration::from_secs(60), 10);
        let pats = make_patterns(&["*://*/*"]);
        let r = maybe_whitelist_redirect(
            200,
            Some("https://other.example.com/foo"),
            "https://example.com/",
            &pats,
            &wl,
        );
        t.assert_true("no action", r.is_none());
    }

    #[test]
    fn test_maybe_whitelist_redirect_relative_location() {
        let t =
            test_report!("maybe_whitelist_redirect resolves relative Location against request url");
        let wl = DynamicWhitelist::new(Duration::from_secs(60), 10);
        let pats = make_patterns(&["https://example.com/*"]);
        let inserted = maybe_whitelist_redirect(
            301,
            Some("/new-path"),
            "https://example.com/old-path",
            &pats,
            &wl,
        );
        t.assert_eq(
            "resolved relative",
            &inserted.as_deref(),
            &Some("https://example.com/new-path"),
        );
    }
}
