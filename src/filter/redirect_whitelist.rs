//! Short-lived global whitelist of follow-up URLs permitted by redirect responses.
//!
//! When a rule-matched request returns a 3xx with a `Location` header that matches
//! the rule's `allow_redirects` patterns, the resolved target URL is inserted here
//! for a bounded TTL. Subsequent requests to the exact URL are allowed — carrying
//! the origin rule's redirect patterns with them so further redirects in the chain
//! can be evaluated against the same policy.

use crate::filter::matcher::UrlPattern;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

struct Entry {
    expires_at: Instant,
    redirect_patterns: Arc<Vec<UrlPattern>>,
}

/// Global, TTL-bounded whitelist of URLs permitted via redirect.
pub struct RedirectWhitelist {
    inner: Mutex<LruCache<String, Entry>>,
    ttl: Duration,
}

impl RedirectWhitelist {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1024).unwrap());
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
            ttl,
        }
    }

    /// Look up a URL. Returns the origin rule's redirect patterns (to evaluate
    /// follow-up redirects in the same chain) if the entry is present and unexpired.
    pub fn get(&self, url: &str) -> Option<Arc<Vec<UrlPattern>>> {
        let mut cache = self.inner.lock().unwrap();
        if let Some(entry) = cache.get(url) {
            if Instant::now() < entry.expires_at {
                return Some(entry.redirect_patterns.clone());
            }
            cache.pop(url);
        }
        None
    }

    /// Insert (or refresh) a whitelisted URL. `redirect_patterns` is the set of
    /// patterns that applied to the origin rule — it travels with the entry so
    /// chained redirects can be validated against the same policy.
    pub fn insert(&self, url: String, redirect_patterns: Arc<Vec<UrlPattern>>) {
        let entry = Entry {
            expires_at: Instant::now() + self.ttl,
            redirect_patterns,
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
    whitelist: &RedirectWhitelist,
) -> Option<String> {
    if !(300..400).contains(&status) {
        return None;
    }
    let loc = location?;
    let resolved = resolve_location(request_url, loc)?;
    if !url_matches_any(&resolved, patterns) {
        return None;
    }
    whitelist.insert(resolved.clone(), patterns.clone());
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
        let t = test_report!("Insert then get returns the same redirect patterns");
        let wl = RedirectWhitelist::new(Duration::from_secs(60), 10);
        let patterns = make_patterns(&["https://cdn.example.com/*"]);
        wl.insert("https://cdn.example.com/x".to_string(), patterns.clone());

        let got = wl.get("https://cdn.example.com/x");
        t.assert_true("entry found", got.is_some());
        t.assert_eq("pattern count", &got.unwrap().len(), &1usize);
    }

    #[test]
    fn test_miss_returns_none() {
        let t = test_report!("Lookup of unknown URL returns None");
        let wl = RedirectWhitelist::new(Duration::from_secs(60), 10);
        t.assert_true("miss", wl.get("https://nope.example.com/").is_none());
    }

    #[test]
    fn test_expired_entry_returns_none() {
        let t = test_report!("Entries past TTL are treated as misses and evicted");
        let wl = RedirectWhitelist::new(Duration::from_millis(1), 10);
        wl.insert(
            "https://x.example.com/a".to_string(),
            make_patterns(&["*://*/*"]),
        );
        std::thread::sleep(Duration::from_millis(10));
        t.assert_true(
            "expired entry gone",
            wl.get("https://x.example.com/a").is_none(),
        );
    }

    #[test]
    fn test_lru_capacity_eviction() {
        let t = test_report!("Cache evicts least-recently-used entry at capacity");
        let wl = RedirectWhitelist::new(Duration::from_secs(60), 2);
        let p = make_patterns(&["*://*/*"]);
        wl.insert("https://a.example.com/".to_string(), p.clone());
        wl.insert("https://b.example.com/".to_string(), p.clone());
        wl.insert("https://c.example.com/".to_string(), p.clone());

        t.assert_true("a evicted", wl.get("https://a.example.com/").is_none());
        t.assert_true("b present", wl.get("https://b.example.com/").is_some());
        t.assert_true("c present", wl.get("https://c.example.com/").is_some());
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
        let wl = RedirectWhitelist::new(Duration::from_secs(60), 10);
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
            wl.get("https://cdn.example.com/file?sig=xyz").is_some(),
        );
    }

    #[test]
    fn test_maybe_whitelist_redirect_nonmatching() {
        let t = test_report!(
            "maybe_whitelist_redirect does nothing when Location does not match patterns"
        );
        let wl = RedirectWhitelist::new(Duration::from_secs(60), 10);
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
            wl.get("https://elsewhere.example.com/path").is_none(),
        );
    }

    #[test]
    fn test_maybe_whitelist_redirect_nonredirect_status() {
        let t = test_report!("maybe_whitelist_redirect no-ops on non-3xx status");
        let wl = RedirectWhitelist::new(Duration::from_secs(60), 10);
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
        let wl = RedirectWhitelist::new(Duration::from_secs(60), 10);
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
