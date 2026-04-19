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
}
