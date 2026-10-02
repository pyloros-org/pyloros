//! Certificate caching for MITM

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use super::ca::HostCert;

/// Certificates are evicted this long before they actually expire, so a certificate is never
/// handed to a handshake with only moments of validity left.
const RENEWAL_MARGIN: Duration = Duration::from_secs(60 * 60);

/// LRU cache for generated certificates
///
/// Entries expire against the certificate's own `not_after`, on wall-clock time rather than an
/// `Instant`-based TTL (see devdocs/lessons/cert-cache-wall-clock-expiry.md).
pub struct CertificateCache {
    cache: Mutex<LruCache<String, HostCert>>,
}

impl CertificateCache {
    /// Create a new certificate cache
    ///
    /// # Arguments
    /// * `capacity` - Maximum number of certificates to cache
    pub fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1000).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    /// Get a certificate from the cache if it exists and hasn't expired
    pub fn get(&self, hostname: &str) -> Option<HostCert> {
        let mut cache = self.cache.lock().unwrap();

        if let Some(entry) = cache.get(hostname) {
            if SystemTime::now() + RENEWAL_MARGIN < entry.not_after {
                return Some(entry.clone());
            } else {
                // Expired (or close enough to it), remove it
                cache.pop(hostname);
            }
        }

        None
    }

    /// Store a certificate in the cache
    pub fn put(&self, hostname: String, issued: HostCert) {
        self.cache.lock().unwrap().put(hostname, issued);
    }

    /// Get the number of cached certificates
    pub fn len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all cached certificates
    pub fn clear(&self) {
        self.cache.lock().unwrap().clear();
    }
}

impl Default for CertificateCache {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca::{CertificateAuthority, GeneratedCa};
    use pyloros_test_support::test_report;

    fn generate_test_cert(hostname: &str) -> HostCert {
        let generated = GeneratedCa::generate().unwrap();
        let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
        ca.generate_cert_for_host(hostname).unwrap()
    }

    /// The same certificate, re-dated — the cache only looks at `not_after`.
    fn expiring_at(issued: &HostCert, not_after: SystemTime) -> HostCert {
        HostCert {
            not_after,
            ..issued.clone()
        }
    }

    #[test]
    fn test_cache_put_get() {
        let t = test_report!("Cache put and get returns same cert");
        let cache = CertificateCache::default();

        let issued = generate_test_cert("example.com");
        cache.put("example.com".to_string(), issued.clone());

        let result = cache.get("example.com");
        t.assert_true("cache hit", result.is_some());
        t.assert_true(
            "cert matches",
            result.unwrap().cert.as_ref() == issued.cert.as_ref(),
        );
    }

    #[test]
    fn test_cache_miss() {
        let t = test_report!("Cache miss returns None");
        let cache = CertificateCache::default();
        t.assert_true("nonexistent key", cache.get("nonexistent.com").is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let t = test_report!("Cache evicts entries by the certificate's wall-clock not_after");
        let cache = CertificateCache::new(100);
        let issued = generate_test_cert("example.com");
        let now = SystemTime::now();

        // Already past not_after.
        cache.put(
            "expired.com".to_string(),
            expiring_at(&issued, now - Duration::from_secs(60)),
        );
        t.assert_true("expired entry is None", cache.get("expired.com").is_none());

        // Still valid, but inside the renewal margin.
        cache.put(
            "soon.com".to_string(),
            expiring_at(&issued, now + RENEWAL_MARGIN / 2),
        );
        t.assert_true(
            "entry inside renewal margin is None",
            cache.get("soon.com").is_none(),
        );

        // Comfortably valid.
        cache.put(
            "fresh.com".to_string(),
            expiring_at(&issued, now + RENEWAL_MARGIN * 2),
        );
        t.assert_true(
            "entry beyond renewal margin is served",
            cache.get("fresh.com").is_some(),
        );
    }

    #[test]
    fn test_cache_capacity() {
        let t = test_report!("Cache LRU eviction at capacity");
        let cache = CertificateCache::new(2);

        cache.put("one.com".to_string(), generate_test_cert("one.com"));
        cache.put("two.com".to_string(), generate_test_cert("two.com"));
        cache.put("three.com".to_string(), generate_test_cert("three.com"));

        t.assert_true("one.com evicted", cache.get("one.com").is_none());
        t.assert_true("two.com present", cache.get("two.com").is_some());
        t.assert_true("three.com present", cache.get("three.com").is_some());
    }

    #[test]
    fn test_cache_len() {
        let t = test_report!("Cache len and is_empty");
        let cache = CertificateCache::default();
        t.assert_eq("initial len", &cache.len(), &0usize);
        t.assert_true("initially empty", cache.is_empty());

        cache.put("example.com".to_string(), generate_test_cert("example.com"));

        t.assert_eq("len after put", &cache.len(), &1usize);
        t.assert_true("not empty", !cache.is_empty());
    }

    #[test]
    fn test_cache_clear() {
        let t = test_report!("Cache clear empties cache");
        let cache = CertificateCache::default();

        cache.put("example.com".to_string(), generate_test_cert("example.com"));

        cache.clear();
        t.assert_true("empty after clear", cache.is_empty());
    }
}
