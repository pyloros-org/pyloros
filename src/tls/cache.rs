//! Certificate caching for MITM

use lru::LruCache;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Certificates are evicted this long before they actually expire, so a certificate is never
/// handed to a handshake with only moments of validity left.
const RENEWAL_MARGIN: Duration = Duration::from_secs(60 * 60);

/// A cached certificate entry
struct CacheEntry {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    /// The certificate's own `not_after`, as reported by the CA that issued it.
    not_after: SystemTime,
}

/// LRU cache for generated certificates
///
/// Entries expire on wall-clock time against the certificate's own `not_after`, not on an
/// independent TTL. A TTL measured with `Instant` would not advance while the host is suspended
/// (`CLOCK_MONOTONIC` excludes suspend time) while certificate validity, being wall-clock, would
/// elapse — so after a long suspend the cache would keep serving certificates that clients
/// already reject as expired. See devdocs/lessons/cert-cache-wall-clock-expiry.md.
pub struct CertificateCache {
    cache: Mutex<LruCache<String, CacheEntry>>,
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
    pub fn get(&self, hostname: &str) -> Option<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let mut cache = self.cache.lock().unwrap();

        if let Some(entry) = cache.get(hostname) {
            if SystemTime::now() + RENEWAL_MARGIN < entry.not_after {
                return Some((entry.cert.clone(), entry.key.clone_key()));
            } else {
                // Expired (or close enough to it), remove it
                cache.pop(hostname);
            }
        }

        None
    }

    /// Store a certificate in the cache
    pub fn put(
        &self,
        hostname: String,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        not_after: SystemTime,
    ) {
        let mut cache = self.cache.lock().unwrap();
        cache.put(
            hostname,
            CacheEntry {
                cert,
                key,
                not_after,
            },
        );
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

    fn generate_test_cert(
        hostname: &str,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>, SystemTime) {
        let generated = GeneratedCa::generate().unwrap();
        let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
        ca.generate_cert_for_host(hostname).unwrap()
    }

    #[test]
    fn test_cache_put_get() {
        let t = test_report!("Cache put and get returns same cert");
        let cache = CertificateCache::default();

        let (cert, key, not_after) = generate_test_cert("example.com");
        cache.put("example.com".to_string(), cert.clone(), key, not_after);

        let result = cache.get("example.com");
        t.assert_true("cache hit", result.is_some());

        let (cached_cert, _) = result.unwrap();
        t.assert_true("cert matches", cached_cert.as_ref() == cert.as_ref());
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
        let (cert, key, _) = generate_test_cert("example.com");

        // Already past not_after: the case a long host suspend produces, where a monotonic TTL
        // would still consider the entry fresh.
        cache.put(
            "expired.com".to_string(),
            cert.clone(),
            key.clone_key(),
            SystemTime::now() - Duration::from_secs(60),
        );
        t.assert_true("expired entry is None", cache.get("expired.com").is_none());

        // Still valid, but inside the renewal margin.
        cache.put(
            "soon.com".to_string(),
            cert.clone(),
            key.clone_key(),
            SystemTime::now() + RENEWAL_MARGIN / 2,
        );
        t.assert_true(
            "entry inside renewal margin is None",
            cache.get("soon.com").is_none(),
        );

        // Comfortably valid.
        cache.put(
            "fresh.com".to_string(),
            cert,
            key,
            SystemTime::now() + RENEWAL_MARGIN * 2,
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

        let (cert1, key1, na1) = generate_test_cert("one.com");
        let (cert2, key2, na2) = generate_test_cert("two.com");
        let (cert3, key3, na3) = generate_test_cert("three.com");

        cache.put("one.com".to_string(), cert1, key1, na1);
        cache.put("two.com".to_string(), cert2, key2, na2);
        cache.put("three.com".to_string(), cert3, key3, na3);

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

        let (cert, key, not_after) = generate_test_cert("example.com");
        cache.put("example.com".to_string(), cert, key, not_after);

        t.assert_eq("len after put", &cache.len(), &1usize);
        t.assert_true("not empty", !cache.is_empty());
    }

    #[test]
    fn test_cache_clear() {
        let t = test_report!("Cache clear empties cache");
        let cache = CertificateCache::default();

        let (cert, key, not_after) = generate_test_cert("example.com");
        cache.put("example.com".to_string(), cert, key, not_after);

        cache.clear();
        t.assert_true("empty after clear", cache.is_empty());
    }
}
