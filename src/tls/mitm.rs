//! MITM certificate generation with caching

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{KeyLog, KeyLogFile, ServerConfig};
use std::sync::Arc;
use std::time::Duration;

use super::ca::CertificateAuthority;
use super::cache::CertificateCache;
use crate::error::Result;

/// MITM certificate generator that creates and caches per-host certificates
pub struct MitmCertificateGenerator {
    ca: Arc<CertificateAuthority>,
    cache: CertificateCache,
    key_log: Arc<dyn KeyLog>,
}

impl std::fmt::Debug for MitmCertificateGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MitmCertificateGenerator")
            .field("cache_size", &self.cache.len())
            .finish()
    }
}

impl MitmCertificateGenerator {
    /// Create a new MITM certificate generator
    pub fn new(ca: CertificateAuthority) -> Self {
        Self {
            ca: Arc::new(ca),
            cache: CertificateCache::default(),
            key_log: Arc::new(KeyLogFile::new()),
        }
    }

    /// Create with custom cache settings
    pub fn with_cache(
        ca: CertificateAuthority,
        cache_capacity: usize,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            ca: Arc::new(ca),
            cache: CertificateCache::new(cache_capacity, cache_ttl),
            key_log: Arc::new(KeyLogFile::new()),
        }
    }

    /// Get or generate a certificate for a hostname
    pub fn get_cert_for_host(
        &self,
        hostname: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        // Check cache first
        if let Some(cached) = self.cache.get(hostname) {
            tracing::debug!(hostname = %hostname, "Using cached certificate");
            return Ok(cached);
        }

        // Generate new certificate
        tracing::debug!(hostname = %hostname, "Generating new certificate");
        let (cert, key) = self.ca.generate_cert_for_host(hostname)?;

        // Cache it
        self.cache
            .put(hostname.to_string(), cert.clone(), key.clone_key());

        Ok((cert, key))
    }

    /// Create a rustls ServerConfig for a specific hostname
    pub fn server_config_for_host(&self, hostname: &str) -> Result<ServerConfig> {
        let (cert, key) = self.get_cert_for_host(hostname)?;
        let ca_cert = self.ca.cert_der().clone();

        // Build certificate chain: [host cert, CA cert]
        let cert_chain = vec![cert, ca_cert];

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| {
                crate::error::Error::tls(format!("Failed to build server config: {}", e))
            })?;

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.key_log = self.key_log.clone();

        Ok(config)
    }

    /// Get the CA certificate for client trust
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        self.ca.cert_der()
    }

    /// Get cache statistics
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Create a rustls ServerConfig that uses SNI to resolve certificates dynamically.
    ///
    /// This is used by the direct HTTPS listener, where the proxy accepts raw TLS
    /// connections and determines the target host from the ClientHello SNI extension.
    pub fn sni_server_config(self: &Arc<Self>) -> ServerConfig {
        let resolver = SniCertResolver {
            generator: self.clone(),
        };
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.key_log = self.key_log.clone();
        config
    }
}

/// A `ResolvesServerCert` implementation that generates MITM certs based on SNI.
#[derive(Debug)]
struct SniCertResolver {
    generator: Arc<MitmCertificateGenerator>,
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let hostname = client_hello.server_name()?;

        let (cert, key) = match self.generator.get_cert_for_host(hostname) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(hostname = %hostname, error = %e, "Failed to generate cert for SNI");
                return None;
            }
        };

        let ca_cert = self.generator.ca_cert_der().clone();
        let cert_chain = vec![cert, ca_cert];

        let signing_key = match rustls::crypto::aws_lc_rs::sign::any_supported_type(&key) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(hostname = %hostname, error = %e, "Failed to create signing key");
                return None;
            }
        };

        Some(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca::GeneratedCa;
    use pyloros_test_support::test_report;

    fn create_test_generator() -> MitmCertificateGenerator {
        let generated = GeneratedCa::generate().unwrap();
        let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
        MitmCertificateGenerator::new(ca)
    }

    #[test]
    fn test_generate_cert() {
        let t = test_report!("MITM generator produces cert+key");
        let gen = create_test_generator();
        let (cert, key) = gen.get_cert_for_host("example.com").unwrap();

        t.assert_true("cert not empty", !cert.is_empty());
        t.assert_true("key not empty", !key.secret_der().is_empty());
    }

    #[test]
    fn test_cache_hit() {
        let t = test_report!("MITM generator caches on second call");
        let gen = create_test_generator();

        let _ = gen.get_cert_for_host("example.com").unwrap();
        t.assert_eq("after first call", &gen.cache_size(), &1usize);

        let _ = gen.get_cert_for_host("example.com").unwrap();
        t.assert_eq("after second call (cached)", &gen.cache_size(), &1usize);
    }

    #[test]
    fn test_different_hosts() {
        let t = test_report!("MITM generator stores per-host");
        let gen = create_test_generator();

        let _ = gen.get_cert_for_host("one.com").unwrap();
        let _ = gen.get_cert_for_host("two.com").unwrap();

        t.assert_eq("cache size", &gen.cache_size(), &2usize);
    }

    #[test]
    fn test_server_config() {
        let t = test_report!("Server config has h2+h1 ALPN");
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let gen = create_test_generator();
        let config = gen.server_config_for_host("example.com").unwrap();

        t.assert_eq(
            "ALPN protocols",
            &config.alpn_protocols,
            &vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        );
    }
}
