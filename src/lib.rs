//! Pyloros - A filtering HTTPS proxy for agent network access control
//!
//! This crate provides a filtering proxy that intercepts HTTPS traffic and applies
//! allowlist-based rules to control network access.
//!
//! # Features
//!
//! - **Allowlist-based filtering**: Default-deny with explicit allow rules
//! - **HTTPS interception**: TLS termination (MITM) for inspecting encrypted traffic
//! - **Flexible pattern matching**: Wildcards for methods, hosts, paths, and query strings
//! - **Certificate management**: User-provided or auto-generated CA certificates
//!
//! # Example
//!
//! ```no_run
//! use pyloros::{Config, ProxyServer};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::from_file("config.toml")?;
//!     let server = ProxyServer::new(config)?;
//!     let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
//!     server.run_until_shutdown(shutdown_rx).await?;
//!     Ok(())
//! }
//! ```

pub mod approvals;
pub mod audit;
pub mod config;
pub mod error;
pub mod filter;
pub mod proxy;
pub mod tls;

pub use audit::AuditLogger;
pub use config::Config;
pub use error::{Error, Result};
pub use filter::{CredentialEngine, FilterEngine, FilterResult, RequestInfo};
pub use proxy::{ListenAddress, ProxyServer};
pub use tls::{CertificateAuthority, GeneratedCa, MitmCertificateGenerator};
