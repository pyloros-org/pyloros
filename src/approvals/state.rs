//! Core state for the approvals feature.
//!
//! In Phase 1 this is a stub: public surface exists so the routing hooks
//! in `api.rs`, `dashboard.rs`, and the proxy server compile, but all
//! runtime behavior returns `NotImplemented`-equivalent responses.

use std::sync::Arc;

use crate::config::ApprovalsConfig;

/// Facade held by `ProxyServer` when the approvals feature is enabled.
#[derive(Debug)]
pub struct ApprovalManager {
    #[allow(dead_code)] // wired in later phases
    config: ApprovalsConfig,
}

impl ApprovalManager {
    /// Construct a new manager from the user's `[approvals]` config.
    ///
    /// Later phases will also accept injected channels for rebuild signals
    /// and a clock trait for testing.
    pub fn new(config: ApprovalsConfig) -> Arc<Self> {
        Arc::new(Self { config })
    }
}
