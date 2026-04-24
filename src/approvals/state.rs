//! Core state for the approvals feature.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;

use crate::config::ApprovalsConfig;

use super::types::{
    ApprovalError, ApprovalRequest, ApprovalStatus, Lifetime, NotifierEvent, TriggeredBy,
};

/// Facade held by `ProxyServer` when the approvals feature is enabled.
#[derive(Debug)]
pub struct ApprovalManager {
    #[allow(dead_code)] // used in later phases (storage path, dashboard bind)
    config: ApprovalsConfig,
    state: Mutex<State>,
    id_counter: AtomicU64,
}

#[derive(Debug, Default)]
struct State {
    /// In-flight approvals awaiting a decision.
    pending: HashMap<String, PendingEntry>,
    /// Resolved approvals kept around so late polls still return the
    /// decision. Small bounded growth is fine for single-user scope; if
    /// this becomes a problem we can LRU-cap.
    resolved: HashMap<String, ApprovalRequest>,
}

#[derive(Debug)]
struct PendingEntry {
    request: ApprovalRequest,
    /// Broadcast the final `ApprovalStatus` to any long-pollers waiting
    /// on this approval. A watch channel is used for its "latest value"
    /// semantics — a poll that arrives after resolution still observes
    /// the final status.
    status_tx: watch::Sender<ApprovalStatus>,
}

impl ApprovalManager {
    /// Construct a new manager from the user's `[approvals]` config.
    pub fn new(config: ApprovalsConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: Mutex::new(State::default()),
            id_counter: AtomicU64::new(1),
        })
    }

    fn next_id(&self) -> String {
        let n = self.id_counter.fetch_add(1, Ordering::Relaxed);
        format!("apr_{:010}", n)
    }

    /// Submit a new approval request. Returns the created request with
    /// its assigned id. The rules vector is stored verbatim; validation
    /// of rule syntax happens at decision time (Phase 4).
    pub fn post(
        &self,
        rules: Vec<String>,
        reason: Option<String>,
        triggered_by: Option<TriggeredBy>,
        suggested_ttl: Option<Lifetime>,
    ) -> ApprovalRequest {
        let id = self.next_id();
        let request = ApprovalRequest {
            id: id.clone(),
            rules,
            reason,
            triggered_by,
            suggested_ttl,
            status: ApprovalStatus::Pending,
        };
        let (status_tx, _rx) = watch::channel(ApprovalStatus::Pending);
        let mut state = self.state.lock().unwrap();
        state.pending.insert(
            id,
            PendingEntry {
                request: request.clone(),
                status_tx,
            },
        );
        request
    }

    /// Fetch an approval by id, waiting up to `wait` for a pending
    /// approval to resolve. Returns `None` if the id is unknown.
    pub async fn get(&self, id: &str, wait: Duration) -> Option<ApprovalRequest> {
        // Fast path: already resolved.
        {
            let state = self.state.lock().unwrap();
            if let Some(req) = state.resolved.get(id) {
                return Some(req.clone());
            }
        }

        // Subscribe to pending status changes.
        let mut rx = {
            let state = self.state.lock().unwrap();
            let entry = state.pending.get(id)?;
            entry.status_tx.subscribe()
        };

        // The current value may already be non-pending if resolution
        // raced between the fast path and our subscribe.
        if !matches!(*rx.borrow_and_update(), ApprovalStatus::Pending) {
            return self.snapshot(id);
        }

        // Wait for a change, bounded by `wait`. Timeout is fine — callers
        // are long-polling and will retry.
        let _ = tokio::time::timeout(wait, rx.changed()).await;
        self.snapshot(id)
    }

    /// Resolve an approval with the given final status. Used by the
    /// dashboard decision endpoint (Phase 3) and the test-only helper.
    /// Returns `NotFound` if the id is unknown or already resolved.
    pub fn resolve(&self, id: &str, status: ApprovalStatus) -> Result<(), ApprovalError> {
        if matches!(status, ApprovalStatus::Pending) {
            return Err(ApprovalError::InvalidRule(
                "cannot resolve to Pending".into(),
            ));
        }
        let mut state = self.state.lock().unwrap();
        let entry = state.pending.remove(id).ok_or(ApprovalError::NotFound)?;
        let mut req = entry.request;
        req.status = status.clone();
        let _ = entry.status_tx.send(status);
        state.resolved.insert(id.to_string(), req);
        Ok(())
    }

    /// Test-only: resolve without going through the dashboard API.
    #[doc(hidden)]
    pub fn resolve_for_test(&self, id: &str, status: ApprovalStatus) -> Result<(), ApprovalError> {
        self.resolve(id, status)
    }

    /// List currently pending approvals (used by dashboard in Phase 3).
    pub fn list_pending(&self) -> Vec<ApprovalRequest> {
        let state = self.state.lock().unwrap();
        state.pending.values().map(|e| e.request.clone()).collect()
    }

    fn snapshot(&self, id: &str) -> Option<ApprovalRequest> {
        let state = self.state.lock().unwrap();
        if let Some(req) = state.resolved.get(id) {
            return Some(req.clone());
        }
        state.pending.get(id).map(|e| e.request.clone())
    }

    // ---- Phase 3+ surface (stubs, not yet used) ----
    /// Subscribe to dashboard notifier events. Returns a receiver that
    /// never yields in Phase 2; wired up in Phase 3.
    #[allow(dead_code)]
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<NotifierEvent> {
        // Placeholder channel so the signature is stable across phases.
        // Replaced in Phase 3 with a shared broadcast sender.
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        rx
    }
}
