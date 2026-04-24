//! Core state for the approvals feature.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, watch};

use crate::config::{ApprovalsConfig, Rule};

use super::types::{
    ApprovalError, ApprovalRequest, ApprovalStatus, Lifetime, NotifierEvent, TriggeredBy,
};

/// Capacity for the dashboard notifier broadcast channel. Each dashboard
/// connection subscribes independently; capacity exceeded = client drops
/// and reconnects (dashboard JS handles this).
const NOTIFIER_CAPACITY: usize = 64;

/// Facade held by `ProxyServer` when the approvals feature is enabled.
#[derive(Debug)]
pub struct ApprovalManager {
    #[allow(dead_code)] // used in later phases (storage path, dashboard bind)
    config: ApprovalsConfig,
    state: Mutex<State>,
    id_counter: AtomicU64,
    notifier: broadcast::Sender<NotifierEvent>,
    /// Signal channel for the proxy's main select loop to rebuild the
    /// effective FilterEngine when the set of active approval rules
    /// changes. Set once by `ProxyServer::serve` via `attach_rebuild_tx`.
    rebuild_tx: OnceLock<mpsc::Sender<()>>,
}

/// A currently-active approval rule. Phase 4 stores only the rule; TTL
/// expiry and permanent storage are added in Phase 5.
#[derive(Debug, Clone)]
pub struct ActiveApproval {
    pub rule: Rule,
    #[allow(dead_code)] // Phase 5
    pub lifetime: Lifetime,
}

#[derive(Debug, Default)]
struct State {
    /// In-flight approvals awaiting a decision.
    pending: HashMap<String, PendingEntry>,
    /// Resolved approvals kept around so late polls still return the
    /// decision. Small bounded growth is fine for single-user scope; if
    /// this becomes a problem we can LRU-cap.
    resolved: HashMap<String, ApprovalRequest>,
    /// Rules that are currently in effect, merged into the FilterEngine
    /// on top of the base config rules.
    active: Vec<ActiveApproval>,
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
        let (notifier, _) = broadcast::channel(NOTIFIER_CAPACITY);
        Arc::new(Self {
            config,
            state: Mutex::new(State::default()),
            id_counter: AtomicU64::new(1),
            notifier,
            rebuild_tx: OnceLock::new(),
        })
    }

    /// Attach the mpsc channel that the proxy's main select loop listens
    /// on for FilterEngine rebuilds. Called once by `ProxyServer::serve`.
    pub fn attach_rebuild_tx(&self, tx: mpsc::Sender<()>) {
        let _ = self.rebuild_tx.set(tx);
    }

    /// Snapshot the active approval rules (used by the server to rebuild
    /// the FilterEngine as `base_rules ++ active_rules()`).
    pub fn active_rules(&self) -> Vec<Rule> {
        let state = self.state.lock().unwrap();
        state.active.iter().map(|a| a.rule.clone()).collect()
    }

    /// Signal the server to rebuild the effective FilterEngine.
    /// Silent no-op if the rebuild channel hasn't been attached yet
    /// (early resolve during startup) or is full (a rebuild is already
    /// queued and will observe our changes).
    fn request_rebuild(&self) {
        if let Some(tx) = self.rebuild_tx.get() {
            let _ = tx.try_send(());
        }
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
        {
            let mut state = self.state.lock().unwrap();
            state.pending.insert(
                id,
                PendingEntry {
                    request: request.clone(),
                    status_tx,
                },
            );
        }
        let _ = self.notifier.send(NotifierEvent::Pending {
            approval: request.clone(),
        });
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
    /// dashboard decision endpoint and the test-only helper.
    ///
    /// On approve, parses the `rules_applied` strings into `Rule`s and
    /// appends them to the active set, then signals the server to rebuild
    /// the effective FilterEngine. If any rule fails to parse, the whole
    /// resolve is rejected with `InvalidRule` and the approval stays
    /// pending (so the user can edit and retry from the dashboard).
    pub fn resolve(&self, id: &str, status: ApprovalStatus) -> Result<(), ApprovalError> {
        if matches!(status, ApprovalStatus::Pending) {
            return Err(ApprovalError::InvalidRule(
                "cannot resolve to Pending".into(),
            ));
        }

        // Parse-before-lock: if the rules don't parse, we want to error
        // out *without* mutating state, so the user can retry from the
        // dashboard.
        let parsed_rules: Vec<Rule> = match &status {
            ApprovalStatus::Approved { rules_applied, .. } => {
                let mut out = Vec::with_capacity(rules_applied.len());
                for r in rules_applied {
                    out.push(
                        Rule::parse_shortform(r)
                            .map_err(|e| ApprovalError::InvalidRule(format!("{}: {}", r, e)))?,
                    );
                }
                out
            }
            _ => Vec::new(),
        };
        let approve_ttl = if let ApprovalStatus::Approved { ttl, .. } = &status {
            Some(*ttl)
        } else {
            None
        };

        let (final_status, rebuilt) = {
            let mut state = self.state.lock().unwrap();
            let entry = state.pending.remove(id).ok_or(ApprovalError::NotFound)?;
            let mut req = entry.request;
            req.status = status.clone();
            let _ = entry.status_tx.send(status.clone());
            state.resolved.insert(id.to_string(), req);
            let rebuilt = if let Some(ttl) = approve_ttl {
                for rule in parsed_rules {
                    state.active.push(ActiveApproval {
                        rule,
                        lifetime: ttl,
                    });
                }
                true
            } else {
                false
            };
            (status, rebuilt)
        };

        let _ = self.notifier.send(NotifierEvent::Resolved {
            id: id.to_string(),
            status: final_status,
        });

        if rebuilt {
            self.request_rebuild();
        }
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

    /// Return a pending approval's snapshot by id. None if unknown or
    /// already resolved (used by the dashboard decision endpoint to
    /// pick default `rules_applied` from the agent's proposal).
    pub fn snapshot_pending(&self, id: &str) -> Option<ApprovalRequest> {
        let state = self.state.lock().unwrap();
        state.pending.get(id).map(|e| e.request.clone())
    }

    fn snapshot(&self, id: &str) -> Option<ApprovalRequest> {
        let state = self.state.lock().unwrap();
        if let Some(req) = state.resolved.get(id) {
            return Some(req.clone());
        }
        state.pending.get(id).map(|e| e.request.clone())
    }

    /// Subscribe to dashboard notifier events. Each dashboard `/events`
    /// connection calls this once at stream open.
    pub fn subscribe_events(&self) -> broadcast::Receiver<NotifierEvent> {
        self.notifier.subscribe()
    }
}
