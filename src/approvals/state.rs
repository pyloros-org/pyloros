//! Core state for the approvals feature.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Rolling window for the POST rate limit.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX: usize = 60;

use tokio::sync::{broadcast, mpsc, watch};

use crate::config::{ApprovalsConfig, Rule};

use super::types::{
    ActiveApprovalSnapshot, ApprovalError, ApprovalRequest, ApprovalStatus, Lifetime,
    NotifierEvent, PermissiveSource, PermissiveStatus, TriggeredBy,
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
    rule_counter: AtomicU64,
    notifier: broadcast::Sender<NotifierEvent>,
    /// Signal channel for the proxy's main select loop to rebuild the
    /// effective FilterEngine when the set of active approval rules
    /// changes. Set once by `ProxyServer::serve` via `attach_rebuild_tx`.
    rebuild_tx: OnceLock<mpsc::Sender<()>>,
    /// Audit logger, attached at server-startup time. Used to record
    /// permissive-mode toggles so they appear in the JSONL log.
    audit_logger: OnceLock<Arc<crate::audit::AuditLogger>>,
}

/// A currently-active approval rule.
#[derive(Debug, Clone)]
pub struct ActiveApproval {
    pub rule: Rule,
    pub lifetime: Lifetime,
    /// The approval id this rule came from. Used by TTL expiry timers
    /// to find all rules from a single approval and remove them together.
    pub approval_id: String,
    /// When this rule expires, or `None` for `Permanent`.
    pub expires_at: Option<Instant>,
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
    /// Timestamps of recent POST /approvals calls, for sliding-window
    /// rate limiting.
    recent_posts: VecDeque<Instant>,
    /// Deadline at which the dashboard-controlled permissive override
    /// expires. `None` means inactive.
    permissive_until: Option<Instant>,
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
    ///
    /// Loads permanent rules from the permanent-rules file (if any) on startup so
    /// they're active from the first FilterEngine build.
    pub fn new(config: ApprovalsConfig) -> Arc<Self> {
        let (notifier, _) = broadcast::channel(NOTIFIER_CAPACITY);
        let mut state = State::default();
        match super::storage::load_permanent_rules(&config.permanent_rules_file) {
            Ok(rules) => {
                for rule in rules {
                    state.active.push(ActiveApproval {
                        rule,
                        lifetime: Lifetime::Permanent,
                        approval_id: String::new(), // permanent rules loaded from disk have no originating approval id
                        expires_at: None,
                    });
                }
                if !state.active.is_empty() {
                    tracing::info!(
                        count = state.active.len(),
                        path = %config.permanent_rules_file,
                        "Loaded permanent approval rules from the permanent-rules file"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %config.permanent_rules_file,
                    "Failed to load approvals permanent-rules file; continuing with empty permanent set"
                );
            }
        }
        Arc::new(Self {
            config,
            state: Mutex::new(state),
            id_counter: AtomicU64::new(1),
            rule_counter: AtomicU64::new(1),
            notifier,
            rebuild_tx: OnceLock::new(),
            audit_logger: OnceLock::new(),
        })
    }

    /// Attach the audit logger so permissive-toggle entries can be recorded
    /// and audit snapshots forwarded to dashboard SSE subscribers. Silent
    /// no-op if already attached.
    pub fn attach_audit_logger(self: &Arc<Self>, logger: Arc<crate::audit::AuditLogger>) {
        let notifier = self.notifier.clone();
        logger.set_subscriber(Arc::new(move |snapshot| {
            let _ = notifier.send(NotifierEvent::Audit {
                entry: snapshot.clone(),
            });
        }));
        let _ = self.audit_logger.set(logger);
    }

    fn audit(&self, entry: crate::audit::AuditEntry) {
        if let Some(logger) = self.audit_logger.get() {
            logger.log(&entry);
        }
    }

    /// Borrow the attached audit logger (used by the dashboard to read
    /// the recent-entries ring buffer).
    pub fn audit_logger_ref(&self) -> Option<&Arc<crate::audit::AuditLogger>> {
        self.audit_logger.get()
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
    /// its assigned id. Enforces a sliding-window rate limit
    /// (60 POSTs/minute per manager); exceeding returns `RateLimited`.
    pub fn post(
        &self,
        rules: Vec<Rule>,
        reason: Option<String>,
        triggered_by: Option<TriggeredBy>,
        suggested_ttl: Option<Lifetime>,
    ) -> Result<ApprovalRequest, ApprovalError> {
        // Validate each rule before consuming a rate-limit slot — a
        // malformed proposal shouldn't burn quota.
        for rule in &rules {
            rule.validate()
                .map_err(|e| ApprovalError::InvalidRule(format!("{}", e)))?;
        }

        // Rate limit check. Prune entries older than the window, then
        // compare against the cap.
        {
            let mut state = self.state.lock().unwrap();
            let now = Instant::now();
            while let Some(&oldest) = state.recent_posts.front() {
                if now.duration_since(oldest) >= RATE_LIMIT_WINDOW {
                    state.recent_posts.pop_front();
                } else {
                    break;
                }
            }
            if state.recent_posts.len() >= RATE_LIMIT_MAX {
                return Err(ApprovalError::RateLimited);
            }
            state.recent_posts.push_back(now);
        }

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
        Ok(request)
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
    /// On approve, validates `rules_applied` and appends them to the
    /// active set, then signals the server to rebuild the effective
    /// FilterEngine. If any rule fails validation, the whole resolve is
    /// rejected with `InvalidRule` and the approval stays pending (so
    /// the user can edit and retry from the dashboard).
    pub fn resolve(
        self: &Arc<Self>,
        id: &str,
        status: ApprovalStatus,
    ) -> Result<(), ApprovalError> {
        if matches!(status, ApprovalStatus::Pending) {
            return Err(ApprovalError::InvalidRule(
                "cannot resolve to Pending".into(),
            ));
        }

        // Validate-before-lock: if the rules don't pass validation we
        // want to error out *without* mutating state, so the user can
        // retry from the dashboard.
        let parsed_rules: Vec<Rule> = match &status {
            ApprovalStatus::Approved { rules_applied, .. } => {
                for r in rules_applied {
                    r.validate()
                        .map_err(|e| ApprovalError::InvalidRule(format!("{}", e)))?;
                }
                rules_applied.clone()
            }
            _ => Vec::new(),
        };
        let approve_ttl = if let ApprovalStatus::Approved { ttl, .. } = &status {
            Some(*ttl)
        } else {
            None
        };

        // Move the request from pending → resolved and notify waiters.
        {
            let mut state = self.state.lock().unwrap();
            let entry = state.pending.remove(id).ok_or(ApprovalError::NotFound)?;
            let mut req = entry.request;
            req.status = status.clone();
            let _ = entry.status_tx.send(status.clone());
            state.resolved.insert(id.to_string(), req);
        }

        let _ = self.notifier.send(NotifierEvent::Resolved {
            id: id.to_string(),
            status,
        });

        // `add_rules_internal` handles persistence, expiry scheduling,
        // FilterEngine rebuild signaling, and the active-rules
        // broadcast. Skipped for denials.
        if let Some(ttl) = approve_ttl {
            self.add_rules_internal(id.to_string(), parsed_rules, ttl);
        }
        Ok(())
    }

    /// Add rules directly without an originating pending approval. Used
    /// by the dashboard's "Create rule from blocked request" endpoint.
    /// Validates each rule, generates a synthetic `rul_…` group id (used
    /// later for revocation), and shares all bookkeeping with `resolve`.
    pub fn add_rules(
        self: &Arc<Self>,
        rules: Vec<Rule>,
        ttl: Lifetime,
    ) -> Result<String, ApprovalError> {
        for r in &rules {
            r.validate()
                .map_err(|e| ApprovalError::InvalidRule(format!("{}", e)))?;
        }
        let group_id = format!(
            "rul_{:010}",
            self.rule_counter.fetch_add(1, Ordering::Relaxed)
        );
        self.add_rules_internal(group_id.clone(), rules, ttl);
        Ok(group_id)
    }

    /// Shared core: append rules to the active set, persist any
    /// permanent ones, schedule expiry, signal a rebuild, and broadcast
    /// the updated active-rules snapshot.
    fn add_rules_internal(self: &Arc<Self>, group_id: String, rules: Vec<Rule>, ttl: Lifetime) {
        if rules.is_empty() {
            return;
        }
        let expires_at = ttl.duration().map(|d| Instant::now() + d);
        let permanent_snapshot = {
            let mut state = self.state.lock().unwrap();
            for rule in rules {
                state.active.push(ActiveApproval {
                    rule,
                    lifetime: ttl,
                    approval_id: group_id.clone(),
                    expires_at,
                });
            }
            if ttl.is_permanent() {
                Some(
                    state
                        .active
                        .iter()
                        .filter(|a| a.lifetime.is_permanent())
                        .map(|a| a.rule.clone())
                        .collect::<Vec<Rule>>(),
                )
            } else {
                None
            }
        };

        if let Some(snapshot) = permanent_snapshot {
            if let Err(e) =
                super::storage::save_permanent_rules(&self.config.permanent_rules_file, &snapshot)
            {
                tracing::error!(
                    error = %e,
                    path = %self.config.permanent_rules_file,
                    "Failed to persist approvals permanent-rules file"
                );
            }
        }

        if let Some(duration) = ttl.duration() {
            self.spawn_expiry_timer(group_id.clone(), duration);
        }

        self.request_rebuild();
        self.broadcast_active_rules();
    }

    /// Broadcast the current active-rules snapshot to dashboard subscribers.
    fn broadcast_active_rules(&self) {
        let rules = self.list_active();
        let _ = self
            .notifier
            .send(NotifierEvent::ActiveRulesChanged { rules });
    }

    /// Revoke all rules from a previously approved approval. Removes them
    /// from the active set, persists the permanent-rules file if any were permanent,
    /// and signals a rebuild. No-op if no rules match.
    pub fn revoke_approval(&self, approval_id: &str) {
        let (removed_any, permanent_snapshot) = {
            let mut state = self.state.lock().unwrap();
            let before = state.active.len();
            let had_permanent = state
                .active
                .iter()
                .any(|a| a.approval_id == approval_id && a.lifetime.is_permanent());
            state.active.retain(|a| a.approval_id != approval_id);
            let removed_any = state.active.len() != before;
            let permanent_snapshot = if removed_any && had_permanent {
                Some(
                    state
                        .active
                        .iter()
                        .filter(|a| a.lifetime.is_permanent())
                        .map(|a| a.rule.clone())
                        .collect::<Vec<Rule>>(),
                )
            } else {
                None
            };
            (removed_any, permanent_snapshot)
        };

        if let Some(snapshot) = permanent_snapshot {
            let _ =
                super::storage::save_permanent_rules(&self.config.permanent_rules_file, &snapshot);
        }

        if removed_any {
            self.request_rebuild();
            self.broadcast_active_rules();
        }
    }

    fn spawn_expiry_timer(self: &Arc<Self>, approval_id: String, duration: Duration) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(duration).await;
            this.revoke_approval(&approval_id);
        });
    }

    // ----- Dashboard-controlled permissive override ---------------------

    /// Enable timeboxed permissive mode for `duration`. Replaces any
    /// existing override deadline. Records a `PermissiveEnabled` audit
    /// entry and broadcasts the new status to dashboard subscribers.
    /// Spawns an expiry task that calls `clear_permissive` once the
    /// deadline passes (unless re-enabled or cleared in the meantime).
    pub fn set_permissive(self: &Arc<Self>, duration: Duration) {
        let until = Instant::now() + duration;
        {
            let mut state = self.state.lock().unwrap();
            state.permissive_until = Some(until);
        }
        let secs = duration.as_secs();
        self.audit(crate::audit::AuditEntry::permissive_enabled(
            secs,
            PermissiveSource::Dashboard.as_str(),
        ));
        let _ = self.notifier.send(NotifierEvent::PermissiveChanged {
            status: PermissiveStatus {
                active: true,
                remaining_secs: Some(secs),
            },
        });
        self.request_rebuild();

        let this = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(duration).await;
            this.expire_permissive_if(until);
        });
    }

    /// Manually clear the dashboard-controlled permissive override.
    /// No-op if already inactive.
    pub fn clear_permissive(self: &Arc<Self>) {
        let was_active = {
            let mut state = self.state.lock().unwrap();
            state.permissive_until.take().is_some()
        };
        if was_active {
            self.audit(crate::audit::AuditEntry::permissive_disabled(
                PermissiveSource::DashboardClear.as_str(),
            ));
            let _ = self.notifier.send(NotifierEvent::PermissiveChanged {
                status: PermissiveStatus {
                    active: false,
                    remaining_secs: None,
                },
            });
            self.request_rebuild();
        }
    }

    /// Internal expiry callback. Only clears state if the deadline
    /// still matches `expected` — a fresh `set_permissive` may have
    /// replaced it in the meantime.
    fn expire_permissive_if(self: &Arc<Self>, expected: Instant) {
        let cleared = {
            let mut state = self.state.lock().unwrap();
            if state.permissive_until == Some(expected) {
                state.permissive_until = None;
                true
            } else {
                false
            }
        };
        if cleared {
            self.audit(crate::audit::AuditEntry::permissive_disabled(
                PermissiveSource::Expired.as_str(),
            ));
            let _ = self.notifier.send(NotifierEvent::PermissiveChanged {
                status: PermissiveStatus {
                    active: false,
                    remaining_secs: None,
                },
            });
            self.request_rebuild();
        }
    }

    /// Is the dashboard-controlled permissive override currently active?
    /// Cheap check used by the proxy on every blocked-request decision.
    pub fn is_permissive_active(&self) -> bool {
        let state = self.state.lock().unwrap();
        match state.permissive_until {
            Some(deadline) => Instant::now() < deadline,
            None => false,
        }
    }

    /// Snapshot of the permissive override (for SSE consumers).
    pub fn permissive_status(&self) -> PermissiveStatus {
        let state = self.state.lock().unwrap();
        match state.permissive_until {
            Some(deadline) => {
                let now = Instant::now();
                if now < deadline {
                    PermissiveStatus {
                        active: true,
                        remaining_secs: Some((deadline - now).as_secs()),
                    }
                } else {
                    PermissiveStatus {
                        active: false,
                        remaining_secs: None,
                    }
                }
            }
            None => PermissiveStatus {
                active: false,
                remaining_secs: None,
            },
        }
    }

    /// Snapshot of currently active rule groups, with their remaining
    /// time and a pre-formatted TOML representation. Sent to dashboards
    /// in the initial SSE frame and on every `ActiveRulesChanged` event.
    pub fn list_active(&self) -> Vec<ActiveApprovalSnapshot> {
        let now = Instant::now();
        let state = self.state.lock().unwrap();
        state
            .active
            .iter()
            .map(|a| {
                let remaining_secs =
                    a.expires_at
                        .map(|t| if t > now { (t - now).as_secs() } else { 0 });
                ActiveApprovalSnapshot {
                    approval_id: a.approval_id.clone(),
                    rule: a.rule.clone(),
                    lifetime: a.lifetime,
                    remaining_secs,
                    toml: super::rule_suggest::format_rule_toml(&a.rule),
                }
            })
            .collect()
    }

    /// Test-only: resolve without going through the dashboard API.
    #[doc(hidden)]
    pub fn resolve_for_test(
        self: &Arc<Self>,
        id: &str,
        status: ApprovalStatus,
    ) -> Result<(), ApprovalError> {
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
