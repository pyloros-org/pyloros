//! Data types for the approvals feature.

use serde::{Deserialize, Serialize};

use crate::config::Rule;

/// An approval request submitted by an agent inside the sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRequest {
    /// Stable identifier assigned by the manager (e.g. `apr_...`).
    pub id: String,

    /// Proposed rule(s) in the same JSON shape as the TOML config `[[rules]]`
    /// table (e.g. `{"method":"GET","url":"https://api.foo.com/*"}` or
    /// `{"git":"fetch","url":"https://github.com/foo/bar.git"}`).
    pub rules: Vec<Rule>,

    /// Free-text reason shown to the user in the dashboard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Optional context about the request that triggered this approval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<TriggeredBy>,

    /// Agent's suggested lifetime; used as the dashboard form default only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_ttl: Option<Lifetime>,

    /// Current decision state. Flattened into the parent object so the
    /// wire format is `{"id":..., "status":"approved", "rules_applied":[...]}`
    /// rather than a nested object.
    #[serde(flatten)]
    pub status: ApprovalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggeredBy {
    pub method: String,
    pub url: String,
}

/// Decision lifetime for an approved rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifetime {
    /// Active for one hour.
    OneHour,
    /// Active for 24 hours.
    OneDay,
    /// Persisted to the permanent-rules file and active across restarts.
    Permanent,
}

impl Lifetime {
    /// Duration for lifetimes that have a natural expiry, else `None`.
    /// Permanent is loaded from the permanent-rules file on startup and
    /// never expires in memory.
    pub fn duration(self) -> Option<std::time::Duration> {
        match self {
            Lifetime::OneHour => Some(std::time::Duration::from_secs(3600)),
            Lifetime::OneDay => Some(std::time::Duration::from_secs(86_400)),
            Lifetime::Permanent => None,
        }
    }

    /// Whether approvals with this lifetime should persist to the permanent-rules file.
    pub fn is_permanent(self) -> bool {
        matches!(self, Lifetime::Permanent)
    }
}

/// Current state of an approval request.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved {
        rules_applied: Vec<Rule>,
        ttl: Lifetime,
    },
    Denied {
        message: Option<String>,
    },
}

/// A decision posted by the human via the dashboard.
#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalDecision {
    pub action: DecisionAction,
    /// If present, overrides the agent's proposed rules (user may edit).
    #[serde(default)]
    pub rules_applied: Option<Vec<Rule>>,
    #[serde(default)]
    pub ttl: Option<Lifetime>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Approve,
    Deny,
}

/// Snapshot of an active (approved-and-still-effective) rule group, used
/// by the dashboard "active timeboxed rules" panel and the SSE
/// snapshot frame. One snapshot per `ApprovalManager::ActiveApproval` entry.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveApprovalSnapshot {
    /// Group identifier — the originating approval id, or a synthetic
    /// `rul_…` id for rules added directly through the dashboard. Used
    /// as the path component for `DELETE /approvals/{id}/rules`.
    pub approval_id: String,
    pub rule: Rule,
    pub lifetime: Lifetime,
    /// Seconds remaining before expiry. `None` for `Permanent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_secs: Option<u64>,
    /// Pre-formatted TOML representation of the rule, so the dashboard
    /// can render it without needing a separate format round-trip.
    pub toml: String,
}

/// Status of the dashboard-controlled permissive-mode override.
#[derive(Debug, Clone, Serialize)]
pub struct PermissiveStatus {
    pub active: bool,
    /// Seconds remaining before auto-disable. `None` when inactive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_secs: Option<u64>,
}

/// Source of a permissive-mode toggle, threaded into audit entries.
#[derive(Debug, Clone, Copy)]
pub enum PermissiveSource {
    /// User clicked "enable permissive mode" in the dashboard.
    Dashboard,
    /// User clicked "disable" (clear) in the dashboard.
    DashboardClear,
    /// Auto-disable timer fired.
    Expired,
}

impl PermissiveSource {
    pub fn as_str(self) -> &'static str {
        match self {
            PermissiveSource::Dashboard => "dashboard",
            PermissiveSource::DashboardClear => "dashboard_clear",
            PermissiveSource::Expired => "expired",
        }
    }
}

/// Event broadcast to dashboard SSE subscribers.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum NotifierEvent {
    Pending {
        approval: ApprovalRequest,
    },
    Resolved {
        id: String,
        status: ApprovalStatus,
    },
    /// Dashboard-controlled permissive-mode override changed state.
    PermissiveChanged {
        status: PermissiveStatus,
    },
    /// The active timeboxed-rules set changed (rule added, revoked, or
    /// auto-expired). Carries the full list so dashboards stay in sync
    /// without separate fetches.
    ActiveRulesChanged {
        rules: Vec<ActiveApprovalSnapshot>,
    },
    /// A new audit entry was recorded — broadcast so the dashboard's
    /// "recent blocked" and "audit log browser" panels update live.
    Audit {
        entry: crate::audit::AuditEntrySnapshot,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("approvals feature is not enabled")]
    NotEnabled,
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("approval not found")]
    NotFound,
    #[error("approval already resolved")]
    AlreadyResolved,
    #[error("invalid rule: {0}")]
    InvalidRule(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml serialization error: {0}")]
    TomlSer(String),
    #[error("toml parse error: {0}")]
    TomlDe(String),
}
