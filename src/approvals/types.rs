//! Data types for the approvals feature.

use serde::{Deserialize, Serialize};

/// An approval request submitted by an agent inside the sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRequest {
    /// Stable identifier assigned by the manager (e.g. `apr_...`).
    pub id: String,

    /// Proposed rule(s) in short-form config syntax, e.g. `GET https://api.foo.com/*`.
    pub rules: Vec<String>,

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
    /// Active only for the proxy's current process lifetime.
    Session,
    /// Active for one hour.
    OneHour,
    /// Active for 24 hours.
    OneDay,
    /// Persisted to the sidecar file and active across restarts.
    Permanent,
}

/// Current state of an approval request.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved {
        rules_applied: Vec<String>,
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
    pub rules_applied: Option<Vec<String>>,
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

/// Event broadcast to dashboard SSE subscribers.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum NotifierEvent {
    Pending { approval: ApprovalRequest },
    Resolved { id: String, status: ApprovalStatus },
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
