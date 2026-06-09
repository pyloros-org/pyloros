//! HTTP proxy server implementation

mod handler;
mod response;
mod server;
mod tunnel;

pub use handler::ProxyHandler;
pub use server::{ListenAddress, ProxyServer};
pub use tunnel::TunnelHandler;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use std::sync::Arc;

use crate::approvals::ApprovalManager;
use crate::audit::{
    AuditCredential, AuditDecision, AuditEntry, AuditEvent, AuditGitInfo, AuditLogger, AuditReason,
};
use response::blocked_response;

/// Hop-by-hop headers that must not be forwarded by a proxy (RFC 7230 §6.1).
pub(crate) const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Remove all hop-by-hop headers from a header map.
pub(crate) fn strip_hop_by_hop_headers(headers: &mut hyper::header::HeaderMap) {
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
}

/// Per-request context passed to `RequestLogger` methods.
pub(crate) struct RequestContext<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub host: &'a str,
    pub scheme: &'a str,
    pub protocol: &'a str,
    pub credential: Option<AuditCredential>,
    /// Suffix appended to log messages, e.g. " (HTTP)".
    pub label: &'a str,
}

/// Whether permissive mode is in effect: the static `[proxy] permissive`
/// config flag OR an active dashboard-controlled timeboxed override.
///
/// Permissive mode decides whether the proxy blocks or forwards a request, so
/// this is a control-flow concern owned by the handlers — not a logging one.
/// The dynamic override is delegated to `ApprovalManager`, which owns it; this
/// type just composes it with the static flag (and works fine with no
/// `ApprovalManager`, i.e. when the approvals feature is disabled).
#[derive(Clone, Default)]
pub(crate) struct PermissiveState {
    /// Static config flag (`[proxy] permissive = true`), fixed for the
    /// lifetime of the handler.
    base: bool,
    /// When set, also consult the dashboard-controlled timeboxed override.
    approvals: Option<Arc<ApprovalManager>>,
}

impl PermissiveState {
    pub fn new(base: bool, approvals: Option<Arc<ApprovalManager>>) -> Self {
        Self { base, approvals }
    }

    /// Set the static config flag (used by the handlers' chained builders,
    /// where `base` and `approvals` arrive in separate calls).
    pub fn set_base(&mut self, base: bool) {
        self.base = base;
    }

    /// Set the approvals manager consulted for the dashboard override.
    pub fn set_approvals(&mut self, approvals: Option<Arc<ApprovalManager>>) {
        self.approvals = approvals;
    }

    /// Effective permissive flag at this instant.
    pub fn is_active(&self) -> bool {
        self.base
            || self
                .approvals
                .as_ref()
                .map(|m| m.is_permissive_active())
                .unwrap_or(false)
    }
}

/// Shared request logging and audit emission logic used by both
/// `ProxyHandler` (plain HTTP) and `TunnelHandler` (HTTPS/CONNECT).
pub(crate) struct RequestLogger {
    pub audit_logger: Option<Arc<AuditLogger>>,
    pub log_allowed_requests: bool,
    pub log_blocked_requests: bool,
}

impl RequestLogger {
    pub fn new() -> Self {
        Self {
            audit_logger: None,
            log_allowed_requests: true,
            log_blocked_requests: true,
        }
    }

    pub fn with_request_logging(mut self, log_allowed: bool, log_blocked: bool) -> Self {
        self.log_allowed_requests = log_allowed;
        self.log_blocked_requests = log_blocked;
        self
    }

    pub fn with_audit_logger(mut self, logger: Option<Arc<AuditLogger>>) -> Self {
        self.audit_logger = logger;
        self
    }

    pub fn emit_audit(&self, entry: AuditEntry) {
        if let Some(ref logger) = self.audit_logger {
            logger.log(&entry);
        }
    }

    /// Handle the `FilterResult::Blocked` pattern: log, emit audit, and
    /// return a blocked response unless `permissive` is set.
    ///
    /// The permissive decision is made by the caller (see [`PermissiveState`])
    /// and passed in, so the logger stays a pure function of its inputs.
    ///
    /// Returns `Some(response)` when the request should be blocked,
    /// `None` when permissive mode allows it through.
    #[allow(clippy::wrong_self_convention)]
    pub fn log_blocked(
        &self,
        ctx: &RequestContext<'_>,
        permissive: bool,
    ) -> Option<hyper::Response<BoxBody<Bytes, hyper::Error>>> {
        if permissive {
            tracing::warn!(method = %ctx.method, url = %ctx.url, "PERMITTED{}", ctx.label);
        } else if self.log_blocked_requests {
            tracing::warn!(method = %ctx.method, url = %ctx.url, "BLOCKED{}", ctx.label);
        }
        self.emit_audit(AuditEntry {
            timestamp: crate::audit::now_iso8601(),
            event: if permissive {
                AuditEvent::RequestPermitted
            } else {
                AuditEvent::RequestBlocked
            },
            method: ctx.method.to_string(),
            url: ctx.url.to_string(),
            host: ctx.host.to_string(),
            scheme: ctx.scheme.to_string(),
            protocol: ctx.protocol.to_string(),
            decision: if permissive {
                AuditDecision::Allowed
            } else {
                AuditDecision::Blocked
            },
            reason: AuditReason::NoMatchingRule,
            credential: ctx.credential.clone(),
            git: None,
            request_body: None,
            request_body_encoding: None,
            response_body: None,
            response_body_encoding: None,
            body_truncated: None,
            permissive_duration_secs: None,
            permissive_source: None,
            redirect_target: None,
        });
        if permissive {
            None
        } else {
            Some(blocked_response(ctx.method, ctx.url))
        }
    }

    /// Emit a `RequestPermitted` audit entry (decision `Allowed`) for a block point
    /// that permissive mode is letting through — e.g. a branch-restricted push, an
    /// LFS op that fails the operation check, a plain-HTTP body that can't be
    /// inspected, or an unsupported CONNECT port.
    ///
    /// Unlike `log_blocked` (which handles the `no_matching_rule` case), this is
    /// called from the specific block points after the caller has already decided
    /// permissive mode is active (see [`PermissiveState`]). It keeps the original
    /// `reason` (e.g. `BranchRestriction`) so the audit log stays greppable and shows
    /// *why it would have been blocked*, while `event`/`decision` say it was permitted.
    /// Always emits a tracing line since the point of permissive mode is visibility.
    pub fn log_permitted_with_reason(
        &self,
        ctx: &RequestContext<'_>,
        reason: AuditReason,
        git: Option<AuditGitInfo>,
    ) {
        tracing::warn!(method = %ctx.method, url = %ctx.url, "PERMITTED{}", ctx.label);
        self.emit_audit(AuditEntry {
            timestamp: crate::audit::now_iso8601(),
            event: AuditEvent::RequestPermitted,
            method: ctx.method.to_string(),
            url: ctx.url.to_string(),
            host: ctx.host.to_string(),
            scheme: ctx.scheme.to_string(),
            protocol: ctx.protocol.to_string(),
            decision: AuditDecision::Allowed,
            reason,
            credential: ctx.credential.clone(),
            git,
            request_body: None,
            request_body_encoding: None,
            response_body: None,
            response_body_encoding: None,
            body_truncated: None,
            permissive_duration_secs: None,
            permissive_source: None,
            redirect_target: None,
        });
    }

    /// Handle the `FilterResult::Allowed` pattern: log and emit audit with `RuleMatched`.
    pub fn log_allowed(&self, ctx: &RequestContext<'_>) {
        self.log_allowed_with_reason(ctx, AuditReason::RuleMatched);
    }

    /// Log and emit audit for an allowed request, with an explicit `reason`.
    /// Used to distinguish dynamic-whitelist allowances (`RedirectWhitelisted`,
    /// `LfsActionWhitelisted`) from direct rule matches.
    pub fn log_allowed_with_reason(&self, ctx: &RequestContext<'_>, reason: AuditReason) {
        if self.log_allowed_requests {
            match reason {
                AuditReason::RedirectWhitelisted => {
                    tracing::info!(
                        method = %ctx.method,
                        url = %ctx.url,
                        "ALLOWED (redirect whitelist){}",
                        ctx.label
                    );
                }
                AuditReason::LfsActionWhitelisted => {
                    tracing::info!(
                        method = %ctx.method,
                        url = %ctx.url,
                        "ALLOWED (LFS action whitelist){}",
                        ctx.label
                    );
                }
                _ => {
                    tracing::info!(method = %ctx.method, url = %ctx.url, "ALLOWED{}", ctx.label);
                }
            }
        }
        self.emit_audit(AuditEntry {
            timestamp: crate::audit::now_iso8601(),
            event: AuditEvent::RequestAllowed,
            method: ctx.method.to_string(),
            url: ctx.url.to_string(),
            host: ctx.host.to_string(),
            scheme: ctx.scheme.to_string(),
            protocol: ctx.protocol.to_string(),
            decision: AuditDecision::Allowed,
            reason,
            credential: ctx.credential.clone(),
            git: None,
            request_body: None,
            request_body_encoding: None,
            response_body: None,
            response_body_encoding: None,
            body_truncated: None,
            permissive_duration_secs: None,
            permissive_source: None,
            redirect_target: None,
        });
    }
}
