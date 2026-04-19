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

use crate::audit::{
    AuditCredential, AuditDecision, AuditEntry, AuditEvent, AuditLogger, AuditReason,
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

/// Shared request logging and audit emission logic used by both
/// `ProxyHandler` (plain HTTP) and `TunnelHandler` (HTTPS/CONNECT).
pub(crate) struct RequestLogger {
    pub audit_logger: Option<Arc<AuditLogger>>,
    pub log_allowed_requests: bool,
    pub log_blocked_requests: bool,
    pub permissive: bool,
}

impl RequestLogger {
    pub fn new() -> Self {
        Self {
            audit_logger: None,
            log_allowed_requests: true,
            log_blocked_requests: true,
            permissive: false,
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

    pub fn with_permissive(mut self, permissive: bool) -> Self {
        self.permissive = permissive;
        self
    }

    pub fn emit_audit(&self, entry: AuditEntry) {
        if let Some(ref logger) = self.audit_logger {
            logger.log(&entry);
        }
    }

    /// Handle the `FilterResult::Blocked` pattern: log, emit audit, and
    /// return a blocked response if not in permissive mode.
    ///
    /// Returns `Some(response)` when the request should be blocked,
    /// `None` when permissive mode allows it through.
    #[allow(clippy::wrong_self_convention)]
    pub fn log_blocked(
        &self,
        ctx: &RequestContext<'_>,
    ) -> Option<hyper::Response<BoxBody<Bytes, hyper::Error>>> {
        if self.permissive {
            tracing::warn!(method = %ctx.method, url = %ctx.url, "PERMITTED{}", ctx.label);
        } else if self.log_blocked_requests {
            tracing::warn!(method = %ctx.method, url = %ctx.url, "BLOCKED{}", ctx.label);
        }
        self.emit_audit(AuditEntry {
            timestamp: crate::audit::now_iso8601(),
            event: if self.permissive {
                AuditEvent::RequestPermitted
            } else {
                AuditEvent::RequestBlocked
            },
            method: ctx.method.to_string(),
            url: ctx.url.to_string(),
            host: ctx.host.to_string(),
            scheme: ctx.scheme.to_string(),
            protocol: ctx.protocol.to_string(),
            decision: if self.permissive {
                AuditDecision::Allowed
            } else {
                AuditDecision::Blocked
            },
            reason: AuditReason::NoMatchingRule,
            credential: ctx.credential.clone(),
            git: None,
        });
        if self.permissive {
            None
        } else {
            Some(blocked_response(ctx.method, ctx.url))
        }
    }

    /// Handle the `FilterResult::Allowed` pattern: log and emit audit with `RuleMatched`.
    pub fn log_allowed(&self, ctx: &RequestContext<'_>) {
        self.log_allowed_with_reason(ctx, AuditReason::RuleMatched);
    }

    /// Log and emit audit for an allowed request, with an explicit `reason`.
    /// Used to distinguish redirect-whitelist allowances (`RedirectWhitelisted`)
    /// from direct rule matches.
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
        });
    }
}
