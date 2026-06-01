//! Human-facing dashboard served on the dedicated `dashboard_bind` listener.
//!
//! Endpoints:
//! - `GET /`                              — HTML page (inline JS for SSE + Notification API)
//! - `GET /events`                        — Server-Sent Events stream
//! - `GET /state`                         — JSON snapshot of pending + active + permissive + recent
//! - `POST /approvals/{id}/decision`      — record a decision for the given approval id
//! - `DELETE /approvals/{id}/rules`       — revoke the active rules from an approval
//! - `POST /permissive`                   — set or clear the timeboxed permissive override
//! - `POST /rules`                        — add rules directly (no upstream approval)
//! - `POST /rules/parse`                  — parse TOML rule text → structured rules
//! - `POST /rules/suggest`                — server-built TOML pre-fill for a blocked
//!   audit entry or a re-format of existing rules

use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream::{self, StreamExt};
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;

use super::rule_suggest;
use super::state::ApprovalManager;
use super::types::{
    ActiveApprovalSnapshot, ApprovalDecision, ApprovalRequest, ApprovalStatus, DecisionAction,
    Lifetime, NotifierEvent, PermissiveStatus,
};
use crate::audit::AuditEntrySnapshot;
use crate::config::Rule;

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Serve a single dashboard HTTP connection.
pub async fn serve_connection<S>(manager: Arc<ApprovalManager>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req: Request<Incoming>| {
        let manager = Arc::clone(&manager);
        async move { Ok::<_, hyper::Error>(dispatch(manager, req).await) }
    });

    let io = TokioIo::new(stream);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().preserve_header_case(true).half_close(true);
    if let Err(e) = builder.serve_connection(io, service).await {
        let err_str = e.to_string();
        if !err_str.contains("connection closed") && !err_str.contains("early eof") {
            tracing::debug!("dashboard service error: {}", e);
        }
    }
}

async fn dispatch(
    manager: Arc<ApprovalManager>,
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    match (&method, path.as_str()) {
        (&Method::GET, "/") => serve_html(),
        (&Method::GET, "/events") => serve_events(manager),
        (&Method::GET, "/state") => serve_state(manager, &query),
        (&Method::POST, "/permissive") => serve_permissive(manager, req).await,
        (&Method::POST, "/rules") => serve_add_rules(manager, req).await,
        (&Method::POST, "/rules/parse") => serve_rules_parse(req).await,
        (&Method::POST, "/rules/suggest") => serve_rules_suggest(req).await,
        (&Method::POST, p) if p.starts_with("/approvals/") && p.ends_with("/decision") => {
            let id = p
                .trim_start_matches("/approvals/")
                .trim_end_matches("/decision")
                .to_string();
            serve_decision(manager, &id, req).await
        }
        (&Method::DELETE, p) if p.starts_with("/approvals/") && p.ends_with("/rules") => {
            let id = p
                .trim_start_matches("/approvals/")
                .trim_end_matches("/rules")
                .to_string();
            manager.revoke_approval(&id);
            no_content()
        }
        _ => not_found(),
    }
}

fn serve_html() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(
            Full::new(Bytes::from_static(DASHBOARD_HTML.as_bytes()))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

/// Snapshot returned both as the initial SSE frame and as the body of
/// `GET /state`. Keeping the shape identical means the dashboard JS
/// has a single code path for rendering.
#[derive(Serialize)]
struct DashboardSnapshot {
    event: &'static str,
    pending: Vec<ApprovalRequest>,
    active: Vec<ActiveApprovalSnapshot>,
    permissive: PermissiveStatus,
    recent_blocked: Vec<AuditEntrySnapshot>,
    recent_all: Vec<AuditEntrySnapshot>,
}

fn build_snapshot(manager: &ApprovalManager) -> DashboardSnapshot {
    let (recent_blocked, recent_all) = match manager.audit_logger_ref() {
        Some(l) => (l.recent_entries(false), l.recent_entries(true)),
        None => (Vec::new(), Vec::new()),
    };
    DashboardSnapshot {
        event: "snapshot",
        pending: manager.list_pending(),
        active: manager.list_active(),
        permissive: manager.permissive_status(),
        recent_blocked,
        recent_all,
    }
}

fn serve_state(
    manager: Arc<ApprovalManager>,
    _query: &str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let snapshot = build_snapshot(&manager);
    json_response(StatusCode::OK, &snapshot)
}

fn serve_events(manager: Arc<ApprovalManager>) -> Response<BoxBody<Bytes, hyper::Error>> {
    let rx = manager.subscribe_events();
    let snapshot = build_snapshot(&manager);
    let initial = Bytes::from(format!(
        "data: {}\n\n",
        serde_json::to_string(&snapshot).unwrap()
    ));

    let initial_stream =
        stream::once(async move { Ok::<Frame<Bytes>, hyper::Error>(Frame::data(initial)) });

    let event_stream = stream::unfold(
        rx,
        |mut rx: broadcast::Receiver<NotifierEvent>| async move {
            match rx.recv().await {
                Ok(ev) => {
                    let payload = serde_json::to_string(&ev).unwrap();
                    let line = format!("data: {}\n\n", payload);
                    Some((
                        Ok::<Frame<Bytes>, hyper::Error>(Frame::data(Bytes::from(line))),
                        rx,
                    ))
                }
                // Closed → channel dropped, stop. Lagged → drop this connection;
                // the dashboard JS reconnects and gets a fresh snapshot.
                Err(_) => None,
            }
        },
    );

    let body = StreamBody::new(initial_stream.chain(event_stream));

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        // X-Accel-Buffering disables proxy buffering (nginx); harmless otherwise.
        .header("X-Accel-Buffering", "no")
        .body(BodyExt::boxed(body))
        .unwrap()
}

async fn serve_decision(
    manager: Arc<ApprovalManager>,
    id: &str,
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => return bad_request(&e),
    };
    let decision: ApprovalDecision = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => return bad_request(&format!("invalid decision JSON: {}", e)),
    };

    // Snapshot the pending approval to pick up the agent's proposed rules
    // as the default when the user didn't edit them.
    let snap = manager.snapshot_pending(id);
    let proposed_rules = match snap {
        Some(req) => req.rules,
        None => {
            return not_found();
        }
    };

    let status = match decision.action {
        DecisionAction::Approve => ApprovalStatus::Approved {
            rules_applied: decision.rules_applied.unwrap_or(proposed_rules),
            ttl: decision.ttl.unwrap_or(Lifetime::Permanent),
        },
        DecisionAction::Deny => ApprovalStatus::Denied {
            message: decision.message,
        },
    };

    match manager.resolve(id, status) {
        Ok(()) => no_content(),
        Err(super::types::ApprovalError::NotFound) => not_found(),
        Err(e) => bad_request(&format!("{}", e)),
    }
}

#[derive(Deserialize)]
struct PermissiveBody {
    duration_secs: u64,
}

async fn serve_permissive(
    manager: Arc<ApprovalManager>,
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => return bad_request(&e),
    };
    let parsed: PermissiveBody = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return bad_request(&format!("invalid JSON: {}", e)),
    };
    if parsed.duration_secs == 0 {
        manager.clear_permissive();
    } else {
        manager.set_permissive(std::time::Duration::from_secs(parsed.duration_secs));
    }
    no_content()
}

#[derive(Deserialize)]
struct AddRulesBody {
    rules: Vec<Rule>,
    ttl: Lifetime,
}

#[derive(Serialize)]
struct AddRulesResponse {
    approval_id: String,
}

async fn serve_add_rules(
    manager: Arc<ApprovalManager>,
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => return bad_request(&e),
    };
    let parsed: AddRulesBody = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return bad_request(&format!("invalid JSON: {}", e)),
    };
    match manager.add_rules(parsed.rules, parsed.ttl) {
        Ok(approval_id) => json_response(StatusCode::OK, &AddRulesResponse { approval_id }),
        Err(e) => bad_request(&format!("{}", e)),
    }
}

#[derive(Deserialize)]
struct RulesParseBody {
    toml: String,
}

#[derive(Deserialize)]
struct RulesWrapper {
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct RulesParseResponse {
    rules: Vec<Rule>,
}

async fn serve_rules_parse(req: Request<Incoming>) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => return bad_request(&e),
    };
    let parsed: RulesParseBody = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return bad_request(&format!("invalid JSON: {}", e)),
    };
    // Accept either a single `[[rules]]` table-array form or a bare rule
    // table. Try the wrapper form first, then a bare table as fallback.
    let rules = match toml::from_str::<RulesWrapper>(&parsed.toml) {
        Ok(w) if !w.rules.is_empty() => w.rules,
        _ => match toml::from_str::<Rule>(&parsed.toml) {
            Ok(r) => vec![r],
            Err(e) => return bad_request(&format!("TOML parse error: {}", e)),
        },
    };
    for r in &rules {
        if let Err(e) = r.validate() {
            return bad_request(&format!("invalid rule: {}", e));
        }
    }
    json_response(StatusCode::OK, &RulesParseResponse { rules })
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RulesSuggestBody {
    AuditEntry { audit: AuditEntrySnapshot },
    RawRules { rules: Vec<Rule> },
}

#[derive(Serialize)]
struct RulesSuggestResponse {
    toml: String,
}

async fn serve_rules_suggest(req: Request<Incoming>) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => return bad_request(&e),
    };
    let parsed: RulesSuggestBody = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return bad_request(&format!("invalid JSON: {}", e)),
    };
    let toml_str = match parsed {
        RulesSuggestBody::AuditEntry { audit } => rule_suggest::suggest_for_audit_snapshot(&audit),
        RulesSuggestBody::RawRules { rules } => rule_suggest::format_rules_toml(&rules),
    };
    json_response(StatusCode::OK, &RulesSuggestResponse { toml: toml_str })
}

// ---------- helpers ----------

async fn read_body(req: Request<Incoming>) -> Result<Bytes, String> {
    req.into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .map_err(|e| format!("failed to read body: {}", e))
}

fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let json = serde_json::to_vec(body).unwrap_or_else(|_| b"null".to_vec());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json)).map_err(|e| match e {}).boxed())
        .unwrap()
}

fn no_content() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
        .unwrap()
}

fn not_found() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "text/plain")
        .body(
            Full::new(Bytes::from_static(b"not found\n"))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

fn bad_request(msg: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!("bad request: {}\n", msg);
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .unwrap()
}
