//! Human-facing dashboard served on the dedicated `dashboard_bind` listener.
//!
//! Endpoints:
//! - `GET /`                              — HTML page (inline JS for SSE + Notification API)
//! - `GET /events`                        — Server-Sent Events stream; first frame is the
//!   snapshot used by the dashboard UI to initialize state
//! - `POST /approvals/{id}/decision`      — record a decision for the given approval id
//! - `DELETE /approvals/{id}/rules`       — revoke the active rules from an approval
//! - `POST /permissive`                   — set or clear the timeboxed permissive override
//! - `POST /rules`                        — add rules directly (no upstream approval)
//! - `POST /rules/parse`                  — parse TOML rule text → structured rules
//! - `POST /rules/suggest`                — server-built TOML pre-fill for a blocked
//!   audit entry or a re-format of existing rules

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use futures_util::stream::{self, Stream, StreamExt};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
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
    let app: Router = Router::new()
        .route("/", get(serve_html))
        .route("/events", get(serve_events))
        .route("/permissive", post(serve_permissive))
        .route("/rules", post(serve_add_rules))
        .route("/rules/parse", post(serve_rules_parse))
        .route("/rules/suggest", post(serve_rules_suggest))
        .route("/approvals/{id}/decision", post(serve_decision))
        .route("/approvals/{id}/rules", delete(serve_revoke))
        .with_state(manager);

    let io = TokioIo::new(stream);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().preserve_header_case(true).half_close(true);
    let service = TowerToHyperService::new(app.into_service::<Incoming>());
    if let Err(e) = builder.serve_connection(io, service).await {
        let err_str = e.to_string();
        if !err_str.contains("connection closed") && !err_str.contains("early eof") {
            tracing::debug!("dashboard service error: {}", e);
        }
    }
}

// ---------- routes ----------

async fn serve_html() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

/// Snapshot sent as the first SSE frame on `/events`. Dashboards
/// receive this once on connect and then maintain state by reacting
/// to subsequent `NotifierEvent` frames.
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

async fn serve_events(
    State(manager): State<Arc<ApprovalManager>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = manager.subscribe_events();
    let snapshot = build_snapshot(&manager);
    let initial = stream::once(async move { Ok(Event::default().json_data(&snapshot).unwrap()) });
    let live = stream::unfold(
        rx,
        |mut rx: broadcast::Receiver<NotifierEvent>| async move {
            match rx.recv().await {
                Ok(ev) => Some((Ok(Event::default().json_data(&ev).unwrap()), rx)),
                // Closed → channel dropped, stop. Lagged → drop this connection;
                // the dashboard JS reconnects and gets a fresh snapshot.
                Err(_) => None,
            }
        },
    );
    Sse::new(initial.chain(live)).keep_alive(KeepAlive::default())
}

async fn serve_decision(
    State(manager): State<Arc<ApprovalManager>>,
    Path(id): Path<String>,
    Json(decision): Json<ApprovalDecision>,
) -> Result<StatusCode, AppError> {
    // Snapshot the pending approval to pick up the agent's proposed rules
    // as the default when the user didn't edit them.
    let proposed_rules = manager
        .snapshot_pending(&id)
        .map(|req| req.rules)
        .ok_or(AppError::NotFound)?;

    let status = match decision.action {
        DecisionAction::Approve => ApprovalStatus::Approved {
            rules_applied: decision.rules_applied.unwrap_or(proposed_rules),
            ttl: decision.ttl.unwrap_or(Lifetime::Permanent),
        },
        DecisionAction::Deny => ApprovalStatus::Denied {
            message: decision.message,
        },
    };

    match manager.resolve(&id, status) {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(super::types::ApprovalError::NotFound) => Err(AppError::NotFound),
        Err(e) => Err(AppError::bad_request(e.to_string())),
    }
}

async fn serve_revoke(
    State(manager): State<Arc<ApprovalManager>>,
    Path(id): Path<String>,
) -> StatusCode {
    manager.revoke_approval(&id);
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
struct PermissiveBody {
    duration_secs: u64,
}

async fn serve_permissive(
    State(manager): State<Arc<ApprovalManager>>,
    Json(body): Json<PermissiveBody>,
) -> StatusCode {
    if body.duration_secs == 0 {
        manager.clear_permissive();
    } else {
        manager.set_permissive(std::time::Duration::from_secs(body.duration_secs));
    }
    StatusCode::NO_CONTENT
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
    State(manager): State<Arc<ApprovalManager>>,
    Json(body): Json<AddRulesBody>,
) -> Result<Json<AddRulesResponse>, AppError> {
    let approval_id = manager
        .add_rules(body.rules, body.ttl)
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    Ok(Json(AddRulesResponse { approval_id }))
}

#[derive(Deserialize)]
struct RulesParseBody {
    toml: String,
}

#[derive(Serialize)]
struct RulesParseResponse {
    rules: Vec<Rule>,
}

async fn serve_rules_parse(
    Json(body): Json<RulesParseBody>,
) -> Result<Json<RulesParseResponse>, AppError> {
    let rules = rule_suggest::parse_rules_toml(&body.toml)
        .map_err(|e| AppError::bad_request(format!("TOML parse error: {}", e)))?;
    for r in &rules {
        r.validate()
            .map_err(|e| AppError::bad_request(format!("invalid rule: {}", e)))?;
    }
    Ok(Json(RulesParseResponse { rules }))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RulesSuggestBody {
    AuditEntry { audit: Box<AuditEntrySnapshot> },
    RawRules { rules: Vec<Rule> },
}

#[derive(Serialize)]
struct RulesSuggestResponse {
    toml: String,
}

async fn serve_rules_suggest(Json(body): Json<RulesSuggestBody>) -> Json<RulesSuggestResponse> {
    let toml_str = match body {
        RulesSuggestBody::AuditEntry { audit } => {
            rule_suggest::suggest_for_audit_snapshot(audit.as_ref())
        }
        RulesSuggestBody::RawRules { rules } => rule_suggest::format_rules_toml(&rules),
    };
    Json(RulesSuggestResponse { toml: toml_str })
}

// ---------- error mapping ----------

enum AppError {
    NotFound,
    BadRequest(String),
}

impl AppError {
    fn bad_request(msg: impl Into<String>) -> Self {
        AppError::BadRequest(msg.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found\n").into_response(),
            AppError::BadRequest(m) => {
                (StatusCode::BAD_REQUEST, format!("bad request: {}\n", m)).into_response()
            }
        }
    }
}
