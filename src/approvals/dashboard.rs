//! Human-facing dashboard served on the dedicated `dashboard_bind` listener.
//!
//! Endpoints:
//! - `GET /`                           — HTML page (includes inline JS for SSE + Notification API)
//! - `GET /events`                     — Server-Sent Events stream
//! - `POST /approvals/{id}/decision`   — record a decision for the given approval id

use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream::{self, StreamExt};
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;

use super::state::ApprovalManager;
use super::types::{
    ApprovalDecision, ApprovalRequest, ApprovalStatus, DecisionAction, Lifetime, NotifierEvent,
};

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

    match (&method, path.as_str()) {
        (&Method::GET, "/") => serve_html(),
        (&Method::GET, "/events") => serve_events(manager),
        (&Method::POST, p) if p.starts_with("/approvals/") && p.ends_with("/decision") => {
            let id = p
                .trim_start_matches("/approvals/")
                .trim_end_matches("/decision")
                .to_string();
            serve_decision(manager, &id, req).await
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

/// SSE event payload sent on stream open: the current set of pending approvals.
#[derive(Serialize)]
struct Snapshot<'a> {
    event: &'static str,
    approvals: &'a [ApprovalRequest],
}

fn serve_events(manager: Arc<ApprovalManager>) -> Response<BoxBody<Bytes, hyper::Error>> {
    let rx = manager.subscribe_events();
    let pending = manager.list_pending();

    // First frame: snapshot of current pending approvals so a reconnecting
    // dashboard immediately sees state without waiting for the next event.
    let snapshot = Snapshot {
        event: "snapshot",
        approvals: &pending,
    };
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
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return bad_request(&format!("failed to read body: {}", e)),
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
        Ok(()) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap(),
        Err(super::types::ApprovalError::NotFound) => not_found(),
        Err(e) => bad_request(&format!("{}", e)),
    }
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

// NotifierEvent is only referenced via type inference on the broadcast
// channel; the import must remain so `subscribe_events`'s return type
// is in scope. Keep Lifetime import explicit since it's constructed
// in `serve_decision`.
#[allow(dead_code)]
fn _type_refs(_: Option<NotifierEvent>, _: Option<Lifetime>) {}
