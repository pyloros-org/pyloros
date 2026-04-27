//! Agent-facing HTTP API at `https://pyloros.internal/`.
//!
//! Phase 2: `POST /approvals` and `GET /approvals/{id}?wait=60s` long-poll.
//! Rule merging (Phase 4), dedup + rate limit (Phase 6), and TTL/storage
//! (Phase 5) land later.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde::Deserialize;

use crate::config::Rule;
use crate::filter::FilterEngine;

use super::dedup;
use super::state::ApprovalManager;
use super::types::{ApprovalError, ApprovalRequest, ApprovalStatus, Lifetime, TriggeredBy};

/// Max time an agent may request to long-poll. Agents asking for more
/// get clamped; they should re-poll on timeout anyway.
const MAX_LONG_POLL: Duration = Duration::from_secs(60);
const DEFAULT_LONG_POLL: Duration = Duration::from_secs(30);

/// Agent-facing protocol documentation. Served at `GET /` on
/// `pyloros.internal` so an agent can always fetch the up-to-date
/// spec for the running build instead of relying on stale prompt
/// blurbs.
const AGENT_INSTRUCTIONS: &str = include_str!("agent_instructions.md");

/// Dispatch an agent-facing request to the appropriate handler.
///
/// When the approvals feature is disabled (`manager` is `None`), returns 404
/// so the sandbox can't tell the difference between "feature off" and
/// "endpoint doesn't exist".
pub async fn serve(
    manager: Option<&Arc<ApprovalManager>>,
    engine: Arc<FilterEngine>,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let Some(manager) = manager else {
        return Ok(not_found());
    };

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (&method, path.as_str()) {
        (&Method::GET, "/") => Ok(serve_instructions()),
        (&Method::POST, "/approvals") => Ok(handle_post(manager, engine.as_ref(), req).await),
        (&Method::GET, p) if p.starts_with("/approvals/") => {
            let id = p.trim_start_matches("/approvals/").to_string();
            let wait = parse_wait(req.uri().query());
            Ok(handle_get(manager, &id, wait).await)
        }
        _ => Ok(not_found()),
    }
}

fn serve_instructions() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/markdown; charset=utf-8")
        .body(
            Full::new(Bytes::from_static(AGENT_INSTRUCTIONS.as_bytes()))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

#[derive(Deserialize)]
struct PostBody {
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    context: Option<Context>,
    #[serde(default)]
    suggested_ttl: Option<Lifetime>,
}

#[derive(Deserialize)]
struct Context {
    #[serde(default)]
    triggered_by: Option<TriggeredBy>,
}

async fn handle_post(
    manager: &Arc<ApprovalManager>,
    engine: &FilterEngine,
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return bad_request(&format!("failed to read body: {}", e)),
    };
    let parsed: PostBody = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return bad_request(&format!("invalid JSON body: {}", e)),
    };
    if parsed.rules.is_empty() {
        return bad_request("at least one rule is required");
    }

    let triggered_by = parsed.context.and_then(|c| c.triggered_by);

    // Dedup (I4): if the proposed rules are already covered by the
    // active ruleset, short-circuit as approved — no pending entry,
    // no rate-limit consumption, no dashboard notification.
    if dedup::all_subsumed(engine, &parsed.rules, triggered_by.as_ref()) {
        let auto = ApprovalRequest {
            id: "apr_dedup".to_string(),
            rules: parsed.rules.clone(),
            reason: parsed.reason,
            triggered_by,
            suggested_ttl: parsed.suggested_ttl,
            status: ApprovalStatus::Approved {
                rules_applied: parsed.rules,
                ttl: Lifetime::Session,
            },
        };
        tracing::debug!("approvals: auto-approved via dedup");
        return json_response(StatusCode::OK, &auto);
    }

    match manager.post(
        parsed.rules,
        parsed.reason,
        triggered_by,
        parsed.suggested_ttl,
    ) {
        Ok(request) => json_response(StatusCode::ACCEPTED, &request),
        Err(ApprovalError::RateLimited) => Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Content-Type", "text/plain")
            .body(
                Full::new(Bytes::from_static(b"approvals rate limit exceeded\n"))
                    .map_err(|e| match e {})
                    .boxed(),
            )
            .unwrap(),
        Err(ApprovalError::InvalidRule(msg)) => bad_request(&format!("invalid rule: {}", msg)),
        Err(e) => bad_request(&e.to_string()),
    }
}

async fn handle_get(
    manager: &Arc<ApprovalManager>,
    id: &str,
    wait: Duration,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    match manager.get(id, wait).await {
        Some(req) => json_response(StatusCode::OK, &req),
        None => not_found(),
    }
}

/// Parse `wait=60s` / `wait=60` / `wait=500ms` from the query string.
/// Returns a default and caps at `MAX_LONG_POLL`.
fn parse_wait(query: Option<&str>) -> Duration {
    let Some(q) = query else {
        return DEFAULT_LONG_POLL;
    };
    for pair in q.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(p) => p,
            None => continue,
        };
        if k != "wait" {
            continue;
        }
        let parsed = if let Some(n) = v.strip_suffix("ms") {
            n.parse::<u64>().ok().map(Duration::from_millis)
        } else if let Some(n) = v.strip_suffix('s') {
            n.parse::<u64>().ok().map(Duration::from_secs)
        } else {
            v.parse::<u64>().ok().map(Duration::from_secs)
        };
        if let Some(d) = parsed {
            return d.min(MAX_LONG_POLL);
        }
    }
    DEFAULT_LONG_POLL
}

fn json_response(
    status: StatusCode,
    value: &impl serde::Serialize,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = serde_json::to_vec(value).expect("serialization should not fail");
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
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

// Silence warning for `ApprovalRequest` used only via serde paths in this module.
#[allow(dead_code)]
fn _force_use(_: &ApprovalRequest) {}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    #[test]
    fn test_parse_wait_defaults() {
        let t = test_report!("parse_wait returns default for missing query");
        t.assert_eq("none", &parse_wait(None), &DEFAULT_LONG_POLL);
        t.assert_eq("empty", &parse_wait(Some("")), &DEFAULT_LONG_POLL);
        t.assert_eq(
            "other key",
            &parse_wait(Some("foo=bar")),
            &DEFAULT_LONG_POLL,
        );
    }

    #[test]
    fn test_parse_wait_formats() {
        let t = test_report!("parse_wait accepts s, ms, and bare-integer formats");
        t.assert_eq(
            "60s",
            &parse_wait(Some("wait=60s")),
            &Duration::from_secs(60),
        );
        t.assert_eq(
            "500ms",
            &parse_wait(Some("wait=500ms")),
            &Duration::from_millis(500),
        );
        t.assert_eq(
            "bare 5 = 5s",
            &parse_wait(Some("wait=5")),
            &Duration::from_secs(5),
        );
    }

    #[test]
    fn test_parse_wait_clamps() {
        let t = test_report!("parse_wait clamps to MAX_LONG_POLL");
        t.assert_eq(
            "1h requested",
            &parse_wait(Some("wait=3600s")),
            &MAX_LONG_POLL,
        );
    }
}
