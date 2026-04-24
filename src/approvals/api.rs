//! Agent-facing HTTP API at `https://pyloros.internal/`.
//!
//! Phase 1: returns `501 Not Implemented` for all paths. Real handlers land
//! in Phase 2 (`POST /approvals`, `GET /approvals/{id}?wait=...`).

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::state::ApprovalManager;

/// Dispatch an agent-facing request to the appropriate handler.
///
/// When the approvals feature is disabled (`manager` is `None`), returns 404
/// so the sandbox can't tell the difference between "feature off" and
/// "endpoint doesn't exist".
pub async fn serve(
    manager: Option<&Arc<ApprovalManager>>,
    _req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if manager.is_none() {
        return Ok(not_found());
    }
    Ok(not_implemented())
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

fn not_implemented() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .header("Content-Type", "text/plain")
        .body(
            Full::new(Bytes::from_static(b"approvals api not yet implemented\n"))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}
