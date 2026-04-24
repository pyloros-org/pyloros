//! Human-facing dashboard served on the dedicated `dashboard_bind` listener.
//!
//! Phase 1: returns `501 Not Implemented` for all paths. Real handlers land
//! in Phase 3 (`GET /`, `GET /events`, `POST /approvals/{id}/decision`).

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};

use super::state::ApprovalManager;

/// Serve a single dashboard HTTP connection.
pub async fn serve_connection<S>(manager: Arc<ApprovalManager>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req: Request<Incoming>| {
        let _manager = Arc::clone(&manager);
        async move { dispatch(req).await }
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
    _req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .header("Content-Type", "text/plain")
        .body(
            Full::new(Bytes::from_static(b"dashboard not yet implemented\n"))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap())
}
