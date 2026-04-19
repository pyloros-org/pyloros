//! Shared HTTP response helpers for blocked/error responses

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{Response, StatusCode};

/// Create an HTTP 451 response for blocked requests
pub fn blocked_response(method: &str, url: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!(
        "Request blocked by proxy policy\n\nMethod: {}\nURL: {}\n",
        method, url
    );

    Response::builder()
        .status(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS) // 451
        .header("Content-Type", "text/plain")
        .header("X-Blocked-By", "pyloros")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .unwrap()
}

/// Create a git receive-pack error response for blocked pushes.
///
/// Instead of returning HTTP 451 (which git clients can't display meaningfully),
/// this returns HTTP 200 with `Content-Type: application/x-git-receive-pack-result`
/// containing proper `ng` (not good) status lines. Git clients parse these and
/// display them as "remote rejected" errors, similar to server-side pre-receive hooks.
pub fn git_blocked_push_response(
    body_bytes: &[u8],
    blocked: &[String],
) -> Response<BoxBody<Bytes, hyper::Error>> {
    use crate::filter::pktline;

    let capabilities = pktline::extract_capabilities(body_bytes);

    // Build a human-readable message listing blocked branches
    let branch_names: Vec<&str> = blocked
        .iter()
        .map(|r| r.strip_prefix("refs/heads/").unwrap_or(r))
        .collect();
    let message = if branch_names.len() == 1 {
        format!(
            "push to branch '{}' blocked by proxy policy",
            branch_names[0]
        )
    } else {
        format!(
            "push to branches [{}] blocked by proxy policy",
            branch_names.join(", ")
        )
    };

    let response_body = pktline::build_receive_pack_error(blocked, &message, &capabilities);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-receive-pack-result")
        .header("X-Blocked-By", "pyloros")
        .body(
            Full::new(Bytes::from(response_body))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

/// Create a git receive-pack error response for a force-push / delete /
/// non-fast-forward update to a protected branch.
///
/// Same transport as `git_blocked_push_response` (HTTP 200 with
/// `application/x-git-receive-pack-result`), but the stderr sideband message
/// identifies the cause specifically as protected-branch policy.
pub fn git_force_push_blocked_response(
    body_bytes: &[u8],
    blocked: &[String],
) -> Response<BoxBody<Bytes, hyper::Error>> {
    use crate::filter::pktline;

    let capabilities = pktline::extract_capabilities(body_bytes);

    let branch_names: Vec<&str> = blocked
        .iter()
        .map(|r| r.strip_prefix("refs/heads/").unwrap_or(r))
        .collect();
    let message = if branch_names.len() == 1 {
        format!(
            "force-push/delete to protected branch '{}' denied by proxy policy",
            branch_names[0]
        )
    } else {
        format!(
            "force-push/delete to protected branches [{}] denied by proxy policy",
            branch_names.join(", ")
        )
    };

    let response_body = pktline::build_receive_pack_error(blocked, &message, &capabilities);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-receive-pack-result")
        .header("X-Blocked-By", "pyloros")
        .body(
            Full::new(Bytes::from(response_body))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

/// Create an HTTP 407 Proxy Authentication Required response
pub fn auth_required_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", "Basic realm=\"pyloros\"")
        .header("Content-Type", "text/plain")
        .body(
            Full::new(Bytes::from("Proxy authentication required\n"))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

/// Create an HTTP 502 Bad Gateway error response
pub fn error_response(message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!("Proxy error: {}\n", message);

    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    #[test]
    fn test_blocked_response() {
        let t = test_report!("Blocked response returns 451");
        let resp = blocked_response("GET", "https://example.com/blocked");
        t.assert_eq(
            "Status",
            &resp.status(),
            &StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
        );
    }

    #[test]
    fn test_auth_required_response() {
        let t = test_report!("Auth required response returns 407");
        let resp = auth_required_response();
        t.assert_eq(
            "Status",
            &resp.status(),
            &StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        );
        t.assert_eq(
            "Proxy-Authenticate header",
            &resp
                .headers()
                .get("Proxy-Authenticate")
                .unwrap()
                .to_str()
                .unwrap(),
            &"Basic realm=\"pyloros\"",
        );
    }

    #[test]
    fn test_error_response() {
        let t = test_report!("Error response returns 502");
        let resp = error_response("test error");
        t.assert_eq("Status", &resp.status(), &StatusCode::BAD_GATEWAY);
    }
}
