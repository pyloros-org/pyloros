//! Protected-branch enforcement for git pushes.
//!
//! Two-stage fast-forward check applied to ref updates whose name matches
//! one of the rule's `protected_branches` patterns:
//!
//! 1. **Pack walk** — parse the pushed packfile in-process and BFS commit
//!    parents from `new-sha`. If `old-sha` is reached, it's a fast-forward
//!    (fast path; no upstream traffic).
//!
//! 2. **Sidecar negotiation** — when the pack walk can't confirm (thin
//!    pack, empty pack, or `Indeterminate`), issue a git protocol v2
//!    `fetch` `want`/`have` against the upstream `git-upload-pack`
//!    endpoint. The server's `acknowledgments` reply is authoritative on
//!    its own commit graph: `ACK` → fast-forward, `NAK` → force-push,
//!    anything else → fail closed.
//!
//! Returns the set of ref names that should be blocked. Caller is
//! responsible for producing the audit entry and the git error response;
//! this module owns only the *decision*.

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::Request;
use rustls::ClientConfig;
use std::sync::Arc;

use crate::filter::pack::{self, AncestryResult};
use crate::filter::pktline;
use crate::filter::upstream_negotiate::{self, AncestryCheck};
use crate::filter::BranchFilter;

use super::tunnel::forward_request_boxed;

/// Upstream connection settings used by the sidecar negotiation. Mirrors
/// the same overrides the main proxy forwarding path honors so tests can
/// point at a local upstream.
#[derive(Default, Clone)]
pub struct UpstreamConfig {
    pub host_override: Option<String>,
    pub port_override: Option<u16>,
    pub tls_config: Option<Arc<ClientConfig>>,
}

/// Evaluate every protected-branch ref update in a buffered receive-pack
/// body. Returns the names of refs whose update should be rejected.
///
/// - Deletions of protected refs → blocked.
/// - New ref creations (`old-sha = 0`) → allowed.
/// - Existing ref updates → require fast-forward, verified first by pack
///   walk and then by upstream negotiation.
pub async fn check_violations(
    body_bytes: &[u8],
    filter: &BranchFilter,
    host: &str,
    port: u16,
    request_path: &str,
    client_headers: &hyper::header::HeaderMap,
    upstream: &UpstreamConfig,
) -> Vec<String> {
    let updates = pktline::extract_push_updates(body_bytes);
    let pack_bytes = pktline::pack_bytes_in_body(body_bytes);
    let mut blocked = Vec::new();

    for u in updates {
        if !filter.is_protected(&u.name) {
            continue;
        }
        if u.is_delete() {
            tracing::warn!(
                refname = %u.name,
                "force-push check: delete of protected ref — blocking"
            );
            blocked.push(u.name);
            continue;
        }
        if u.is_create() {
            continue;
        }

        let pack_walk = pack_bytes.map(|pb| pack::pack_contains_ancestry(pb, &u.old, &u.new));

        match pack_walk {
            Some(AncestryResult::IsAncestor) => {
                tracing::info!(
                    refname = %u.name,
                    "force-push check: fast-forward confirmed by pack walk"
                );
            }
            Some(AncestryResult::NotAncestor) | Some(AncestryResult::Indeterminate) | None => {
                tracing::info!(
                    refname = %u.name,
                    "force-push check: pack walk inconclusive, querying upstream"
                );
                let check = upstream_ancestry_check(
                    host,
                    port,
                    request_path,
                    client_headers,
                    &u.old,
                    &u.new,
                    upstream,
                )
                .await;
                match check {
                    AncestryCheck::Acked => {
                        tracing::info!(
                            refname = %u.name,
                            "force-push check: fast-forward confirmed by upstream ACK"
                        );
                    }
                    AncestryCheck::Nak => {
                        tracing::warn!(
                            refname = %u.name,
                            "force-push check: upstream NAK — force-push detected"
                        );
                        blocked.push(u.name);
                    }
                    AncestryCheck::Error(reason) => {
                        tracing::warn!(
                            refname = %u.name,
                            reason = %reason,
                            "force-push check: upstream query failed — blocking (fail closed)"
                        );
                        blocked.push(u.name);
                    }
                }
            }
        }
    }

    blocked
}

/// Issue a v2 `fetch` `want`/`have` against the upstream's
/// `git-upload-pack` endpoint and interpret the ACK/NAK reply.
async fn upstream_ancestry_check(
    host: &str,
    port: u16,
    request_path: &str,
    client_headers: &hyper::header::HeaderMap,
    old: &[u8; 20],
    new: &[u8; 20],
    upstream: &UpstreamConfig,
) -> AncestryCheck {
    let base = request_path
        .strip_suffix("/git-receive-pack")
        .unwrap_or(request_path);
    let upload_pack_path = format!("{}/git-upload-pack", base);

    let body_bytes = Bytes::from(upstream_negotiate::build_v2_fetch_body(new, old));
    let body_len = body_bytes.len();

    let connect_host = upstream
        .host_override
        .clone()
        .unwrap_or_else(|| host.to_string());
    let connect_port = upstream.port_override.unwrap_or(port);
    let sni_host = host.to_string();
    let authority = if port == 443 {
        sni_host.clone()
    } else {
        format!("{}:{}", sni_host, port)
    };
    let uri_str = format!("https://{}{}", authority, upload_pack_path);

    let mut builder = Request::builder()
        .method("POST")
        .uri(&uri_str)
        .header(hyper::header::HOST, &authority)
        .header(
            hyper::header::CONTENT_TYPE,
            "application/x-git-upload-pack-request",
        )
        .header(
            hyper::header::ACCEPT,
            "application/x-git-upload-pack-result",
        )
        .header("Git-Protocol", "version=2")
        .header(hyper::header::CONTENT_LENGTH, body_len.to_string());

    if let Some(v) = client_headers.get(hyper::header::AUTHORIZATION) {
        builder = builder.header(hyper::header::AUTHORIZATION, v);
    }

    let req_body = Full::new(body_bytes)
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed();
    let req: Request<BoxBody<Bytes, hyper::Error>> = match builder.body(req_body) {
        Ok(r) => r,
        Err(e) => return AncestryCheck::Error(format!("build request: {}", e)),
    };

    let resp = match forward_request_boxed(
        req,
        connect_host,
        connect_port,
        sni_host,
        upstream.tls_config.clone(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return AncestryCheck::Error(format!("upstream request failed: {}", e)),
    };

    if !resp.status().is_success() {
        return AncestryCheck::Error(format!("upstream HTTP {}", resp.status()));
    }

    let body = match resp.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => return AncestryCheck::Error(format!("read response: {}", e)),
    };

    upstream_negotiate::parse_fetch_response(&body)
}
