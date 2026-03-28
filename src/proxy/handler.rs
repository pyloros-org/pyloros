//! HTTP request handler for the proxy

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpStream;

use super::response::{auth_required_response, blocked_response, error_response};
use super::tunnel::TunnelHandler;
use super::{RequestContext, RequestLogger};
use crate::audit::{AuditDecision, AuditEntry, AuditEvent, AuditLogger, AuditReason};
use crate::filter::{FilterEngine, FilterResult, RequestInfo};

use base64::Engine;

/// Main proxy request handler
pub struct ProxyHandler {
    tunnel_handler: Arc<TunnelHandler>,
    filter_engine: Arc<FilterEngine>,
    auth: Option<(String, String)>,
    logger: RequestLogger,
}

impl ProxyHandler {
    pub fn new(tunnel_handler: Arc<TunnelHandler>, filter_engine: Arc<FilterEngine>) -> Self {
        Self {
            tunnel_handler,
            filter_engine,
            auth: None,
            logger: RequestLogger::new(),
        }
    }

    pub fn with_request_logging(mut self, log_allowed: bool, log_blocked: bool) -> Self {
        self.logger = self.logger.with_request_logging(log_allowed, log_blocked);
        self
    }

    pub fn with_auth(mut self, auth: Option<(String, String)>) -> Self {
        self.auth = auth;
        self
    }

    pub fn with_audit_logger(mut self, logger: Option<Arc<AuditLogger>>) -> Self {
        self.logger = self.logger.with_audit_logger(logger);
        self
    }

    pub fn with_permissive(mut self, permissive: bool) -> Self {
        self.logger = self.logger.with_permissive(permissive);
        self
    }

    /// Check the Proxy-Authorization header against configured credentials.
    /// Returns true if auth is not configured or if credentials match.
    fn check_auth(&self, req: &Request<Incoming>) -> bool {
        let (expected_user, expected_pass) = match &self.auth {
            Some(creds) => creds,
            None => return true,
        };

        let header_value = match req.headers().get("proxy-authorization") {
            Some(v) => v,
            None => return false,
        };

        let header_str = match header_value.to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };

        let encoded = match header_str.strip_prefix("Basic ") {
            Some(e) => e,
            None => return false,
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(d) => d,
            Err(_) => return false,
        };

        let decoded_str = match std::str::from_utf8(&decoded) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let (user, pass) = match decoded_str.split_once(':') {
            Some(pair) => pair,
            None => return false,
        };

        user == expected_user && pass == expected_pass
    }

    /// Handle an incoming proxy request
    pub async fn handle(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        // Check proxy authentication before processing any request
        if !self.check_auth(&req) {
            tracing::warn!("Proxy authentication failed");
            let url = req.uri().to_string();
            let method = req.method().to_string();
            let host = req.uri().host().unwrap_or("unknown").to_string();
            self.logger.emit_audit(AuditEntry {
                timestamp: crate::audit::now_iso8601(),
                event: AuditEvent::AuthFailed,
                method,
                url,
                host,
                scheme: "unknown".to_string(),
                protocol: "unknown".to_string(),
                decision: AuditDecision::Blocked,
                reason: AuditReason::AuthFailed,
                credential: None,
                git: None,
                request_body: None,
                request_body_encoding: None,
                response_body: None,
                response_body_encoding: None,
                body_truncated: None,
            });
            return Ok(auth_required_response());
        }

        // Handle CONNECT requests (HTTPS tunneling)
        if req.method() == Method::CONNECT {
            return self.handle_connect(req).await;
        }

        // Handle regular HTTP requests (non-HTTPS)
        self.handle_http(req).await
    }

    async fn handle_connect(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let host = req.uri().host().unwrap_or("unknown").to_string();
        let port = req.uri().port_u16().unwrap_or(443);

        tracing::debug!(host = %host, port = %port, "CONNECT request");

        // Only allow HTTPS (port 443 or explicit https)
        if port != 443 {
            tracing::warn!(host = %host, port = %port, "Blocking non-HTTPS CONNECT");
            let url = format!("{}:{}", host, port);
            self.logger.emit_audit(AuditEntry {
                timestamp: crate::audit::now_iso8601(),
                event: AuditEvent::RequestBlocked,
                method: "CONNECT".to_string(),
                url: url.clone(),
                host: host.clone(),
                scheme: "unknown".to_string(),
                protocol: "unknown".to_string(),
                decision: AuditDecision::Blocked,
                reason: AuditReason::NonHttpsConnect,
                credential: None,
                git: None,
                request_body: None,
                request_body_encoding: None,
                response_body: None,
                response_body_encoding: None,
                body_truncated: None,
            });
            return Ok(blocked_response("CONNECT", &url));
        }

        // Get the upgrade future before we move the request
        let upgrade = hyper::upgrade::on(req);

        // Clone what we need for the spawned task
        let tunnel_handler = self.tunnel_handler.clone();

        // Spawn the tunnel handling
        tokio::spawn(async move {
            let upgraded = match upgrade.await {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!(host = %host, error = %e, "Failed to upgrade connection");
                    return;
                }
            };

            if let Err(e) = tunnel_handler.run_mitm_tunnel(upgraded, &host, port).await {
                // Don't log connection closed errors
                let err_str = e.to_string();
                if !err_str.contains("connection closed") && !err_str.contains("early eof") {
                    tracing::error!(host = %host, error = %e, "Tunnel error");
                }
            }
        });

        // Return 200 OK to indicate tunnel established
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
            .unwrap())
    }

    async fn handle_http(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        // For plain HTTP proxy requests, the full URL is in the request URI
        let uri = req.uri();
        let method = req.method().to_string();

        let scheme = uri.scheme_str().unwrap_or("http");
        let host = uri.host().unwrap_or("unknown").to_string();
        let port = uri.port_u16();
        let path = uri.path();
        let query = uri.query();

        let request_info = RequestInfo::http(&method, scheme, &host, port, path, query);
        let full_url = request_info.full_url();

        // Check filter
        let ctx = RequestContext {
            method: &method,
            url: &full_url,
            host: &host,
            scheme,
            protocol: "http",
            credential: None,
            label: " (HTTP)",
        };

        match self.filter_engine.check(&request_info) {
            FilterResult::Blocked => {
                if let Some(resp) = self.logger.log_blocked(&ctx) {
                    return Ok(resp);
                }
            }
            FilterResult::AllowedWithBranchCheck { .. }
            | FilterResult::AllowedWithLfsCheck { .. } => {
                // Git rules with branch restrictions or LFS operation checks
                // require body inspection, which is only supported over HTTPS
                // CONNECT tunnels. Block plain HTTP to maintain default-deny.
                if self.logger.log_blocked_requests {
                    tracing::warn!(
                        method = %method,
                        url = %full_url,
                        "BLOCKED (HTTP: body inspection requires HTTPS)"
                    );
                }
                self.logger.emit_audit(AuditEntry {
                    timestamp: crate::audit::now_iso8601(),
                    event: AuditEvent::RequestBlocked,
                    method: method.clone(),
                    url: full_url.clone(),
                    host: host.clone(),
                    scheme: scheme.to_string(),
                    protocol: "http".to_string(),
                    decision: AuditDecision::Blocked,
                    reason: AuditReason::BodyInspectionRequiresHttps,
                    credential: None,
                    git: None,
                    request_body: None,
                    request_body_encoding: None,
                    response_body: None,
                    response_body_encoding: None,
                    body_truncated: None,
                });
                return Ok(blocked_response(&method, &full_url));
            }
            FilterResult::Allowed { .. } => {
                self.logger.log_allowed(&ctx);
            }
        }

        let upstream_port = port.unwrap_or(80);
        match forward_http_request(&host, upstream_port, req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::error!(host = %host, port = %upstream_port, error = %e, "HTTP forwarding error");
                Ok(error_response(&e.to_string()))
            }
        }
    }
}

/// Forward a plain HTTP request to the upstream server.
async fn forward_http_request(
    host: &str,
    port: u16,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    // Connect to upstream
    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect(&addr).await?;
    let io = TokioIo::new(tcp);

    // HTTP/1.1 handshake
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    // Spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            let err_str = e.to_string();
            if !err_str.contains("connection closed") && !err_str.contains("early eof") {
                tracing::error!(error = %e, "HTTP upstream connection error");
            }
        }
    });

    // Rebuild request: relative URI, strip hop-by-hop headers, ensure Host header
    let (mut parts, body) = req.into_parts();

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let new_uri: hyper::Uri = path_and_query.parse()?;

    super::strip_hop_by_hop_headers(&mut parts.headers);

    let mut builder = Request::builder().method(parts.method).uri(new_uri);

    // Copy remaining headers
    for (name, value) in &parts.headers {
        builder = builder.header(name, value);
    }

    // Ensure Host header is present
    if !parts.headers.contains_key(hyper::header::HOST) {
        if port == 80 {
            builder = builder.header(hyper::header::HOST, host);
        } else {
            builder = builder.header(hyper::header::HOST, format!("{}:{}", host, port));
        }
    }

    let upstream_req = builder.body(body)?;
    let resp = sender.send_request(upstream_req).await?;

    // Map the response body to BoxBody
    Ok(resp.map(|b| b.boxed()))
}
