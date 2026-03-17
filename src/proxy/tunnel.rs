//! CONNECT tunnel handling with TLS MITM

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::response::{blocked_response, error_response, git_blocked_push_response};
use crate::audit::{
    AuditCredential, AuditDecision, AuditEntry, AuditEvent, AuditGitInfo, AuditLogger, AuditReason,
};
use crate::error::{Error, Result};
use crate::filter::lfs;
use crate::filter::pktline;
use crate::filter::{CredentialEngine, FilterEngine, FilterResult, RequestInfo};
use crate::tls::MitmCertificateGenerator;

/// Handles CONNECT tunnels with TLS MITM
pub struct TunnelHandler {
    mitm_generator: Arc<MitmCertificateGenerator>,
    filter_engine: Arc<FilterEngine>,
    credential_engine: Arc<CredentialEngine>,
    audit_logger: Option<Arc<AuditLogger>>,
    upstream_port_override: Option<u16>,
    upstream_host_override: Option<String>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
    log_allowed_requests: bool,
    log_blocked_requests: bool,
}

impl TunnelHandler {
    pub fn new(
        mitm_generator: Arc<MitmCertificateGenerator>,
        filter_engine: Arc<FilterEngine>,
        credential_engine: Arc<CredentialEngine>,
    ) -> Self {
        Self {
            mitm_generator,
            filter_engine,
            credential_engine,
            audit_logger: None,
            upstream_port_override: None,
            upstream_host_override: None,
            upstream_tls_config: None,
            log_allowed_requests: true,
            log_blocked_requests: true,
        }
    }

    /// Override the upstream port for all forwarded connections (for testing).
    pub fn with_upstream_port_override(mut self, port: u16) -> Self {
        self.upstream_port_override = Some(port);
        self
    }

    /// Override the upstream host for TCP connections (for testing with non-resolvable hostnames).
    /// The original hostname is still used for TLS SNI.
    pub fn with_upstream_host_override(mut self, host: String) -> Self {
        self.upstream_host_override = Some(host);
        self
    }

    /// Inject a custom TLS config for upstream connections (for testing with self-signed certs).
    pub fn with_upstream_tls(mut self, config: Arc<ClientConfig>) -> Self {
        self.upstream_tls_config = Some(config);
        self
    }

    /// Set the audit logger for structured request logging.
    pub fn with_audit_logger(mut self, logger: Arc<AuditLogger>) -> Self {
        self.audit_logger = Some(logger);
        self
    }

    /// Configure request logging.
    pub fn with_request_logging(mut self, log_allowed: bool, log_blocked: bool) -> Self {
        self.log_allowed_requests = log_allowed;
        self.log_blocked_requests = log_blocked;
        self
    }

    fn emit_audit(&self, entry: AuditEntry) {
        if let Some(ref logger) = self.audit_logger {
            logger.log(&entry);
        }
    }

    /// Build the first matching credential info for the audit entry.
    fn audit_credential(&self, request_info: &RequestInfo) -> Option<AuditCredential> {
        self.credential_engine
            .matched_credential_infos(request_info)
            .into_iter()
            .next()
            .map(|(cred_type, url_pattern)| AuditCredential {
                cred_type,
                url_pattern,
            })
    }

    /// Run a MITM tunnel on an upgraded connection
    pub async fn run_mitm_tunnel(
        self: &Arc<Self>,
        upgraded: hyper::upgrade::Upgraded,
        host: &str,
        port: u16,
    ) -> Result<()> {
        let upgraded = TokioIo::new(upgraded);

        // Create TLS acceptor for the client connection
        let server_config = self.mitm_generator.server_config_for_host(host)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        // Accept TLS from client
        let client_tls = acceptor
            .accept(upgraded)
            .await
            .map_err(|e| Error::tls(format!("Failed to accept TLS from client: {}", e)))?;

        tracing::debug!(host = %host, "TLS handshake with client complete");

        self.serve_tls_http(client_tls, host, port).await;

        Ok(())
    }

    /// Serve HTTP requests over an established TLS connection.
    ///
    /// Shared by CONNECT tunnel (after MITM handshake) and direct HTTPS listener
    /// (after SNI-based handshake). Handles HTTP/1.1 and HTTP/2 via ALPN.
    pub async fn serve_tls_http<S>(self: &Arc<Self>, tls_stream: S, host: &str, port: u16)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let host = host.to_string();
        let handler = Arc::clone(self);

        let service = service_fn(move |req: Request<Incoming>| {
            let host = host.clone();
            let handler = Arc::clone(&handler);
            async move { handler.handle_tunneled_request(req, &host, port).await }
        });

        let io = TokioIo::new(tls_stream);
        let mut builder = auto::Builder::new(TokioExecutor::new());
        builder.http1().preserve_header_case(true).half_close(true);

        if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
            let err_str = e.to_string();
            if !err_str.contains("connection closed") && !err_str.contains("early eof") {
                tracing::debug!("HTTP service error: {}", e);
            }
        }
    }

    /// Handle a request that came through the MITM tunnel or direct HTTPS listener.
    pub async fn handle_tunneled_request(
        &self,
        req: Request<Incoming>,
        host: &str,
        port: u16,
    ) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let query = req.uri().query().map(|s| s.to_string());

        // Check for WebSocket upgrade
        let is_websocket = req
            .headers()
            .get(hyper::header::UPGRADE)
            .map(|v| {
                v.to_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains("websocket")
            })
            .unwrap_or(false);

        // Create request info for filtering
        let request_info = if is_websocket {
            RequestInfo::websocket("https", host, Some(port), &path, query.as_deref())
        } else {
            RequestInfo::http(&method, "https", host, Some(port), &path, query.as_deref())
        };

        let full_url = request_info.full_url();

        // Check filter
        let filter_result = self.filter_engine.check(&request_info);

        match filter_result {
            FilterResult::Blocked => {
                if self.log_blocked_requests {
                    tracing::warn!(
                        method = %method,
                        url = %full_url,
                        "BLOCKED"
                    );
                }
                self.emit_audit(AuditEntry {
                    timestamp: crate::audit::now_iso8601(),
                    event: AuditEvent::RequestBlocked,
                    method: method.clone(),
                    url: full_url.clone(),
                    host: host.to_string(),
                    scheme: "https".to_string(),
                    protocol: "https".to_string(),
                    decision: AuditDecision::Blocked,
                    reason: AuditReason::NoMatchingRule,
                    credential: None,
                    git: None,
                });
                return Ok(blocked_response(&method, &full_url));
            }
            FilterResult::AllowedWithBranchCheck(ref filter) => {
                if self.log_allowed_requests {
                    tracing::info!(
                        method = %method,
                        url = %full_url,
                        "ALLOWED (branch check pending)"
                    );
                }

                // Buffer the request body to inspect pkt-line refs
                // TODO: optimize by reading only the pkt-line prefix, then chaining
                // with the remaining stream for forwarding
                let (mut parts, body) = req.into_parts();
                let body_bytes = body
                    .collect()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to buffer request body for branch check");
                        e
                    })?
                    .to_bytes();

                let blocked = pktline::blocked_refs_with_filter(&body_bytes, filter);
                if !blocked.is_empty() {
                    if self.log_blocked_requests {
                        tracing::warn!(
                            method = %method,
                            url = %full_url,
                            blocked_refs = ?blocked,
                            "BLOCKED (branch restriction)"
                        );
                    }
                    self.emit_audit(AuditEntry {
                        timestamp: crate::audit::now_iso8601(),
                        event: AuditEvent::RequestBlocked,
                        method: method.clone(),
                        url: full_url.clone(),
                        host: host.to_string(),
                        scheme: "https".to_string(),
                        protocol: "https".to_string(),
                        decision: AuditDecision::Blocked,
                        reason: AuditReason::BranchRestriction,
                        credential: None,
                        git: Some(AuditGitInfo {
                            blocked_refs: blocked.clone(),
                        }),
                    });
                    return Ok(git_blocked_push_response(&body_bytes, &blocked));
                }

                // Allowed after branch check
                self.emit_audit(AuditEntry {
                    timestamp: crate::audit::now_iso8601(),
                    event: AuditEvent::RequestAllowed,
                    method: method.clone(),
                    url: full_url.clone(),
                    host: host.to_string(),
                    scheme: "https".to_string(),
                    protocol: "https".to_string(),
                    decision: AuditDecision::Allowed,
                    reason: AuditReason::RuleMatched,
                    credential: self.audit_credential(&request_info),
                    git: None,
                });

                // Inject credentials (body already buffered)
                self.credential_engine.inject_with_body(
                    &request_info,
                    &mut parts.headers,
                    &body_bytes,
                );

                return self
                    .forward_buffered(parts, body_bytes, host, port, &method, &full_url)
                    .await;
            }
            FilterResult::AllowedWithLfsCheck(ref allowed_ops) => {
                if self.log_allowed_requests {
                    tracing::info!(
                        method = %method,
                        url = %full_url,
                        "ALLOWED (LFS check pending)"
                    );
                }

                // Buffer the request body to inspect the LFS operation field
                let (parts, body) = req.into_parts();
                let body_bytes = body
                    .collect()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to buffer request body for LFS check");
                        e
                    })?
                    .to_bytes();

                if !lfs::check_lfs_operation(&body_bytes, allowed_ops) {
                    if self.log_blocked_requests {
                        tracing::warn!(
                            method = %method,
                            url = %full_url,
                            allowed_ops = ?allowed_ops,
                            "BLOCKED (LFS operation not allowed)"
                        );
                    }
                    self.emit_audit(AuditEntry {
                        timestamp: crate::audit::now_iso8601(),
                        event: AuditEvent::RequestBlocked,
                        method: method.clone(),
                        url: full_url.clone(),
                        host: host.to_string(),
                        scheme: "https".to_string(),
                        protocol: "https".to_string(),
                        decision: AuditDecision::Blocked,
                        reason: AuditReason::LfsOperationNotAllowed,
                        credential: None,
                        git: None,
                    });
                    return Ok(blocked_response(&method, &full_url));
                }

                // Allowed after LFS check
                self.emit_audit(AuditEntry {
                    timestamp: crate::audit::now_iso8601(),
                    event: AuditEvent::RequestAllowed,
                    method: method.clone(),
                    url: full_url.clone(),
                    host: host.to_string(),
                    scheme: "https".to_string(),
                    protocol: "https".to_string(),
                    decision: AuditDecision::Allowed,
                    reason: AuditReason::RuleMatched,
                    credential: self.audit_credential(&request_info),
                    git: None,
                });

                return self
                    .forward_buffered(parts, body_bytes, host, port, &method, &full_url)
                    .await;
            }
            FilterResult::Allowed => {
                if self.log_allowed_requests {
                    tracing::info!(
                        method = %method,
                        url = %full_url,
                        "ALLOWED"
                    );
                }
                self.emit_audit(AuditEntry {
                    timestamp: crate::audit::now_iso8601(),
                    event: AuditEvent::RequestAllowed,
                    method: method.clone(),
                    url: full_url.clone(),
                    host: host.to_string(),
                    scheme: "https".to_string(),
                    protocol: "https".to_string(),
                    decision: AuditDecision::Allowed,
                    reason: AuditReason::RuleMatched,
                    credential: self.audit_credential(&request_info),
                    git: None,
                });
            }
        }

        // Forward the request to the actual server
        let connect_port = self.upstream_port_override.unwrap_or(port);
        let connect_host = self
            .upstream_host_override
            .as_deref()
            .unwrap_or(host)
            .to_string();
        let result = if is_websocket {
            // Inject credentials into the WebSocket request before forwarding
            let (mut parts, body) = req.into_parts();
            self.credential_engine
                .inject(&request_info, &mut parts.headers);
            let req = Request::from_parts(parts, body);
            forward_websocket(
                req,
                connect_host,
                connect_port,
                host.to_string(),
                self.upstream_tls_config.clone(),
            )
            .await
        } else if self.credential_engine.needs_body(&request_info) {
            // SigV4 credentials need the full body for signing.
            // Set the upstream Host header BEFORE signing so the signature covers
            // the final host value that the upstream server will see.
            let (mut parts, body) = req.into_parts();
            super::strip_hop_by_hop_headers(&mut parts.headers);
            let upstream_host_value = if connect_port == 443 {
                host.to_string()
            } else {
                format!("{}:{}", host, connect_port)
            };
            if let Ok(hv) = hyper::header::HeaderValue::from_str(&upstream_host_value) {
                parts.headers.insert(hyper::header::HOST, hv);
            }
            let body_bytes = body
                .collect()
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to buffer request body for SigV4 signing");
                    e
                })?
                .to_bytes();
            self.credential_engine
                .inject_with_body(&request_info, &mut parts.headers, &body_bytes);
            let full_body = Full::new(body_bytes).map_err(|e| match e {}).boxed();
            // Host already set, build request without rebuild_request_for_upstream
            // to avoid double-setting it
            let req = Request::from_parts(parts, full_body);
            forward_request_boxed(
                req,
                connect_host,
                connect_port,
                host.to_string(),
                self.upstream_tls_config.clone(),
            )
            .await
        } else {
            let (mut parts, body) = req.into_parts();
            super::strip_hop_by_hop_headers(&mut parts.headers);
            self.credential_engine
                .inject(&request_info, &mut parts.headers);
            let req = rebuild_request_for_upstream(parts, body.boxed(), host, connect_port);
            match req {
                Ok(req) => {
                    forward_request_boxed(
                        req,
                        connect_host,
                        connect_port,
                        host.to_string(),
                        self.upstream_tls_config.clone(),
                    )
                    .await
                }
                Err(e) => Err(e),
            }
        };

        match result {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::error!(method = %method, url = %full_url, error = %e, "Failed to forward request");
                Ok(error_response(&e.to_string()))
            }
        }
    }

    /// Rebuild a buffered request for upstream and forward it.
    /// Shared by branch-check and LFS-check arms.
    async fn forward_buffered(
        &self,
        mut parts: hyper::http::request::Parts,
        body_bytes: Bytes,
        host: &str,
        port: u16,
        method: &str,
        full_url: &str,
    ) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let connect_port = self.upstream_port_override.unwrap_or(port);
        let connect_host = self
            .upstream_host_override
            .as_deref()
            .unwrap_or(host)
            .to_string();
        super::strip_hop_by_hop_headers(&mut parts.headers);
        let full_body = Full::new(body_bytes).map_err(|e| match e {}).boxed();
        let req = match rebuild_request_for_upstream(parts, full_body, host, connect_port) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "Failed to rebuild request");
                return Ok(error_response(&e.to_string()));
            }
        };
        let result = forward_request_boxed(
            req,
            connect_host,
            connect_port,
            host.to_string(),
            self.upstream_tls_config.clone(),
        )
        .await;

        match result {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::error!(method = %method, url = %full_url, error = %e, "Failed to forward request");
                Ok(error_response(&e.to_string()))
            }
        }
    }
}

/// Connect to upstream over TLS, returning the TLS stream.
///
/// Shared by both `forward_request` (which branches h1/h2 based on ALPN)
/// and `forward_websocket` (which always uses h1 with upgrades).
///
/// `connect_host` is the hostname/IP used for TCP connection (may be overridden
/// for testing). `sni_host` is the hostname used for TLS SNI.
async fn connect_upstream_tls(
    connect_host: &str,
    port: u16,
    sni_host: &str,
    upstream_tls_config: Option<Arc<ClientConfig>>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let addr = format!("{}:{}", connect_host, port);
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| Error::proxy(format!("Failed to connect to {}: {}", addr, e)))?;

    // Set up TLS for upstream connection (with ALPN for h2 negotiation)
    let client_config = match upstream_tls_config {
        Some(config) => config,
        None => {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            // Also load native/system root certificates (e.g. /etc/ssl/certs on Linux)
            let native = rustls_native_certs::load_native_certs();
            for error in &native.errors {
                tracing::warn!(error = %error, "Error loading native root certificates");
            }
            for cert in native.certs {
                let _ = root_store.add(cert);
            }
            let mut config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Arc::new(config)
        }
    };

    let connector = TlsConnector::from(client_config);

    let server_name = rustls::pki_types::ServerName::try_from(sni_host.to_string())
        .map_err(|e| Error::proxy(format!("Invalid server name '{}': {}", sni_host, e)))?;

    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::tls(format!("TLS connection to {} failed: {}", sni_host, e)))
}

/// Rebuild an incoming request for forwarding to the upstream server,
/// updating the Host header to match the target.
fn rebuild_request_for_upstream<B>(
    parts: hyper::http::request::Parts,
    body: B,
    host: &str,
    port: u16,
) -> Result<Request<B>> {
    // If the URI is path-only (e.g. "/" from an HTTP/1.1 client inside a CONNECT
    // tunnel), reconstruct the full absolute URI so that hyper's HTTP/2 client can
    // derive the :scheme and :authority pseudo-headers. Without this, h2 servers
    // reject the request with PROTOCOL_ERROR.
    let uri = if parts.uri.scheme().is_none() {
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let authority = if port == 443 {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        };
        hyper::Uri::builder()
            .scheme("https")
            .authority(authority)
            .path_and_query(path_and_query)
            .build()
            .map_err(|e| Error::proxy(format!("Failed to build URI: {}", e)))?
    } else {
        parts.uri
    };

    let host_value = if port == 443 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    };

    let mut builder = Request::builder().method(parts.method).uri(uri);

    for (name, value) in parts.headers.iter() {
        if name == hyper::header::HOST {
            builder = builder.header(name, &host_value);
        } else {
            builder = builder.header(name, value);
        }
    }

    builder
        .body(body)
        .map_err(|e| Error::proxy(format!("Failed to build request: {}", e)))
}

/// Forward a request with a BoxBody to the upstream server (supports h1 and h2 via ALPN).
async fn forward_request_boxed(
    mut req: Request<BoxBody<Bytes, hyper::Error>>,
    connect_host: String,
    port: u16,
    sni_host: String,
    upstream_tls_config: Option<Arc<ClientConfig>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    let tls_stream =
        connect_upstream_tls(&connect_host, port, &sni_host, upstream_tls_config).await?;

    // Check negotiated ALPN protocol
    let negotiated_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    tracing::debug!(host = %sni_host, h2 = negotiated_h2, "Upstream TLS handshake complete");

    let io = TokioIo::new(tls_stream);

    if negotiated_h2 {
        // HTTP/2 handshake
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| {
                Error::proxy(format!(
                    "{} {}: HTTP/2 handshake failed: {}",
                    method, uri, e
                ))
            })?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("HTTP/2 connection error: {}", e);
            }
        });

        // In HTTP/2, the :authority pseudo-header is derived from the URI.
        // Some servers (e.g. Google) reject requests that have both :authority
        // and a Host header, even when they match. Remove Host since it's redundant.
        req.headers_mut().remove(hyper::header::HOST);

        let resp = sender.send_request(req).await.map_err(|e| {
            Error::proxy(format!("{} {}: HTTP/2 request failed: {}", method, uri, e))
        })?;

        let (parts, body) = resp.into_parts();
        let body = body.map_err(|e| e).boxed();
        Ok(Response::from_parts(parts, body))
    } else {
        // HTTP/1.1 handshake
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| {
                Error::proxy(format!("{} {}: HTTP handshake failed: {}", method, uri, e))
            })?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("Connection error: {}", e);
            }
        });

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| Error::proxy(format!("{} {}: request failed: {}", method, uri, e)))?;

        let (parts, body) = resp.into_parts();
        let body = body.map_err(|e| e).boxed();
        Ok(Response::from_parts(parts, body))
    }
}

/// Forward a WebSocket upgrade request, then bidirectionally copy frames.
///
/// WebSocket always uses HTTP/1.1 (upgrade mechanism), so this bypasses
/// the h2 ALPN negotiation and forces an h1 connection with upgrades enabled.
async fn forward_websocket(
    mut req: Request<Incoming>,
    connect_host: String,
    port: u16,
    sni_host: String,
    upstream_tls_config: Option<Arc<ClientConfig>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let tls_stream =
        connect_upstream_tls(&connect_host, port, &sni_host, upstream_tls_config).await?;
    let io = TokioIo::new(tls_stream);

    let method = req.method().clone();
    let uri = req.uri().clone();

    // WebSocket requires HTTP/1.1 with upgrades
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| {
            Error::proxy(format!(
                "{} {}: WebSocket handshake failed: {}",
                method, uri, e
            ))
        })?;

    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!("Connection error: {}", e);
        }
    });

    // Extract the client-side upgrade future via &mut (doesn't consume the request)
    let client_on_upgrade = hyper::upgrade::on(&mut req);

    let (parts, body) = req.into_parts();
    let upstream_req = rebuild_request_for_upstream(parts, body, &sni_host, port)?;

    let mut resp = sender.send_request(upstream_req).await.map_err(|e| {
        Error::proxy(format!(
            "{} {}: WebSocket request failed: {}",
            method, uri, e
        ))
    })?;

    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (parts, body) = resp.into_parts();
        let body = body.map_err(|e| e).boxed();
        return Ok(Response::from_parts(parts, body));
    }

    // Extract the upstream upgrade future via &mut
    let upstream_on_upgrade = hyper::upgrade::on(&mut resp);

    // Build a 101 response to send back to the client, copying upgrade headers
    let mut client_resp = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (name, value) in resp.headers() {
        client_resp = client_resp.header(name, value);
    }

    let client_response = client_resp
        .body(
            Empty::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
        .map_err(|e| Error::proxy(format!("Failed to build 101 response: {}", e)))?;

    // Spawn a task to bridge the two upgraded connections
    tokio::spawn(async move {
        let (client_upgraded, upstream_upgraded) =
            match tokio::try_join!(client_on_upgrade, upstream_on_upgrade) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!("WebSocket upgrade failed: {}", e);
                    return;
                }
            };

        let mut client_io = TokioIo::new(client_upgraded);
        let mut upstream_io = TokioIo::new(upstream_upgraded);

        if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
            tracing::debug!("WebSocket bridge ended: {}", e);
        }
    });

    Ok(client_response)
}
