//! Main proxy server

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio_rustls::TlsAcceptor;

use super::handler::ProxyHandler;
use super::tunnel::TunnelHandler;
use crate::approvals::{self, ApprovalManager};
use crate::audit::AuditLogger;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::filter::dynamic_whitelist::DynamicWhitelist;
use crate::filter::{CredentialEngine, FilterEngine};
use crate::tls::{CertificateAuthority, MitmCertificateGenerator};
use std::time::Duration;

/// The address the proxy is listening on after bind().
pub enum ListenAddress {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl ListenAddress {
    /// Returns the TCP socket address, panicking if this is a Unix socket.
    /// Useful in tests that always bind to TCP.
    pub fn tcp_addr(&self) -> SocketAddr {
        match self {
            ListenAddress::Tcp(addr) => *addr,
            #[cfg(unix)]
            ListenAddress::Unix(path) => {
                panic!("expected TCP address, got Unix socket: {}", path.display())
            }
        }
    }
}

impl fmt::Display for ListenAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListenAddress::Tcp(addr) => write!(f, "{}", addr),
            #[cfg(unix)]
            ListenAddress::Unix(path) => write!(f, "{}", path.display()),
        }
    }
}

/// Internal enum wrapping the bound listener.
enum BoundListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

/// The main proxy server
pub struct ProxyServer {
    config: Config,
    filter_engine: Arc<FilterEngine>,
    credential_engine: Arc<CredentialEngine>,
    dynamic_whitelist: Arc<DynamicWhitelist>,
    mitm_generator: Arc<MitmCertificateGenerator>,
    resolved_auth: Option<(String, String)>,
    audit_logger: Option<Arc<AuditLogger>>,
    listener: Option<BoundListener>,
    /// Optional direct HTTPS listener (accepts raw TLS, uses SNI for routing).
    direct_https_listener: Option<BoundListener>,
    /// Optional direct HTTP listener (accepts plain HTTP, uses Host header for routing).
    direct_http_listener: Option<BoundListener>,
    /// Optional dashboard listener (plain HTTP, dedicated address for approvals UI).
    dashboard_listener: Option<BoundListener>,
    /// Approvals manager when the `[approvals]` config section is present.
    approvals: Option<Arc<ApprovalManager>>,
    /// Receiver for the approvals rebuild channel (consumed by `serve`).
    /// Paired with a sender attached to `ApprovalManager` at construction
    /// time so resolve signals don't race the serve loop's startup.
    approval_rebuild_rx: Option<tokio::sync::mpsc::Receiver<()>>,
    upstream_port_override: Option<u16>,
    upstream_host_override: Option<String>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
    /// Path to the config file for live-reload.
    config_path: Option<PathBuf>,
    /// Sender for the reload channel (kept alive so recv() blocks).
    reload_tx: Option<tokio::sync::mpsc::Sender<()>>,
    /// Receiver for the reload channel.
    reload_rx: Option<tokio::sync::mpsc::Receiver<()>>,
    /// Notified after each completed reload attempt (success or failure).
    reload_complete: Arc<tokio::sync::Notify>,
}

impl ProxyServer {
    /// Create a new proxy server from configuration
    pub fn new(config: Config) -> Result<Self> {
        // Load CA certificate
        let ca_cert = config
            .proxy
            .ca_cert
            .as_ref()
            .ok_or_else(|| Error::config("CA certificate path not specified"))?;
        let ca_key = config
            .proxy
            .ca_key
            .as_ref()
            .ok_or_else(|| Error::config("CA key path not specified"))?;

        let ca = CertificateAuthority::from_files(ca_cert, ca_key)?;
        let mitm_generator = Arc::new(MitmCertificateGenerator::new(ca));

        // Build filter engine
        let filter_engine = Arc::new(FilterEngine::new(config.rules.clone())?);

        // Build credential engine
        let credential_engine = Arc::new(CredentialEngine::new(config.credentials.clone())?);

        // Resolve auth credentials at startup (expands ${ENV_VAR})
        let resolved_auth = config.resolved_auth()?;

        tracing::info!(
            rules = filter_engine.rule_count(),
            credentials = credential_engine.credential_count(),
            auth = resolved_auth.is_some(),
            "Filter engine initialized"
        );

        let dynamic_whitelist = Arc::new(DynamicWhitelist::new(
            Duration::from_secs(config.proxy.redirect_whitelist_ttl_secs),
            1024,
        ));

        let approvals = config
            .approvals
            .as_ref()
            .map(|ac| ApprovalManager::new(ac.clone()));

        // Create the rebuild channel up front and attach the sender to the
        // manager. This avoids a race where an early resolve() signals
        // rebuild before serve()'s select loop is wired up, which would
        // silently drop the rebuild.
        let approval_rebuild_rx = if let Some(ref manager) = approvals {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            manager.attach_rebuild_tx(tx);
            Some(rx)
        } else {
            None
        };

        // Build the initial FilterEngine from base rules ++ approval rules
        // loaded from the sidecar. Replaces the earlier `filter_engine`
        // that used only config.rules.
        let filter_engine = if let Some(ref manager) = approvals {
            let mut combined = config.rules.clone();
            combined.extend(manager.active_rules());
            Arc::new(FilterEngine::new(combined)?)
        } else {
            filter_engine
        };

        Ok(Self {
            config,
            filter_engine,
            credential_engine,
            dynamic_whitelist,
            mitm_generator,
            resolved_auth,
            audit_logger: None,
            listener: None,
            direct_https_listener: None,
            direct_http_listener: None,
            dashboard_listener: None,
            approvals,
            approval_rebuild_rx,
            upstream_port_override: None,
            upstream_host_override: None,
            upstream_tls_config: None,
            config_path: None,
            reload_tx: None,
            reload_rx: None,
            reload_complete: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// Create a server with an existing filter engine and MITM generator
    pub fn with_components(
        config: Config,
        filter_engine: Arc<FilterEngine>,
        credential_engine: Arc<CredentialEngine>,
        mitm_generator: Arc<MitmCertificateGenerator>,
    ) -> Self {
        let dynamic_whitelist = Arc::new(DynamicWhitelist::new(
            Duration::from_secs(config.proxy.redirect_whitelist_ttl_secs),
            1024,
        ));
        let approvals = config
            .approvals
            .as_ref()
            .map(|ac| ApprovalManager::new(ac.clone()));
        Self {
            config,
            filter_engine,
            credential_engine,
            dynamic_whitelist,
            mitm_generator,
            resolved_auth: None,
            audit_logger: None,
            listener: None,
            direct_https_listener: None,
            direct_http_listener: None,
            dashboard_listener: None,
            approvals,
            approval_rebuild_rx: None,
            upstream_port_override: None,
            upstream_host_override: None,
            upstream_tls_config: None,
            config_path: None,
            reload_tx: None,
            reload_rx: None,
            reload_complete: Arc::new(tokio::sync::Notify::new()),
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

    /// Set the audit logger for structured request logging.
    pub fn with_audit_logger(mut self, logger: Arc<AuditLogger>) -> Self {
        self.audit_logger = Some(logger);
        self
    }

    /// Inject a custom TLS config for upstream connections (for testing with self-signed certs).
    pub fn with_upstream_tls(mut self, config: Arc<ClientConfig>) -> Self {
        self.upstream_tls_config = Some(config);
        self
    }

    /// Set the config file path for live-reload support.
    /// When set, the server watches the file for changes and reloads on modification.
    pub fn with_config_path(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// Get a sender that triggers a config reload when a message is sent.
    /// For testing: send `()` to trigger a reload, then await `reload_complete_notify()`.
    pub fn reload_trigger(&mut self) -> tokio::sync::mpsc::Sender<()> {
        if self.reload_tx.is_none() {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            self.reload_tx = Some(tx);
            self.reload_rx = Some(rx);
        }
        self.reload_tx.as_ref().unwrap().clone()
    }

    /// Get a Notify that is signaled after each reload attempt completes.
    pub fn reload_complete_notify(&self) -> Arc<tokio::sync::Notify> {
        self.reload_complete.clone()
    }

    /// Run the proxy server with graceful shutdown
    pub async fn run_until_shutdown(
        mut self,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<()> {
        let local_addr = self.bind().await?;
        tracing::info!(address = %local_addr, "Proxy server listening");

        // Bind direct HTTPS listener if configured
        if let Some(ref addr) = self.config.proxy.direct_https_bind.clone() {
            let direct_addr = self.bind_direct_https(addr).await?;
            tracing::info!(address = %direct_addr, "Direct HTTPS listener active");
        }

        // Bind direct HTTP listener if configured
        if let Some(ref addr) = self.config.proxy.direct_http_bind.clone() {
            let direct_addr = self.bind_direct_http(addr).await?;
            tracing::info!(address = %direct_addr, "Direct HTTP listener active");
        }

        // Bind dashboard listener if approvals are enabled
        if let Some(ref ac) = self.config.approvals.clone() {
            let dashboard_addr = self.bind_dashboard(&ac.dashboard_bind).await?;
            tracing::info!(address = %dashboard_addr, "Approvals dashboard listener active");
        }

        self.serve(shutdown).await
    }

    /// Bind the server to its configured address and return the listen address.
    ///
    /// For TCP, this is useful when binding to port 0 to discover the assigned port.
    /// For Unix sockets, the path from the config is returned.
    /// Call `serve()` afterwards to start accepting connections.
    pub async fn bind(&mut self) -> Result<ListenAddress> {
        let (listener, addr) = bind_listener(&self.config.proxy.bind_address).await?;
        self.listener = Some(listener);
        Ok(addr)
    }

    /// Bind the direct HTTPS listener to the given address.
    /// The address can be a TCP socket address or a Unix socket path (containing '/').
    pub async fn bind_direct_https(&mut self, bind_address: &str) -> Result<ListenAddress> {
        let (listener, addr) = bind_listener(bind_address).await?;
        self.direct_https_listener = Some(listener);
        Ok(addr)
    }

    /// Bind the direct HTTP listener to the given address.
    /// The address can be a TCP socket address or a Unix socket path (containing '/').
    pub async fn bind_direct_http(&mut self, bind_address: &str) -> Result<ListenAddress> {
        let (listener, addr) = bind_listener(bind_address).await?;
        self.direct_http_listener = Some(listener);
        Ok(addr)
    }

    /// Bind the approvals dashboard listener to the given address.
    /// The address can be a TCP socket address or a Unix socket path (containing '/').
    pub async fn bind_dashboard(&mut self, bind_address: &str) -> Result<ListenAddress> {
        let (listener, addr) = bind_listener(bind_address).await?;
        self.dashboard_listener = Some(listener);
        Ok(addr)
    }

    /// Serve connections using a previously bound listener, with graceful shutdown.
    ///
    /// Must call `bind()` first. Panics if no listener is stored.
    pub async fn serve(mut self, mut shutdown: tokio::sync::oneshot::Receiver<()>) -> Result<()> {
        let listener = self
            .listener
            .take()
            .expect("must call bind() before serve()");

        // Use a watch channel for the tunnel handler so both the proxy and
        // direct HTTPS listeners see reloaded configs.
        let (tunnel_handler_tx, tunnel_handler_rx) =
            tokio::sync::watch::channel(Arc::new(self.make_tunnel_handler()));

        // Spawn direct HTTPS listener if bound (shares the watch receiver)
        if let Some(direct_listener) = self.direct_https_listener.take() {
            let tls_config = self.mitm_generator.sni_server_config();
            let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
            spawn_direct_https_accept_loop(
                direct_listener,
                tls_acceptor,
                tunnel_handler_rx.clone(),
            );
        }

        // Spawn direct HTTP listener if bound (shares the watch receiver)
        if let Some(direct_listener) = self.direct_http_listener.take() {
            spawn_direct_http_accept_loop(direct_listener, tunnel_handler_rx.clone());
        }

        // Spawn dashboard listener if bound (independent of tunnel_handler; only
        // needs the approvals manager).
        if let Some(dashboard_listener) = self.dashboard_listener.take() {
            if let Some(ref manager) = self.approvals {
                spawn_dashboard_accept_loop(dashboard_listener, manager.clone());
            }
        }

        // Set up reload channel. We always create one so the select! branch blocks.
        // If an external trigger was set up via reload_trigger(), use that channel.
        // Otherwise create a fresh one.
        let (reload_tx, mut reload_rx) = if let Some(rx) = self.reload_rx.take() {
            (self.reload_tx.take().unwrap(), rx)
        } else {
            tokio::sync::mpsc::channel(1)
        };

        // Approvals rebuild channel: ApprovalManager sends `()` when the
        // active approval rules change. The sender was attached at
        // construction time (in `new`) so early resolves don't race the
        // serve loop's startup. If approvals are disabled, build a dummy
        // receiver so the select! arm stays `Pending` forever.
        let mut approval_rebuild_rx = match self.approval_rebuild_rx.take() {
            Some(rx) => rx,
            None => tokio::sync::mpsc::channel::<()>(1).1,
        };

        // Spawn file watcher and SIGHUP handler if config_path is set
        if let Some(ref config_path) = self.config_path {
            spawn_file_watcher(config_path.clone(), reload_tx.clone());
            #[cfg(unix)]
            spawn_sighup_handler(reload_tx.clone());
        }

        // Keep one sender alive so recv() blocks (never returns None)
        let _reload_tx_keepalive = reload_tx;

        match listener {
            BoundListener::Tcp(tcp_listener) => loop {
                tokio::select! {
                    _ = &mut shutdown => {
                        tracing::info!("Shutdown signal received");
                        return Ok(());
                    }
                    Some(()) = reload_rx.recv() => {
                        self.apply_reload(&tunnel_handler_tx);
                    }
                    Some(()) = approval_rebuild_rx.recv() => {
                        self.apply_approval_rebuild(&tunnel_handler_tx);
                    }
                    result = tcp_listener.accept() => {
                        let (stream, client_addr) = match result {
                            Ok(conn) => conn,
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to accept connection");
                                continue;
                            }
                        };

                        tracing::debug!(client = %client_addr, "New connection");
                        let handler = tunnel_handler_rx.borrow().clone();
                        self.spawn_connection(stream, client_addr.to_string(), &handler);
                    }
                }
            },
            #[cfg(unix)]
            BoundListener::Unix(unix_listener) => loop {
                tokio::select! {
                    _ = &mut shutdown => {
                        tracing::info!("Shutdown signal received");
                        return Ok(());
                    }
                    Some(()) = reload_rx.recv() => {
                        self.apply_reload(&tunnel_handler_tx);
                    }
                    Some(()) = approval_rebuild_rx.recv() => {
                        self.apply_approval_rebuild(&tunnel_handler_tx);
                    }
                    result = unix_listener.accept() => {
                        let (stream, _addr) = match result {
                            Ok(conn) => conn,
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to accept connection");
                                continue;
                            }
                        };

                        tracing::debug!(client = "unix", "New connection");
                        let handler = tunnel_handler_rx.borrow().clone();
                        self.spawn_connection(stream, "unix".to_string(), &handler);
                    }
                }
            },
        }
    }

    /// Apply a config reload from the config file on disk.
    fn apply_reload(&mut self, tunnel_handler_tx: &tokio::sync::watch::Sender<Arc<TunnelHandler>>) {
        let config_path = match &self.config_path {
            Some(p) => p.clone(),
            None => return,
        };

        // Read and parse config
        let new_config = match Config::from_file(&config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::error!(error = %e, "Config reload failed: invalid config file");
                self.reload_complete.notify_waiters();
                return;
            }
        };

        // Warn on non-reloadable field changes
        if new_config.proxy.bind_address != self.config.proxy.bind_address {
            tracing::warn!(
                old = %self.config.proxy.bind_address,
                new = %new_config.proxy.bind_address,
                "bind_address changed but requires restart to take effect"
            );
        }
        if new_config.proxy.ca_cert != self.config.proxy.ca_cert {
            tracing::warn!("ca_cert changed but requires restart to take effect");
        }
        if new_config.proxy.ca_key != self.config.proxy.ca_key {
            tracing::warn!("ca_key changed but requires restart to take effect");
        }
        if new_config.proxy.direct_https_bind != self.config.proxy.direct_https_bind {
            tracing::warn!("direct_https_bind changed but requires restart to take effect");
        }
        if new_config.proxy.direct_http_bind != self.config.proxy.direct_http_bind {
            tracing::warn!("direct_http_bind changed but requires restart to take effect");
        }

        // Compile new filter engine
        let new_filter = match FilterEngine::new(new_config.rules.clone()) {
            Ok(f) => Arc::new(f),
            Err(e) => {
                tracing::error!(error = %e, "Config reload failed: rule compilation error");
                self.reload_complete.notify_waiters();
                return;
            }
        };

        // Compile new credential engine
        let new_creds = match CredentialEngine::new(new_config.credentials.clone()) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::error!(error = %e, "Config reload failed: credential compilation error");
                self.reload_complete.notify_waiters();
                return;
            }
        };

        // Re-resolve auth credentials
        let new_auth = match new_config.resolved_auth() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(error = %e, "Config reload failed: auth resolution error");
                self.reload_complete.notify_waiters();
                return;
            }
        };

        // Update audit logger if path changed
        if new_config.logging.audit_log != self.config.logging.audit_log {
            match &new_config.logging.audit_log {
                Some(path) => match AuditLogger::open(path) {
                    Ok(logger) => {
                        tracing::info!(path = %path, "Audit log path updated");
                        self.audit_logger = Some(Arc::new(logger));
                    }
                    Err(e) => {
                        tracing::error!(error = %e, path = %path, "Config reload failed: cannot open audit log");
                        self.reload_complete.notify_waiters();
                        return;
                    }
                },
                None => {
                    if self.audit_logger.is_some() {
                        tracing::info!("Audit log disabled by reload");
                    }
                    self.audit_logger = None;
                }
            }
        }

        // Apply all changes
        self.filter_engine = new_filter;
        self.credential_engine = new_creds;
        self.resolved_auth = new_auth;
        self.config = new_config;

        // Broadcast new tunnel handler to all listeners (proxy + direct HTTPS)
        let _ = tunnel_handler_tx.send(Arc::new(self.make_tunnel_handler()));

        tracing::info!(
            rules = self.filter_engine.rule_count(),
            credentials = self.credential_engine.credential_count(),
            "Config reloaded successfully"
        );

        self.reload_complete.notify_waiters();
    }

    /// Spawn a task to handle a single connection.
    fn spawn_connection<S>(
        &self,
        stream: S,
        client_addr: String,
        tunnel_handler: &Arc<TunnelHandler>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let tunnel_handler = tunnel_handler.clone();
        let filter_engine = self.filter_engine.clone();
        let dynamic_whitelist = self.dynamic_whitelist.clone();
        let auth = self.resolved_auth.clone();
        let log_allowed = self.config.logging.log_allowed_requests;
        let log_blocked = self.config.logging.log_blocked_requests;
        let audit_logger = self.audit_logger.clone();
        let permissive = self.config.proxy.permissive;
        let max_body_log_size = self.config.logging.max_body_log_size;

        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let service = service_fn(move |req| {
                let handler = ProxyHandler::new(
                    tunnel_handler.clone(),
                    filter_engine.clone(),
                    dynamic_whitelist.clone(),
                )
                .with_request_logging(log_allowed, log_blocked)
                .with_auth(auth.clone())
                .with_audit_logger(audit_logger.clone())
                .with_permissive(permissive)
                .with_max_body_log_size(max_body_log_size);
                async move { handler.handle(req).await }
            });

            if let Err(e) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                if !e.to_string().contains("connection closed") {
                    tracing::debug!(client = %client_addr, error = %e, "Connection error");
                }
            }
        });
    }

    /// Rebuild the effective FilterEngine from `config.rules ++ active_approval_rules`
    /// and broadcast a new TunnelHandler. Called when an approval is granted
    /// or expires. No-op if approvals are disabled (shouldn't happen — the
    /// channel would never fire).
    fn apply_approval_rebuild(
        &mut self,
        tunnel_handler_tx: &tokio::sync::watch::Sender<Arc<TunnelHandler>>,
    ) {
        let Some(ref manager) = self.approvals else {
            return;
        };

        let mut combined = self.config.rules.clone();
        combined.extend(manager.active_rules());

        let new_filter = match FilterEngine::new(combined) {
            Ok(f) => Arc::new(f),
            Err(e) => {
                tracing::error!(error = %e, "approval rebuild failed: rule compilation error");
                return;
            }
        };

        self.filter_engine = new_filter;
        let _ = tunnel_handler_tx.send(Arc::new(self.make_tunnel_handler()));
        tracing::info!(
            rules = self.filter_engine.rule_count(),
            "Approval rebuild applied"
        );
    }

    fn make_tunnel_handler(&self) -> TunnelHandler {
        let mut handler = TunnelHandler::new(
            self.mitm_generator.clone(),
            self.filter_engine.clone(),
            self.credential_engine.clone(),
            self.dynamic_whitelist.clone(),
        )
        .with_request_logging(
            self.config.logging.log_allowed_requests,
            self.config.logging.log_blocked_requests,
        )
        .with_permissive(self.config.proxy.permissive)
        .with_max_body_log_size(self.config.logging.max_body_log_size);
        if let Some(port) = self.upstream_port_override {
            handler = handler.with_upstream_port_override(port);
        }
        if let Some(ref host) = self.upstream_host_override {
            handler = handler.with_upstream_host_override(host.clone());
        }
        if let Some(ref config) = self.upstream_tls_config {
            handler = handler.with_upstream_tls(config.clone());
        }
        if let Some(ref logger) = self.audit_logger {
            handler = handler.with_audit_logger(logger.clone());
        }
        if let Some(ref approvals) = self.approvals {
            handler = handler.with_approvals(approvals.clone());
        }
        handler
    }

    /// Accessor for tests that need to poke at the approvals manager directly.
    pub fn approvals_manager(&self) -> Option<&Arc<ApprovalManager>> {
        self.approvals.as_ref()
    }

    /// Get the bind address
    pub fn bind_address(&self) -> &str {
        &self.config.proxy.bind_address
    }

    /// Get the filter engine
    pub fn filter_engine(&self) -> &Arc<FilterEngine> {
        &self.filter_engine
    }

    /// Get the MITM generator
    pub fn mitm_generator(&self) -> &Arc<MitmCertificateGenerator> {
        &self.mitm_generator
    }
}

/// Bind a listener to a TCP address or Unix socket path.
/// Returns the bound listener and the address it's listening on.
async fn bind_listener(bind_address: &str) -> Result<(BoundListener, ListenAddress)> {
    #[cfg(unix)]
    if bind_address.contains('/') {
        let path = PathBuf::from(bind_address);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                Error::proxy(format!(
                    "Failed to remove stale socket '{}': {}",
                    path.display(),
                    e
                ))
            })?;
        }
        let listener = UnixListener::bind(&path)
            .map_err(|e| Error::proxy(format!("Failed to bind to {}: {}", path.display(), e)))?;
        return Ok((BoundListener::Unix(listener), ListenAddress::Unix(path)));
    }

    let addr: SocketAddr = bind_address
        .parse()
        .map_err(|e| Error::config(format!("Invalid bind address '{}': {}", bind_address, e)))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| Error::proxy(format!("Failed to bind to {}: {}", addr, e)))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| Error::proxy(format!("Failed to get local address: {}", e)))?;
    Ok((BoundListener::Tcp(listener), ListenAddress::Tcp(local_addr)))
}

/// Spawn the direct HTTPS accept loop as a background task.
///
/// Reads the current `TunnelHandler` from the watch receiver for each new
/// connection, so config reloads take effect. The task exits when the watch
/// sender is dropped (server shutdown).
fn spawn_direct_https_accept_loop(
    listener: BoundListener,
    tls_acceptor: TlsAcceptor,
    tunnel_handler_rx: tokio::sync::watch::Receiver<Arc<TunnelHandler>>,
) {
    match listener {
        BoundListener::Tcp(tcp_listener) => {
            tokio::spawn(accept_loop_direct_https(
                tcp_listener,
                tls_acceptor,
                tunnel_handler_rx,
            ));
        }
        #[cfg(unix)]
        BoundListener::Unix(unix_listener) => {
            tokio::spawn(accept_loop_direct_https(
                unix_listener,
                tls_acceptor,
                tunnel_handler_rx,
            ));
        }
    }
}

/// Generic accept loop for the direct HTTPS listener (works for both TCP and Unix).
async fn accept_loop_direct_https<L>(
    listener: L,
    tls_acceptor: TlsAcceptor,
    tunnel_handler_rx: tokio::sync::watch::Receiver<Arc<TunnelHandler>>,
) where
    L: DirectAccept,
{
    loop {
        let (stream, client_addr) = match listener.accept_conn().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "Direct HTTPS: failed to accept connection");
                continue;
            }
        };
        tracing::debug!(client = %client_addr, "Direct HTTPS: new connection");
        let handler = tunnel_handler_rx.borrow().clone();
        spawn_direct_https_connection(stream, client_addr, tls_acceptor.clone(), handler);
    }
}

/// Trait abstracting over TCP and Unix listeners for the accept loop.
trait DirectAccept {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn accept_conn(
        &self,
    ) -> impl std::future::Future<Output = std::io::Result<(Self::Stream, String)>> + Send;
}

impl DirectAccept for TcpListener {
    type Stream = tokio::net::TcpStream;
    async fn accept_conn(&self) -> std::io::Result<(Self::Stream, String)> {
        let (stream, addr) = self.accept().await?;
        Ok((stream, addr.to_string()))
    }
}

#[cfg(unix)]
impl DirectAccept for UnixListener {
    type Stream = tokio::net::UnixStream;
    async fn accept_conn(&self) -> std::io::Result<(Self::Stream, String)> {
        let (stream, _addr) = self.accept().await?;
        Ok((stream, "unix".to_string()))
    }
}

/// Spawn the direct HTTP accept loop as a background task.
fn spawn_direct_http_accept_loop(
    listener: BoundListener,
    tunnel_handler_rx: tokio::sync::watch::Receiver<Arc<TunnelHandler>>,
) {
    match listener {
        BoundListener::Tcp(tcp_listener) => {
            tokio::spawn(accept_loop_direct_http(tcp_listener, tunnel_handler_rx));
        }
        #[cfg(unix)]
        BoundListener::Unix(unix_listener) => {
            tokio::spawn(accept_loop_direct_http(unix_listener, tunnel_handler_rx));
        }
    }
}

/// Generic accept loop for the direct HTTP listener (works for both TCP and Unix).
async fn accept_loop_direct_http<L>(
    listener: L,
    tunnel_handler_rx: tokio::sync::watch::Receiver<Arc<TunnelHandler>>,
) where
    L: DirectAccept,
{
    loop {
        let (stream, client_addr) = match listener.accept_conn().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "Direct HTTP: failed to accept connection");
                continue;
            }
        };
        tracing::debug!(client = %client_addr, "Direct HTTP: new connection");
        let handler = tunnel_handler_rx.borrow().clone();
        tokio::spawn(async move {
            handler.serve_direct_http(stream).await;
        });
    }
}

/// Spawn a task to handle a single direct HTTPS connection.
///
/// Performs TLS accept (using SNI-based cert resolution), then serves HTTP requests
/// over the TLS stream using `TunnelHandler::serve_tls_http`.
fn spawn_direct_https_connection<S>(
    stream: S,
    client_addr: String,
    tls_acceptor: TlsAcceptor,
    tunnel_handler: Arc<TunnelHandler>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let tls_stream = match tls_acceptor.accept(stream).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(client = %client_addr, error = %e, "Direct HTTPS: TLS handshake failed");
                return;
            }
        };

        let (_, server_conn) = tls_stream.get_ref();
        let hostname = match server_conn.server_name() {
            Some(name) => name.to_string(),
            None => {
                tracing::warn!(client = %client_addr, "Direct HTTPS: no SNI hostname");
                return;
            }
        };

        tracing::debug!(client = %client_addr, host = %hostname, "Direct HTTPS: TLS handshake complete");
        tunnel_handler
            .serve_tls_http(tls_stream, &hostname, 443)
            .await;
    });
}

/// Spawn a background thread that watches a config file for changes and sends
/// reload triggers with 200ms debouncing.
fn spawn_file_watcher(config_path: PathBuf, reload_tx: tokio::sync::mpsc::Sender<()>) {
    std::thread::spawn(move || {
        use notify::{EventKind, RecursiveMode, Watcher};

        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match notify::recommended_watcher(tx) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create config file watcher");
                return;
            }
        };

        // Watch parent directory to catch editor save patterns (write-to-tmp + rename)
        let watch_dir = config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            tracing::error!(
                error = %e,
                path = %watch_dir.display(),
                "Failed to watch config directory"
            );
            return;
        }

        tracing::debug!(path = %config_path.display(), "Watching config file for changes");

        let config_filename = config_path.file_name().map(|f| f.to_owned());

        loop {
            match rx.recv() {
                Ok(Ok(event)) => {
                    // Only care about creates and modifications
                    if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                        continue;
                    }

                    // Check if the event is for our config file
                    let is_our_file = event
                        .paths
                        .iter()
                        .any(|p| p.file_name() == config_filename.as_deref());
                    if !is_our_file {
                        continue;
                    }

                    // Debounce: drain events for 200ms after detecting a change
                    let debounce = std::time::Duration::from_millis(200);
                    while rx.recv_timeout(debounce).is_ok() {}

                    tracing::debug!("Config file change detected, triggering reload");
                    if reload_tx.blocking_send(()).is_err() {
                        break; // server shut down
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "Config file watcher error");
                }
                Err(_) => break, // watcher dropped
            }
        }
    });
}

/// Spawn a SIGHUP handler that triggers config reloads.
#[cfg(unix)]
fn spawn_sighup_handler(reload_tx: tokio::sync::mpsc::Sender<()>) {
    tokio::spawn(async move {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .expect("failed to install SIGHUP handler");
        loop {
            signal.recv().await;
            tracing::info!("Received SIGHUP, triggering config reload");
            if reload_tx.send(()).await.is_err() {
                break;
            }
        }
    });
}

/// Spawn the dashboard accept loop. Each accepted connection serves the
/// approvals dashboard (plain HTTP, no MITM, no proxy semantics).
fn spawn_dashboard_accept_loop(listener: BoundListener, manager: Arc<ApprovalManager>) {
    match listener {
        BoundListener::Tcp(tcp_listener) => {
            tokio::spawn(accept_loop_dashboard(tcp_listener, manager));
        }
        #[cfg(unix)]
        BoundListener::Unix(unix_listener) => {
            tokio::spawn(accept_loop_dashboard(unix_listener, manager));
        }
    }
}

async fn accept_loop_dashboard<L>(listener: L, manager: Arc<ApprovalManager>)
where
    L: DirectAccept,
{
    loop {
        let (stream, client_addr) = match listener.accept_conn().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "Dashboard: failed to accept connection");
                continue;
            }
        };
        tracing::debug!(client = %client_addr, "Dashboard: new connection");
        let manager = manager.clone();
        tokio::spawn(async move {
            approvals::dashboard::serve_connection(manager, stream).await;
        });
    }
}
