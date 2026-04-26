//! Test infrastructure for e2e proxy tests.
// Each integration test is a separate crate, so not every test uses every item here.
#![allow(dead_code)]

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use pyloros::tls::{CertificateAuthority, GeneratedCa};
use pyloros::{Config, ProxyServer};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ServerConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// Re-export TestReport from the shared crate so existing test_report! macro works
pub use pyloros_test_support::TestReport;

/// Auto-detect the test name from the calling function.
/// Must be called from the test function body (not a helper).
#[macro_export]
macro_rules! test_report {
    ($title:expr) => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        // Strip "::f" suffix
        let name = &name[..name.len() - 3];
        // In async fns, the path ends with "::{{closure}}" — strip that too
        let name = name.strip_suffix("::{{closure}}").unwrap_or(name);
        $crate::common::TestReport::new(name, $title, file!(), line!())
    }};
}

// ---------------------------------------------------------------------------
// ReportingClient — HTTP client that auto-logs actions to TestReport
// ---------------------------------------------------------------------------

pub struct ReportingClient<'a> {
    inner: reqwest::Client,
    report: &'a TestReport,
}

impl<'a> ReportingClient<'a> {
    pub fn new(report: &'a TestReport, proxy_addr: SocketAddr, ca: &TestCa) -> Self {
        Self {
            inner: test_client(proxy_addr, ca),
            report,
        }
    }

    pub fn new_h1_only(report: &'a TestReport, proxy_addr: SocketAddr, ca: &TestCa) -> Self {
        Self {
            inner: test_client_h1_only(proxy_addr, ca),
            report,
        }
    }

    pub async fn get(&self, url: &str) -> reqwest::Response {
        self.report.action(format!("GET `{}`", url));
        self.inner.get(url).send().await.unwrap()
    }

    pub fn new_with_proxy_auth(
        report: &'a TestReport,
        proxy_addr: SocketAddr,
        ca: &TestCa,
        username: &str,
        password: &str,
    ) -> Self {
        let proxy_url = format!("http://{}:{}@{}", username, password, proxy_addr);
        let proxy = reqwest::Proxy::all(&proxy_url).unwrap();
        let ca_cert = reqwest::tls::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .add_root_certificate(ca_cert)
            .build()
            .unwrap();
        Self {
            inner: client,
            report,
        }
    }

    pub fn new_plain(report: &'a TestReport, proxy_addr: SocketAddr) -> Self {
        let proxy_url = format!("http://{}", proxy_addr);
        let proxy = reqwest::Proxy::all(&proxy_url).unwrap();
        let client = reqwest::Client::builder().proxy(proxy).build().unwrap();
        Self {
            inner: client,
            report,
        }
    }

    pub fn new_plain_no_follow(report: &'a TestReport, proxy_addr: SocketAddr) -> Self {
        let proxy_url = format!("http://{}", proxy_addr);
        let proxy = reqwest::Proxy::all(&proxy_url).unwrap();
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self {
            inner: client,
            report,
        }
    }

    pub fn new_plain_with_proxy_auth(
        report: &'a TestReport,
        proxy_addr: SocketAddr,
        username: &str,
        password: &str,
    ) -> Self {
        let proxy_url = format!("http://{}:{}@{}", username, password, proxy_addr);
        let proxy = reqwest::Proxy::all(&proxy_url).unwrap();
        let client = reqwest::Client::builder().proxy(proxy).build().unwrap();
        Self {
            inner: client,
            report,
        }
    }

    pub async fn post(&self, url: &str) -> reqwest::Response {
        self.report.action(format!("POST `{}`", url));
        self.inner.post(url).send().await.unwrap()
    }

    pub async fn post_with_body(
        &self,
        url: &str,
        body: impl Into<reqwest::Body>,
    ) -> reqwest::Response {
        self.report.action(format!("POST `{}` (with body)", url));
        self.inner.post(url).body(body).send().await.unwrap()
    }

    pub async fn get_with_headers(&self, url: &str, headers: &[(&str, &str)]) -> reqwest::Response {
        let header_desc = headers
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<_>>()
            .join(", ");
        self.report
            .action(format!("GET `{}` [{}]", url, header_desc));
        let mut req = self.inner.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.send().await.unwrap()
    }

    pub async fn request(&self, method: reqwest::Method, url: &str) -> reqwest::Response {
        self.report.action(format!("{} `{}`", method, url));
        self.inner
            .request(method, url.parse::<reqwest::Url>().unwrap())
            .send()
            .await
            .unwrap()
    }

    pub async fn get_with_header(&self, url: &str, key: &str, val: &str) -> reqwest::Response {
        self.report
            .action(format!("GET `{}` [{}:{}]", url, key, val));
        self.inner.get(url).header(key, val).send().await.unwrap()
    }

    /// Access the raw inner client for cases where wrappers don't suffice.
    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }

    /// Access the report for manual step recording.
    pub fn report(&self) -> &'a TestReport {
        self.report
    }
}

// ---------------------------------------------------------------------------
// TestCa
// ---------------------------------------------------------------------------

/// A test CA that generates certs and saves them to a tempdir.
pub struct TestCa {
    pub ca: CertificateAuthority,
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: CertificateDer<'static>,
    pub dir: TempDir,
    pub cert_path: String,
    pub key_path: String,
}

impl TestCa {
    pub fn generate() -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let generated = GeneratedCa::generate().unwrap();
        let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
        let cert_der = ca.cert_der().clone();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("ca.crt");
        let key_path = dir.path().join("ca.key");
        generated.save(&cert_path, &key_path).unwrap();

        Self {
            ca,
            cert_pem: generated.cert_pem,
            key_pem: generated.key_pem,
            cert_der,
            cert_path: cert_path.to_str().unwrap().to_string(),
            key_path: key_path.to_str().unwrap().to_string(),
            dir,
        }
    }

    /// Build a rustls ClientConfig that trusts this CA (with h2 + h1 ALPN).
    pub fn client_tls_config(&self) -> Arc<ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(self.cert_der.clone()).unwrap();
        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Build a rustls ServerConfig for a given hostname signed by this CA (with h2 + h1 ALPN).
    pub fn server_tls_config(&self, hostname: &str) -> Arc<ServerConfig> {
        let (cert, key) = self.ca.generate_cert_for_host(hostname).unwrap();
        let cert_chain = vec![cert, self.cert_der.clone()];
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Build a rustls ServerConfig that only advertises HTTP/1.1 ALPN.
    pub fn server_tls_config_h1_only(&self, hostname: &str) -> Arc<ServerConfig> {
        let (cert, key) = self.ca.generate_cert_for_host(hostname).unwrap();
        let cert_chain = vec![cert, self.cert_der.clone()];
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

// ---------------------------------------------------------------------------
// TestUpstream — a tiny HTTPS server
// ---------------------------------------------------------------------------

/// A handler function for the test upstream.
pub type UpstreamHandler =
    Arc<dyn Fn(Request<Incoming>) -> UpstreamResponse + Send + Sync + 'static>;

pub type UpstreamResponse = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>,
            > + Send,
    >,
>;

/// A test HTTPS upstream server.
pub struct TestUpstream {
    pub addr: SocketAddr,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl TestUpstream {
    async fn start_with_config(server_config: Arc<ServerConfig>, handler: UpstreamHandler) -> Self {
        let h1_only = !server_config.alpn_protocols.iter().any(|p| p == b"h2");
        let acceptor = TlsAcceptor::from(server_config);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    result = listener.accept() => {
                        let (stream, _) = match result {
                            Ok(conn) => conn,
                            Err(_) => continue,
                        };

                        let acceptor = acceptor.clone();
                        let handler = handler.clone();

                        tokio::spawn(async move {
                            let tls_stream = match acceptor.accept(stream).await {
                                Ok(s) => s,
                                Err(_) => return,
                            };
                            let io = TokioIo::new(tls_stream);

                            let service = service_fn(move |req: Request<Incoming>| {
                                let handler = handler.clone();
                                handler(req)
                            });

                            if h1_only {
                                let _ = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .with_upgrades()
                                    .await;
                            } else {
                                let _ = auto::Builder::new(TokioExecutor::new())
                                    .serve_connection_with_upgrades(io, service)
                                    .await;
                            }
                        });
                    }
                }
            }
        });

        Self { addr, shutdown_tx }
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Create a builder for configuring a test upstream.
    pub fn builder(ca: &TestCa, handler: UpstreamHandler) -> TestUpstreamBuilder<'_> {
        TestUpstreamBuilder {
            ca,
            handler,
            hostname: "localhost",
            h1_only: false,
            report: None,
        }
    }
}

pub struct TestUpstreamBuilder<'a> {
    ca: &'a TestCa,
    handler: UpstreamHandler,
    hostname: &'a str,
    h1_only: bool,
    report: Option<(&'a TestReport, String)>,
}

impl<'a> TestUpstreamBuilder<'a> {
    pub fn hostname(mut self, hostname: &'a str) -> Self {
        self.hostname = hostname;
        self
    }

    pub fn h1_only(mut self) -> Self {
        self.h1_only = true;
        self
    }

    pub fn report(mut self, report: &'a TestReport, desc: impl Into<String>) -> Self {
        self.report = Some((report, desc.into()));
        self
    }

    pub async fn start(self) -> TestUpstream {
        if let Some((report, desc)) = &self.report {
            if self.h1_only {
                report.setup(format!("Upstream (h1 only): {}", desc));
            } else if self.hostname != "localhost" {
                report.setup(format!("Upstream ({}): {}", self.hostname, desc));
            } else {
                report.setup(format!("Upstream: {}", desc));
            }
        }

        let server_config = if self.h1_only {
            self.ca.server_tls_config_h1_only(self.hostname)
        } else {
            self.ca.server_tls_config(self.hostname)
        };
        TestUpstream::start_with_config(server_config, self.handler).await
    }
}

/// A simple upstream handler that returns 200 with a text body.
pub fn ok_handler(body: &'static str) -> UpstreamHandler {
    Arc::new(move |_req| {
        Box::pin(async move {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                .unwrap())
        })
    })
}

/// An upstream handler that echoes request details back.
pub fn echo_handler() -> UpstreamHandler {
    Arc::new(|req: Request<Incoming>| {
        Box::pin(async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();

            // Collect interesting headers
            let mut header_lines = Vec::new();
            for (name, value) in req.headers().iter() {
                header_lines.push(format!("{}: {}", name, value.to_str().unwrap_or("?")));
            }

            let body = format!(
                "method={}\npath={}\n{}\n",
                method,
                path,
                header_lines.join("\n")
            );

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .header("X-Echo", "true")
                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                .unwrap())
        })
    })
}

// ---------------------------------------------------------------------------
// TestProxy — wraps ProxyServer with bind + spawn
// ---------------------------------------------------------------------------

pub struct TestProxy {
    pub addr: SocketAddr,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl TestProxy {
    async fn start_from_builder(builder: &TestProxyBuilder<'_>) -> Self {
        let mut config = Config::minimal(
            "127.0.0.1:0".to_string(),
            builder.ca.cert_path.clone(),
            builder.ca.key_path.clone(),
        );
        config.rules = builder.rules.clone();
        config.credentials = builder.credentials.clone();
        config.proxy.permissive = builder.permissive;
        if let Some(ttl) = builder.redirect_whitelist_ttl_secs {
            config.proxy.redirect_whitelist_ttl_secs = ttl;
        }
        if let Some((ref username, ref password)) = builder.auth {
            config.proxy.auth_username = Some(username.clone());
            config.proxy.auth_password = Some(password.clone());
        }
        config.logging.log_allowed_requests = false;
        config.logging.log_blocked_requests = false;
        if let Some(size) = builder.max_body_log_size {
            config.logging.max_body_log_size = size;
        }

        let client_tls = builder.ca.client_tls_config();

        let mut server = ProxyServer::new(config).unwrap();
        server = server
            .with_upstream_port_override(builder.upstream_port)
            .with_upstream_tls(client_tls);
        if let Some(ref host) = builder.upstream_host {
            server = server.with_upstream_host_override(host.clone());
        }
        if let Some(ref path) = builder.audit_log {
            let logger = pyloros::AuditLogger::open(path).unwrap();
            server = server.with_audit_logger(Arc::new(logger));
        }

        let addr = server.bind().await.unwrap().tcp_addr();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let _ = server.serve(shutdown_rx).await;
        });

        Self { addr, shutdown_tx }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Create a builder for configuring a test proxy.
    pub fn builder(
        ca: &TestCa,
        rules: Vec<pyloros::config::Rule>,
        upstream_port: u16,
    ) -> TestProxyBuilder<'_> {
        TestProxyBuilder {
            ca,
            rules,
            upstream_port,
            credentials: Vec::new(),
            upstream_host: None,
            auth: None,
            audit_log: None,
            permissive: false,
            redirect_whitelist_ttl_secs: None,
            max_body_log_size: None,
            report: None,
        }
    }
}

pub struct TestProxyBuilder<'a> {
    ca: &'a TestCa,
    rules: Vec<pyloros::config::Rule>,
    upstream_port: u16,
    credentials: Vec<pyloros::config::Credential>,
    upstream_host: Option<String>,
    auth: Option<(String, String)>,
    audit_log: Option<String>,
    permissive: bool,
    redirect_whitelist_ttl_secs: Option<u64>,
    max_body_log_size: Option<usize>,
    report: Option<&'a TestReport>,
}

impl<'a> TestProxyBuilder<'a> {
    pub fn credentials(mut self, credentials: Vec<pyloros::config::Credential>) -> Self {
        self.credentials = credentials;
        self
    }

    pub fn upstream_host(mut self, host: &str) -> Self {
        self.upstream_host = Some(host.to_string());
        self
    }

    pub fn auth(mut self, username: &str, password: &str) -> Self {
        self.auth = Some((username.to_string(), password.to_string()));
        self
    }

    pub fn audit_log(mut self, path: &str) -> Self {
        self.audit_log = Some(path.to_string());
        self
    }

    pub fn permissive(mut self, enabled: bool) -> Self {
        self.permissive = enabled;
        self
    }

    pub fn redirect_whitelist_ttl_secs(mut self, secs: u64) -> Self {
        self.redirect_whitelist_ttl_secs = Some(secs);
        self
    }

    pub fn max_body_log_size(mut self, size: usize) -> Self {
        self.max_body_log_size = Some(size);
        self
    }

    pub fn report(mut self, report: &'a TestReport) -> Self {
        self.report = Some(report);
        self
    }

    pub async fn start(self) -> TestProxy {
        if let Some(report) = self.report {
            let desc = self
                .rules
                .iter()
                .map(|r| {
                    if let Some(ref git) = r.git {
                        let branches_desc = r
                            .branches
                            .as_ref()
                            .map(|b| format!(" branches={:?}", b))
                            .unwrap_or_default();
                        format!("`git={} {}`{}", git, r.url, branches_desc)
                    } else {
                        format!(
                            "`{} {}`{}",
                            r.method.as_deref().unwrap_or("?"),
                            r.url,
                            if r.websocket { " [ws]" } else { "" }
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            if let Some(ref host) = self.upstream_host {
                report.setup(format!(
                    "Proxy with rules: [{}] (host override: {})",
                    desc, host
                ));
            } else {
                report.setup(format!("Proxy with rules: [{}]", desc));
            }
        }

        TestProxy::start_from_builder(&self).await
    }
}

// ---------------------------------------------------------------------------
// test_client — reqwest client that uses the proxy and trusts the test CA
// ---------------------------------------------------------------------------

/// Build a reqwest client that routes through the given proxy and trusts the test CA.
/// By default reqwest negotiates h2 when available.
pub fn test_client(proxy_addr: SocketAddr, ca: &TestCa) -> reqwest::Client {
    let proxy_url = format!("http://{}", proxy_addr);
    let proxy = reqwest::Proxy::all(&proxy_url).unwrap();

    let ca_cert = reqwest::tls::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap();

    reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(ca_cert)
        .build()
        .unwrap()
}

/// Build a reqwest client that forces HTTP/1.1 only (no h2 negotiation).
pub fn test_client_h1_only(proxy_addr: SocketAddr, ca: &TestCa) -> reqwest::Client {
    let proxy_url = format!("http://{}", proxy_addr);
    let proxy = reqwest::Proxy::all(&proxy_url).unwrap();

    let ca_cert = reqwest::tls::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap();

    reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(ca_cert)
        .http1_only()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------
// LogCapture — capture tracing output for assertions
// ---------------------------------------------------------------------------

/// Captures tracing output into a shared buffer for test assertions.
///
/// Installs a thread-local default subscriber that writes to an in-memory buffer.
/// In single-threaded tokio (`#[tokio::test]`), spawned tasks run on the same
/// thread and therefore also write to this buffer.
pub struct LogCapture {
    buf: Arc<std::sync::Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

struct BufWriter(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    pub fn new() -> Self {
        let buf = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer_buf = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || BufWriter(writer_buf.clone()))
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        Self { buf, _guard: guard }
    }

    pub fn contains(&self, text: &str) -> bool {
        let bytes = self.buf.lock().unwrap();
        let output = String::from_utf8_lossy(&bytes);
        output.contains(text)
    }
}

// ---------------------------------------------------------------------------
// run_command_reported — generic reported subprocess invocation
// ---------------------------------------------------------------------------

/// Shell-escape an argument for display in report action lines.
/// Quotes the arg if it contains whitespace or special chars, and escapes control characters.
fn shell_escape_arg(arg: &str) -> String {
    let needs_quoting = arg.is_empty()
        || arg
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\'');
    if !needs_quoting {
        return arg.to_string();
    }
    // Escape control characters and double quotes, then wrap in double quotes
    let mut escaped = String::with_capacity(arg.len() + 2);
    escaped.push('"');
    for c in arg.chars() {
        match c {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            c if c.is_control() => escaped.push_str(&format!("\\x{:02x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

/// Run a subprocess and report it as a test action.
/// The action description is auto-generated from the command program name and arguments.
pub fn run_command_reported(
    t: &TestReport,
    cmd: &mut std::process::Command,
) -> std::process::Output {
    let program = std::path::Path::new(cmd.get_program())
        .file_name()
        .unwrap_or(cmd.get_program().as_ref())
        .to_string_lossy()
        .into_owned();
    let args: Vec<_> = cmd
        .get_args()
        .map(|a| shell_escape_arg(&a.to_string_lossy()))
        .collect();
    let desc = if args.is_empty() {
        format!("Run `{}`", program)
    } else {
        format!("Run `{} {}`", program, args.join(" "))
    };
    t.action(desc);
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {}", program, e));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.is_empty() {
        t.output("stdout", &stdout);
    }
    if !stderr.is_empty() {
        t.output("stderr", &stderr);
    }
    output
}

// ---------------------------------------------------------------------------
// Rule helpers
// ---------------------------------------------------------------------------

pub fn rule(method: &str, url: &str) -> pyloros::config::Rule {
    pyloros::config::Rule {
        method: Some(method.to_string()),
        url: url.to_string(),
        websocket: false,
        git: None,
        branches: None,
        allow_redirects: Vec::new(),
        log_body: false,
        protected_branches: None,
    }
}

pub fn rule_with_redirects(method: &str, url: &str, redirects: &[&str]) -> pyloros::config::Rule {
    pyloros::config::Rule {
        method: Some(method.to_string()),
        url: url.to_string(),
        websocket: false,
        git: None,
        branches: None,
        allow_redirects: redirects.iter().map(|s| s.to_string()).collect(),
        log_body: false,
        protected_branches: None,
    }
}

pub fn rule_with_body_log(method: &str, url: &str) -> pyloros::config::Rule {
    pyloros::config::Rule {
        method: Some(method.to_string()),
        url: url.to_string(),
        websocket: false,
        git: None,
        branches: None,
        allow_redirects: Vec::new(),
        log_body: true,
        protected_branches: None,
    }
}

pub fn ws_rule(url: &str) -> pyloros::config::Rule {
    pyloros::config::Rule {
        method: Some("GET".to_string()),
        url: url.to_string(),
        websocket: true,
        git: None,
        branches: None,
        allow_redirects: Vec::new(),
        log_body: false,
        protected_branches: None,
    }
}

pub fn git_rule(git_op: &str, url: &str) -> pyloros::config::Rule {
    pyloros::config::Rule {
        method: None,
        url: url.to_string(),
        websocket: false,
        git: Some(git_op.to_string()),
        branches: None,
        allow_redirects: Vec::new(),
        log_body: false,
        protected_branches: None,
    }
}

pub fn git_rule_with_branches(git_op: &str, url: &str, branches: &[&str]) -> pyloros::config::Rule {
    pyloros::config::Rule {
        method: None,
        url: url.to_string(),
        websocket: false,
        git: Some(git_op.to_string()),
        branches: Some(branches.iter().map(|b| b.to_string()).collect()),
        allow_redirects: Vec::new(),
        log_body: false,
        protected_branches: None,
    }
}

pub fn git_rule_with_protected(
    git_op: &str,
    url: &str,
    branches: &[&str],
    protected: &[&str],
) -> pyloros::config::Rule {
    pyloros::config::Rule {
        method: None,
        url: url.to_string(),
        websocket: false,
        git: Some(git_op.to_string()),
        branches: if branches.is_empty() {
            None
        } else {
            Some(branches.iter().map(|b| b.to_string()).collect())
        },
        protected_branches: Some(protected.iter().map(|p| p.to_string()).collect()),
        allow_redirects: Vec::new(),
        log_body: false,
    }
}

// ---------------------------------------------------------------------------
// Git test infrastructure
// ---------------------------------------------------------------------------

/// Shared log of "METHOD path?query" strings recorded by the upstream handler.
pub type RequestLog = Arc<Mutex<Vec<String>>>;

/// Locate the `git-http-backend` binary via `git --exec-path`.
pub fn git_http_backend_path() -> std::path::PathBuf {
    let output = std::process::Command::new("git")
        .arg("--exec-path")
        .output()
        .expect("git --exec-path failed");
    assert!(output.status.success(), "git --exec-path returned non-zero");
    let exec_path = String::from_utf8(output.stdout)
        .expect("non-UTF-8 exec path")
        .trim()
        .to_string();
    let backend = std::path::PathBuf::from(exec_path).join("git-http-backend");
    assert!(
        backend.exists(),
        "git-http-backend not found at {:?}",
        backend
    );
    backend
}

/// Create a test git repo: a source repo with a commit, then a bare clone to serve.
/// Returns the path to the directory containing the bare repo (the GIT_PROJECT_ROOT).
pub fn create_test_repo(dir: &std::path::Path, repo_name: &str) -> std::path::PathBuf {
    let source_dir = dir.join("source");
    std::fs::create_dir_all(&source_dir).unwrap();

    let run = |args: &[&str], cwd: &std::path::Path| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };

    run(&["init", "-b", "main"], &source_dir);
    run(&["config", "user.email", "test@test.com"], &source_dir);
    run(&["config", "user.name", "Test User"], &source_dir);

    std::fs::write(
        source_dir.join("README.md"),
        "# Test Repository\nHello from git test!\n",
    )
    .unwrap();
    run(&["add", "README.md"], &source_dir);
    run(&["commit", "-m", "Initial commit"], &source_dir);

    let repos_dir = dir.join("repos");
    std::fs::create_dir_all(&repos_dir).unwrap();
    run(
        &[
            "clone",
            "--bare",
            source_dir.to_str().unwrap(),
            repos_dir.join(repo_name).to_str().unwrap(),
        ],
        dir,
    );

    repos_dir
}

/// Parse CGI response output into (status_code, headers, body).
pub fn parse_cgi_response(output: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let (header_end, body_start) =
        if let Some(pos) = output.windows(4).position(|w| w == b"\r\n\r\n") {
            (pos, pos + 4)
        } else if let Some(pos) = output.windows(2).position(|w| w == b"\n\n") {
            (pos, pos + 2)
        } else {
            (output.len(), output.len())
        };

    let header_bytes = &output[..header_end];
    let body = output[body_start..].to_vec();

    let header_str = String::from_utf8_lossy(header_bytes);
    let mut status = 200u16;
    let mut headers = Vec::new();

    for line in header_str.lines() {
        if let Some(rest) = line.strip_prefix("Status:") {
            let rest = rest.trim();
            if let Some(code_str) = rest.split_whitespace().next() {
                if let Ok(code) = code_str.parse::<u16>() {
                    status = code;
                }
            }
        } else if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    (status, headers, body)
}

/// Create an upstream handler that delegates to `git http-backend` CGI.
/// Records each request as "METHOD path?query" in the shared log.
pub fn git_cgi_handler(
    backend_path: std::path::PathBuf,
    git_root: std::path::PathBuf,
    request_log: RequestLog,
) -> UpstreamHandler {
    Arc::new(move |req: Request<Incoming>| {
        let backend_path = backend_path.clone();
        let git_root = git_root.clone();
        let request_log = request_log.clone();
        Box::pin(async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let query = req.uri().query().unwrap_or("").to_string();

            let entry = if query.is_empty() {
                format!("{} {}", method, path)
            } else {
                format!("{} {}?{}", method, path, query)
            };
            request_log.lock().unwrap().push(entry);
            let content_type = req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let content_length = req
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            // Forward the Git-Protocol header so the backend can negotiate v2.
            // git-http-backend reads the `GIT_PROTOCOL` env var (not
            // `HTTP_GIT_PROTOCOL`) per its source.
            let git_protocol = req
                .headers()
                .get("git-protocol")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let body_bytes = req.collect().await.unwrap().to_bytes();

            let mut cmd = std::process::Command::new(&backend_path);
            cmd.env("GIT_PROJECT_ROOT", &git_root)
                .env("GIT_HTTP_EXPORT_ALL", "1")
                .env("PATH_INFO", &path)
                .env("QUERY_STRING", &query)
                .env("REQUEST_METHOD", &method)
                .env("CONTENT_TYPE", &content_type)
                .env("SERVER_PROTOCOL", "HTTP/1.1")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            if !content_length.is_empty() {
                cmd.env("CONTENT_LENGTH", &content_length);
            }
            if !git_protocol.is_empty() {
                cmd.env("GIT_PROTOCOL", &git_protocol);
            }

            let mut child = cmd.spawn().expect("failed to spawn git http-backend");

            if !body_bytes.is_empty() {
                use std::io::Write;
                let stdin = child.stdin.as_mut().unwrap();
                stdin.write_all(&body_bytes).unwrap();
            }
            drop(child.stdin.take());

            let output = child.wait_with_output().expect("git http-backend failed");

            let (status, headers, body) = parse_cgi_response(&output.stdout);

            let mut builder = Response::builder().status(status);
            for (key, value) in &headers {
                builder = builder.header(key.as_str(), value.as_str());
            }

            Ok(builder
                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                .unwrap())
        })
    })
}

/// An upstream handler that accepts WebSocket upgrades and echoes messages back.
pub fn ws_echo_handler() -> UpstreamHandler {
    use http_body_util::Empty;
    use tokio_tungstenite::WebSocketStream;

    Arc::new(|mut req: Request<Incoming>| {
        Box::pin(async move {
            // Verify this is a valid websocket upgrade request
            if !req
                .headers()
                .get(hyper::header::UPGRADE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.to_lowercase().contains("websocket"))
            {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(
                        Full::new(Bytes::from("Not a WebSocket request"))
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .unwrap());
            }

            // Extract the upgrade future before sending the 101 response
            let on_upgrade = hyper::upgrade::on(&mut req);

            // Derive the Sec-WebSocket-Accept value
            let ws_key = req
                .headers()
                .get("sec-websocket-key")
                .map(|v| v.to_str().unwrap_or("").to_string())
                .unwrap_or_default();
            let accept = tungstenite_accept_key(&ws_key);

            // Spawn the echo task
            tokio::spawn(async move {
                let upgraded = match on_upgrade.await {
                    Ok(u) => u,
                    Err(e) => {
                        eprintln!("ws_echo_handler upgrade failed: {}", e);
                        return;
                    }
                };

                let ws = WebSocketStream::from_raw_socket(
                    TokioIo::new(upgraded),
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                )
                .await;

                use futures_util::{SinkExt, StreamExt};
                let (mut tx, mut rx) = ws.split();
                while let Some(Ok(msg)) = rx.next().await {
                    if msg.is_close() {
                        let _ = tx.close().await;
                        break;
                    }
                    if (msg.is_text() || msg.is_binary()) && tx.send(msg).await.is_err() {
                        break;
                    }
                }
            });

            // Send 101 Switching Protocols response
            Ok(Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(hyper::header::UPGRADE, "websocket")
                .header(hyper::header::CONNECTION, "Upgrade")
                .header("Sec-WebSocket-Accept", accept)
                .body(
                    Empty::new()
                        .map_err(|e: std::convert::Infallible| match e {})
                        .boxed(),
                )
                .unwrap())
        })
    })
}

/// Compute the Sec-WebSocket-Accept value from a Sec-WebSocket-Key.
fn tungstenite_accept_key(key: &str) -> String {
    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes())
}

// ---------------------------------------------------------------------------
// Git-LFS test infrastructure
// ---------------------------------------------------------------------------

/// In-memory LFS object store, keyed by OID (SHA-256 hex string).
pub type LfsStore = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// In-memory LFS lock store for testing the locks API.
pub type LfsLockStore = Arc<Mutex<LfsLockState>>;

/// State for the LFS locks API mock.
pub struct LfsLockState {
    locks: Vec<LfsLock>,
    next_id: u64,
}

/// A single LFS lock entry.
#[derive(Clone)]
struct LfsLock {
    id: String,
    path: String,
}

impl LfsLockState {
    pub fn new() -> Self {
        Self {
            locks: Vec::new(),
            next_id: 1,
        }
    }
}

/// Create a new empty LFS lock store.
pub fn new_lfs_lock_store() -> LfsLockStore {
    Arc::new(Mutex::new(LfsLockState::new()))
}

/// Check whether `git lfs` is available on this system.
pub fn git_lfs_available() -> bool {
    std::process::Command::new("git")
        .args(["lfs", "version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Extract LFS object OID from a path like `/repo.git/lfs/objects/<oid>`.
/// Returns None if the path doesn't match or the OID is not a valid SHA-256 hex string.
fn extract_lfs_object_oid(path: &str) -> Option<String> {
    let idx = path.find("/lfs/objects/")?;
    let after = &path[idx + "/lfs/objects/".len()..];
    if after.len() == 64 && !after.contains('/') && after.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(after.to_string())
    } else {
        None
    }
}

/// Detect if a path is an LFS locks API endpoint.
/// Returns the lock endpoint type if matched.
enum LfsLockEndpoint {
    /// GET /info/lfs/locks — list locks
    List,
    /// POST /info/lfs/locks — create lock
    Create,
    /// POST /info/lfs/locks/verify — verify locks
    Verify,
    /// POST /info/lfs/locks/<id>/unlock — delete lock
    Unlock(String),
}

fn detect_lfs_lock_endpoint(path: &str, method: &hyper::Method) -> Option<LfsLockEndpoint> {
    // Check for /info/lfs/locks in the path
    let idx = path.find("/info/lfs/locks")?;
    let after = &path[idx + "/info/lfs/locks".len()..];

    match (method.as_str(), after) {
        ("GET", "" | "/") => Some(LfsLockEndpoint::List),
        ("POST", "" | "/") => Some(LfsLockEndpoint::Create),
        ("POST", "/verify" | "/verify/") => Some(LfsLockEndpoint::Verify),
        ("POST", suffix) => {
            // Match /info/lfs/locks/<id>/unlock
            let suffix = suffix.strip_prefix('/')?;
            let suffix = suffix
                .strip_suffix("/unlock")
                .or_else(|| suffix.strip_suffix("/unlock/"))?;
            if !suffix.is_empty() && !suffix.contains('/') {
                Some(LfsLockEndpoint::Unlock(suffix.to_string()))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Create an upstream handler that serves both git smart HTTP (via `git http-backend`)
/// and Git-LFS batch API + object transfers + locks API.
///
/// Routing:
/// - `POST .../info/lfs/objects/batch` → LFS batch API (parse JSON, return transfer URLs)
/// - `GET .../lfs/objects/<oid>` → serve LFS object from in-memory store
/// - `PUT .../lfs/objects/<oid>` → store LFS object in in-memory store
/// - `GET/POST .../info/lfs/locks[/...]` → LFS locks API
/// - Everything else → delegate to `git http-backend` CGI
pub fn lfs_git_handler(
    backend_path: std::path::PathBuf,
    git_root: std::path::PathBuf,
    request_log: RequestLog,
    lfs_store: LfsStore,
) -> UpstreamHandler {
    let lfs_request_log = request_log.clone();
    let git_handler = git_cgi_handler(backend_path, git_root, request_log);
    let lock_store = new_lfs_lock_store();

    Arc::new(move |req: Request<Incoming>| {
        let path = req.uri().path().to_string();
        let method = req.method().clone();

        // Log LFS requests (git CGI requests are logged by git_cgi_handler)
        let is_lfs_lock = path.contains("/info/lfs/locks");
        if path.ends_with("/info/lfs/objects/batch")
            || extract_lfs_object_oid(&path).is_some()
            || is_lfs_lock
        {
            lfs_request_log
                .lock()
                .unwrap()
                .push(format!("{} {}", method, path));
        }

        if path.ends_with("/info/lfs/objects/batch") && method == hyper::Method::POST {
            let lfs_store = lfs_store.clone();
            // Read host from URI authority (h2) or Host header (h1), before consuming body
            let host = req
                .uri()
                .host()
                .map(|h| h.to_string())
                .or_else(|| {
                    req.headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .map(|h| h.split(':').next().unwrap_or(h).to_string())
                })
                .unwrap_or_else(|| "localhost".to_string());
            Box::pin(async move {
                let body_bytes = req.collect().await.unwrap().to_bytes();
                let parsed: serde_json::Value =
                    serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
                let operation = parsed
                    .get("operation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let objects = parsed
                    .get("objects")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let repo_path = path.strip_suffix("/info/lfs/objects/batch").unwrap_or("");

                let mut response_objects = Vec::new();
                let store = lfs_store.lock().unwrap();
                for obj in &objects {
                    let oid = obj.get("oid").and_then(|v| v.as_str()).unwrap_or("");
                    let size = obj.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                    let href = format!("https://{}{}/lfs/objects/{}", host, repo_path, oid);

                    let actions = match operation {
                        "download" => {
                            serde_json::json!({ "download": { "href": href } })
                        }
                        "upload" => {
                            if store.contains_key(oid) {
                                serde_json::json!({})
                            } else {
                                serde_json::json!({ "upload": { "href": href } })
                            }
                        }
                        _ => serde_json::json!({}),
                    };

                    response_objects.push(serde_json::json!({
                        "oid": oid,
                        "size": size,
                        "authenticated": true,
                        "actions": actions,
                    }));
                }
                drop(store);

                let response_body = serde_json::json!({
                    "transfer": "basic",
                    "objects": response_objects,
                });

                Ok(Response::builder()
                    .status(200)
                    .header("Content-Type", "application/vnd.git-lfs+json")
                    .body(
                        Full::new(Bytes::from(response_body.to_string()))
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .unwrap())
            })
        } else if let Some(oid) = extract_lfs_object_oid(&path) {
            if method == hyper::Method::GET {
                let lfs_store = lfs_store.clone();
                Box::pin(async move {
                    let store = lfs_store.lock().unwrap();
                    if let Some(content) = store.get(&oid) {
                        Ok(Response::builder()
                            .status(200)
                            .header("Content-Type", "application/octet-stream")
                            .body(
                                Full::new(Bytes::from(content.clone()))
                                    .map_err(|e| match e {})
                                    .boxed(),
                            )
                            .unwrap())
                    } else {
                        Ok(Response::builder()
                            .status(404)
                            .body(
                                Full::new(Bytes::from("Object not found"))
                                    .map_err(|e| match e {})
                                    .boxed(),
                            )
                            .unwrap())
                    }
                })
            } else if method == hyper::Method::PUT {
                let lfs_store = lfs_store.clone();
                Box::pin(async move {
                    let body_bytes = req.collect().await.unwrap().to_bytes().to_vec();
                    lfs_store.lock().unwrap().insert(oid, body_bytes);
                    Ok(Response::builder()
                        .status(200)
                        .body(
                            Full::new(Bytes::from_static(b""))
                                .map_err(|e| match e {})
                                .boxed(),
                        )
                        .unwrap())
                })
            } else {
                Box::pin(async {
                    Ok(Response::builder()
                        .status(405)
                        .body(
                            Full::new(Bytes::from("Method not allowed"))
                                .map_err(|e| match e {})
                                .boxed(),
                        )
                        .unwrap())
                })
            }
        } else if let Some(lock_endpoint) = detect_lfs_lock_endpoint(&path, &method) {
            let lock_store = lock_store.clone();
            Box::pin(async move {
                // Consume body (needed for POST endpoints)
                let body_bytes = req.collect().await.unwrap().to_bytes();
                let mut store = lock_store.lock().unwrap();

                let response_body = match lock_endpoint {
                    LfsLockEndpoint::List => {
                        let locks: Vec<serde_json::Value> = store
                            .locks
                            .iter()
                            .map(|l| {
                                serde_json::json!({
                                    "id": l.id,
                                    "path": l.path,
                                    "locked_at": "2024-01-01T00:00:00Z",
                                    "owner": { "name": "test-user" }
                                })
                            })
                            .collect();
                        serde_json::json!({ "locks": locks })
                    }
                    LfsLockEndpoint::Create => {
                        let parsed: serde_json::Value =
                            serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
                        let lock_path = parsed
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let id = store.next_id.to_string();
                        store.next_id += 1;
                        store.locks.push(LfsLock {
                            id: id.clone(),
                            path: lock_path.clone(),
                        });
                        serde_json::json!({
                            "lock": {
                                "id": id,
                                "path": lock_path,
                                "locked_at": "2024-01-01T00:00:00Z",
                                "owner": { "name": "test-user" }
                            }
                        })
                    }
                    LfsLockEndpoint::Verify => {
                        let ours: Vec<serde_json::Value> = store
                            .locks
                            .iter()
                            .map(|l| {
                                serde_json::json!({
                                    "id": l.id,
                                    "path": l.path,
                                    "locked_at": "2024-01-01T00:00:00Z",
                                    "owner": { "name": "test-user" }
                                })
                            })
                            .collect();
                        serde_json::json!({ "ours": ours, "theirs": [] })
                    }
                    LfsLockEndpoint::Unlock(ref lock_id) => {
                        if let Some(pos) = store.locks.iter().position(|l| l.id == *lock_id) {
                            let removed = store.locks.remove(pos);
                            serde_json::json!({
                                "lock": {
                                    "id": removed.id,
                                    "path": removed.path,
                                    "locked_at": "2024-01-01T00:00:00Z",
                                    "owner": { "name": "test-user" }
                                }
                            })
                        } else {
                            return Ok(Response::builder()
                                .status(404)
                                .header("Content-Type", "application/vnd.git-lfs+json")
                                .body(
                                    Full::new(Bytes::from(
                                        serde_json::json!({"message": "lock not found"})
                                            .to_string(),
                                    ))
                                    .map_err(|e| match e {})
                                    .boxed(),
                                )
                                .unwrap());
                        }
                    }
                };

                Ok(Response::builder()
                    .status(200)
                    .header("Content-Type", "application/vnd.git-lfs+json")
                    .body(
                        Full::new(Bytes::from(response_body.to_string()))
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .unwrap())
            })
        } else {
            git_handler(req)
        }
    })
}

/// Recursively collect LFS objects from `.git/lfs/objects/` into the store.
fn collect_lfs_objects(dir: &std::path::Path, store: &LfsStore) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_lfs_objects(&path, store);
            } else if path.is_file() {
                let filename = path.file_name().unwrap().to_str().unwrap().to_string();
                // LFS OIDs are 64 hex characters (SHA-256)
                if filename.len() == 64 && filename.chars().all(|c| c.is_ascii_hexdigit()) {
                    let content = std::fs::read(&path).unwrap();
                    store.lock().unwrap().insert(filename, content);
                }
            }
        }
    }
}

/// Create a test git repo with LFS-tracked files.
///
/// Returns:
/// - The repos directory (GIT_PROJECT_ROOT for git-http-backend)
/// - An in-memory LFS store pre-populated with the LFS objects from the repo
///
/// The bare repo has `http.receivepack = true` for push tests.
pub fn create_test_repo_with_lfs(
    dir: &std::path::Path,
    repo_name: &str,
) -> (std::path::PathBuf, LfsStore) {
    let source_dir = dir.join("source");
    std::fs::create_dir_all(&source_dir).unwrap();

    let run = |args: &[&str], cwd: &std::path::Path| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };

    run(&["init", "-b", "main"], &source_dir);
    run(&["config", "user.email", "test@test.com"], &source_dir);
    run(&["config", "user.name", "Test User"], &source_dir);
    run(&["lfs", "install", "--local"], &source_dir);
    run(&["lfs", "track", "*.bin"], &source_dir);

    let test_content = b"Hello from LFS! This is binary content for testing.\n";
    std::fs::write(source_dir.join("test-data.bin"), test_content).unwrap();

    run(&["add", ".gitattributes", "test-data.bin"], &source_dir);
    run(&["commit", "-m", "Initial commit with LFS"], &source_dir);

    // Bare clone (copies git objects including LFS pointers, but not LFS content)
    let repos_dir = dir.join("repos");
    std::fs::create_dir_all(&repos_dir).unwrap();
    run(
        &[
            "clone",
            "--bare",
            source_dir.to_str().unwrap(),
            repos_dir.join(repo_name).to_str().unwrap(),
        ],
        dir,
    );

    // Enable receive-pack for push tests
    run(
        &["config", "http.receivepack", "true"],
        &repos_dir.join(repo_name),
    );

    // Extract LFS objects from source repo into in-memory store
    let store: LfsStore = Arc::new(Mutex::new(HashMap::new()));
    let lfs_objects_dir = source_dir.join(".git/lfs/objects");
    if lfs_objects_dir.exists() {
        collect_lfs_objects(&lfs_objects_dir, &store);
    }
    assert!(
        !store.lock().unwrap().is_empty(),
        "No LFS objects found in source repo — git-lfs may not be installed"
    );

    (repos_dir, store)
}

// ---------------------------------------------------------------------------
// Audit log helpers
// ---------------------------------------------------------------------------

/// Read a JSONL audit log file and parse each line into a serde_json::Value.
pub fn read_audit_entries(path: &str) -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("invalid JSON in audit log"))
        .collect()
}
