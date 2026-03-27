mod common;

use common::{ok_handler, ws_echo_handler, ws_rule, TestCa, TestProxy, TestReport, TestUpstream};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

type WsStream = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Connect a WebSocket client through the HTTP CONNECT proxy to wss://localhost/path.
///
/// Returns a WebSocketStream ready for sending/receiving messages.
async fn ws_connect_through_proxy(proxy_addr: SocketAddr, ca: &TestCa, path: &str) -> WsStream {
    // Step 1: TCP connect to proxy
    let mut tcp = TcpStream::connect(proxy_addr).await.unwrap();

    // Step 2: Send HTTP CONNECT request
    let connect_req = "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n";
    tcp.write_all(connect_req.as_bytes()).await.unwrap();

    // Step 3: Read the 200 OK response from the proxy
    let mut buf = [0u8; 1024];
    let n = tcp.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "Expected 200 from CONNECT, got: {}",
        response
    );

    // Step 4: TLS handshake over the tunnel (proxy does MITM, so we trust the test CA)
    let tls_config = ca.client_tls_config();
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    // Step 5: WebSocket handshake over TLS
    let ws_url = format!("wss://localhost{}", path);
    let (ws_stream, _resp) = tokio_tungstenite::client_async(&ws_url, tls_stream)
        .await
        .expect("WebSocket handshake failed");

    ws_stream
}

/// Connect a WebSocket client with reporting.
async fn ws_connect_reported(
    t: &TestReport,
    proxy_addr: SocketAddr,
    ca: &TestCa,
    path: &str,
) -> WsStream {
    t.action(format!("WebSocket connect to wss://localhost{}", path));
    ws_connect_through_proxy(proxy_addr, ca, path).await
}

/// A WebSocket stream wrapper that auto-logs actions to TestReport.
struct ReportingWebSocket<'a> {
    inner: WsStream,
    report: &'a TestReport,
}

impl<'a> ReportingWebSocket<'a> {
    fn new(inner: WsStream, report: &'a TestReport) -> Self {
        Self { inner, report }
    }

    async fn send(&mut self, msg: Message) {
        let desc = match &msg {
            Message::Text(t) => format!("WS send text: '{}'", t),
            Message::Binary(b) => format!("WS send binary ({} bytes)", b.len()),
            Message::Ping(p) => format!("WS send Ping ({} bytes)", p.len()),
            Message::Pong(p) => format!("WS send Pong ({} bytes)", p.len()),
            Message::Close(_) => "WS send Close".to_string(),
            _ => "WS send frame".to_string(),
        };
        self.report.action(desc);
        self.inner.send(msg).await.unwrap();
    }

    async fn next(&mut self) -> Message {
        self.report.action("WS receive");
        self.inner.next().await.unwrap().unwrap()
    }

    async fn close(&mut self) {
        self.report.action("WS close");
        self.inner.close(None).await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// Group 1: Basic WebSocket echo + blocked
// ---------------------------------------------------------------------------

/// WebSocket echo through the proxy: send a text message, receive it back.
#[tokio::test]
async fn test_websocket_echo() {
    let t = test_report!("WebSocket echo through proxy");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ws_echo_handler())
        .report(&t, "ws echo handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![ws_rule("wss://localhost/*")], upstream.port())
        .report(&t)
        .start()
        .await;

    let ws = ws_connect_reported(&t, proxy.addr(), &ca, "/echo").await;
    let mut ws = ReportingWebSocket::new(ws, &t);

    ws.send(Message::Text("hello websocket".into())).await;

    let msg = ws.next().await;
    t.assert_eq(
        "Echo response",
        &msg,
        &Message::Text("hello websocket".into()),
    );

    ws.close().await;
    proxy.shutdown();
    upstream.shutdown();
}

/// WebSocket request blocked by filter returns 451.
#[tokio::test]
async fn test_websocket_blocked_by_filter() {
    let t = test_report!("WebSocket blocked by filter returns 451");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ws_echo_handler())
        .report(&t, "ws echo handler")
        .start()
        .await;

    // Only allow example.com, not localhost
    let proxy = TestProxy::builder(&ca, vec![ws_rule("wss://example.com/*")], upstream.port())
        .report(&t)
        .start()
        .await;

    // Low-level raw TCP/TLS handshake — intentionally bare t.action()
    t.action("TCP CONNECT + TLS handshake to localhost:443");
    let mut tcp = TcpStream::connect(proxy.addr()).await.unwrap();

    let connect_req = "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n";
    tcp.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = tcp.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.starts_with("HTTP/1.1 200"));

    let tls_config = ca.client_tls_config();
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    // Send raw HTTP WebSocket upgrade request
    t.action("Send WebSocket upgrade request to /echo");
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;
    let (mut read_half, mut write_half) = tokio::io::split(tls_stream);

    let upgrade_req = "GET /echo HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        \r\n";
    write_half.write_all(upgrade_req.as_bytes()).await.unwrap();

    // Read the response — should be 451
    let mut resp_buf = vec![0u8; 4096];
    let n = read_half.read(&mut resp_buf).await.unwrap();
    let resp = String::from_utf8_lossy(&resp_buf[..n]).to_string();

    t.assert_starts_with("Response is 451", &resp, "HTTP/1.1 451");

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Group 2: Multiple messages + binary
// ---------------------------------------------------------------------------

/// Send several text messages and verify all are echoed back in order.
#[tokio::test]
async fn test_websocket_multiple_messages() {
    let t = test_report!("WebSocket multiple messages echoed in order");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ws_echo_handler())
        .report(&t, "ws echo handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![ws_rule("wss://localhost/*")], upstream.port())
        .report(&t)
        .start()
        .await;

    let ws = ws_connect_reported(&t, proxy.addr(), &ca, "/multi").await;
    let mut ws = ReportingWebSocket::new(ws, &t);

    let messages = vec!["first", "second", "third", "fourth", "fifth"];
    for msg in &messages {
        ws.send(Message::Text((*msg).into())).await;
    }

    for expected in &messages {
        let msg = ws.next().await;
        t.assert_eq(
            &format!("Echo of '{}'", expected),
            &msg,
            &Message::Text((*expected).into()),
        );
    }

    ws.close().await;
    proxy.shutdown();
    upstream.shutdown();
}

/// Send binary data through the WebSocket proxy and verify integrity.
#[tokio::test]
async fn test_websocket_binary_message() {
    let t = test_report!("WebSocket binary message integrity");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ws_echo_handler())
        .report(&t, "ws echo handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![ws_rule("wss://localhost/*")], upstream.port())
        .report(&t)
        .start()
        .await;

    let ws = ws_connect_reported(&t, proxy.addr(), &ca, "/binary").await;
    let mut ws = ReportingWebSocket::new(ws, &t);

    // Send binary data with all byte values 0-255
    let binary_data: Vec<u8> = (0..=255).collect();
    ws.send(Message::Binary(binary_data.clone().into())).await;

    let msg = ws.next().await;
    match msg {
        Message::Binary(data) => {
            t.assert_eq("Binary data length", &data.len(), &binary_data.len());
            t.assert_true(
                "Binary data matches",
                data.as_ref() == binary_data.as_slice(),
            );
        }
        other => panic!("Expected Binary message, got {:?}", other),
    }

    ws.close().await;
    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Group 3: Upstream rejection
// ---------------------------------------------------------------------------

/// When upstream returns a non-101 response to a WebSocket upgrade, the proxy
/// forwards the rejection to the client.
#[tokio::test]
async fn test_websocket_upstream_rejects() {
    let t = test_report!("WebSocket upstream rejection forwarded");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("not a websocket server"))
        .report(&t, "returns 200 (not ws)")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![ws_rule("wss://localhost/*")], upstream.port())
        .report(&t)
        .start()
        .await;

    // Low-level raw TCP/TLS handshake — intentionally bare t.action()
    t.action("TCP CONNECT + TLS handshake to localhost:443");
    let mut tcp = TcpStream::connect(proxy.addr()).await.unwrap();
    let connect_req = "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n";
    tcp.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = tcp.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.starts_with("HTTP/1.1 200"));

    let tls_config = ca.client_tls_config();
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    // Try WebSocket handshake — upstream doesn't support it, so it should fail
    t.action("WebSocket handshake to wss://localhost/ws (expect failure)");
    let ws_url = "wss://localhost/ws";
    let result = tokio_tungstenite::client_async(ws_url, tls_stream).await;

    t.assert_true("WebSocket handshake failed", result.is_err());
    let err = result.unwrap_err().to_string();
    t.assert_contains("Error mentions status 200", &err, "200");

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Group 4: Control frames
// ---------------------------------------------------------------------------

/// Ping frames are forwarded through the proxy tunnel; upstream tungstenite
/// auto-responds with a Pong carrying the same payload.
#[tokio::test]
async fn test_websocket_ping_pong() {
    let t = test_report!("WebSocket ping/pong control frames");

    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ws_echo_handler())
        .report(&t, "ws echo handler")
        .start()
        .await;
    let proxy = TestProxy::builder(&ca, vec![ws_rule("wss://localhost/*")], upstream.port())
        .report(&t)
        .start()
        .await;

    let ws = ws_connect_reported(&t, proxy.addr(), &ca, "/ping").await;
    let mut ws = ReportingWebSocket::new(ws, &t);

    // Send a Ping control frame
    ws.send(Message::Ping(b"ping-payload".to_vec().into()))
        .await;

    // Send a Text message to trigger the upstream to flush its auto-pong
    ws.send(Message::Text("hello".into())).await;

    // Collect the next 2 messages — expect Pong + Text echo (order not guaranteed)
    let mut received = Vec::new();
    for _ in 0..2 {
        let msg = ws.next().await;
        received.push(msg);
    }

    let has_pong = received.iter().any(|m| match m {
        Message::Pong(data) => data.as_ref() == b"ping-payload",
        _ => false,
    });
    let has_echo = received.iter().any(|m| *m == Message::Text("hello".into()));

    t.assert_true("Received Pong with correct payload", has_pong);
    t.assert_true("Received Text echo", has_echo);

    // Clean close
    ws.close().await;
    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Group 5: HTTP/2 ALPN negotiation
// ---------------------------------------------------------------------------

/// A strict upstream that uses h2::Builder when ALPN negotiated h2, instead of
/// auto-detecting from wire bytes. This simulates real servers (e.g. elevenlabs)
/// that immediately send h2 connection preface after ALPN negotiation.
async fn start_strict_alpn_upstream(
    ca: &TestCa,
    handler: common::UpstreamHandler,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    use hyper::server::conn::{http1, http2};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio_rustls::TlsAcceptor;

    let server_config = ca.server_tls_config("localhost");
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

                        // Check what ALPN was actually negotiated
                        let negotiated_h2 = tls_stream
                            .get_ref()
                            .1
                            .alpn_protocol()
                            == Some(b"h2".as_slice());

                        let io = TokioIo::new(tls_stream);
                        let service = service_fn(move |req| {
                            let handler = handler.clone();
                            handler(req)
                        });

                        if negotiated_h2 {
                            // Strict h2: use h2 builder directly, no fallback
                            let _ = http2::Builder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await;
                        } else {
                            let _ = http1::Builder::new()
                                .serve_connection(io, service)
                                .with_upgrades()
                                .await;
                        }
                    });
                }
            }
        }
    });

    (addr, shutdown_tx)
}

/// WebSocket through a strict-ALPN upstream that speaks h2 when h2 is negotiated.
///
/// Without the h1-only ALPN fix in forward_websocket, the proxy would negotiate
/// h2 with the upstream, then try to send h1 Upgrade bytes on an h2 connection,
/// causing "invalid HTTP version parsed".
#[tokio::test]
async fn test_websocket_with_h2_preferring_upstream() {
    let t = test_report!("WebSocket works with h2-preferring upstream (strict ALPN)");

    let ca = TestCa::generate();
    let (upstream_addr, upstream_shutdown) =
        start_strict_alpn_upstream(&ca, ws_echo_handler()).await;

    t.setup(format!(
        "Strict-ALPN upstream on port {}",
        upstream_addr.port()
    ));

    let proxy = TestProxy::builder(
        &ca,
        vec![ws_rule("wss://localhost/*")],
        upstream_addr.port(),
    )
    .report(&t)
    .start()
    .await;

    let ws = ws_connect_reported(&t, proxy.addr(), &ca, "/echo").await;
    let mut ws = ReportingWebSocket::new(ws, &t);

    ws.send(Message::Text("h2 alpn test".into())).await;

    let msg = ws.next().await;
    t.assert_eq("Echo response", &msg, &Message::Text("h2 alpn test".into()));

    ws.close().await;
    proxy.shutdown();
    let _ = upstream_shutdown.send(());
}
