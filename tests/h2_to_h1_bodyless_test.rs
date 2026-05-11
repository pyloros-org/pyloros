mod common;

use bytes::Bytes;
use common::{rule, ReportingClient, TestCa, TestProxy, TestUpstream, UpstreamHandler};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::sync::{Arc, Mutex};

/// Some servers are still http/1.1 only (e.g. AWS STS regional endpoints), and
/// strictly require a `Host:` header on HTTP/1.1 requests — they return
/// `400` with an empty body if it's missing.
///
/// When pyloros's hyper h2 server receives a request, it does *not* synthesize
/// a `Host` header from the `:authority` pseudo-header. The previous
/// `rebuild_request_for_upstream` only re-set Host **if it was already
/// present in incoming headers**, so h2-client → h1-upstream requests went
/// out without Host, breaking against any RFC-compliant h1 server (AWS STS,
/// many CDNs, etc.). HTTP/1.1 clients send Host themselves so the h1→h1
/// path was unaffected.
///
/// This handler models that strict behavior locally: 400 if Host is absent,
/// else 200.
fn require_host_handler(observed_host: Arc<Mutex<Vec<Option<String>>>>) -> UpstreamHandler {
    Arc::new(move |req: Request<Incoming>| {
        let observed_host = observed_host.clone();
        Box::pin(async move {
            let host = req
                .headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            observed_host.lock().unwrap().push(host.clone());

            if host.is_none() {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
                    .unwrap());
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(
                    Full::new(Bytes::from_static(b"ok"))
                        .map_err(|e| match e {})
                        .boxed(),
                )
                .unwrap())
        })
    })
}

#[tokio::test]
async fn h1_client_to_h1_upstream_sends_host() {
    let t = test_report!("H1 client → h1 upstream: Host header present");

    let ca = TestCa::generate();
    let observed = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let upstream = TestUpstream::builder(&ca, require_host_handler(observed.clone()))
        .h1_only()
        .report(&t, "rejects requests without Host header")
        .start()
        .await;
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new_h1_only(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/").await;

    t.assert_eq("Response status", &resp.status().as_u16(), &200u16);
    let h = observed.lock().unwrap().clone();
    t.assert_eq("Upstream saw N requests", &h.len(), &1usize);
    t.assert_true("Upstream saw Host header", h[0].is_some());

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn h2_client_to_h1_upstream_sends_host() {
    let t = test_report!("H2 client → h1 upstream: Host header forwarded");

    let ca = TestCa::generate();
    let observed = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let upstream = TestUpstream::builder(&ca, require_host_handler(observed.clone()))
        .h1_only()
        .report(&t, "rejects requests without Host header")
        .start()
        .await;
    let proxy = TestProxy::builder(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .report(&t)
    .start()
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/").await;

    t.assert_eq(
        "Client-side HTTP version",
        &format!("{:?}", resp.version()),
        &"HTTP/2.0",
    );
    t.assert_eq("Response status", &resp.status().as_u16(), &200u16);
    let h = observed.lock().unwrap().clone();
    t.assert_eq("Upstream saw N requests", &h.len(), &1usize);
    t.assert_true("Upstream saw Host header", h[0].is_some());
    if let Some(host) = &h[0] {
        // Host derived from h2 :authority (the upstream-port override is
        // appended in tests but the hostname must be present).
        t.assert_starts_with("Host header value", host.as_str(), "localhost");
    }

    proxy.shutdown();
    upstream.shutdown();
}
