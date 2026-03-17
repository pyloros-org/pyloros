//! HTTP proxy server implementation

mod handler;
mod response;
mod server;
mod tunnel;

pub use handler::ProxyHandler;
pub use server::{ListenAddress, ProxyServer};
pub use tunnel::TunnelHandler;

/// Hop-by-hop headers that must not be forwarded by a proxy (RFC 7230 §6.1).
pub(crate) const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Remove all hop-by-hop headers from a header map.
pub(crate) fn strip_hop_by_hop_headers(headers: &mut hyper::header::HeaderMap) {
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
}
