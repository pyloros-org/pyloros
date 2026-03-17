# HTTP/1.1 to HTTP/2 Forwarding in CONNECT Tunnels

## Problem

When an HTTP/1.1 client (wget, `curl --http1.1`) sends requests inside a CONNECT tunnel and the upstream server negotiates HTTP/2, the proxy must translate between protocols correctly.

## Key differences between h1 and h2 clients in a CONNECT tunnel

- **HTTP/2 clients** (curl default): Negotiate h2 with the MITM server via ALPN. Their requests arrive with a full absolute URI (`https://host/path`) and no `Host` header. hyper's h2 module derives `:scheme` and `:authority` pseudo-headers from the URI.

- **HTTP/1.1 clients** (wget, `curl --http1.1`): Send origin-form requests (`GET /`) with a `Host` header. The proxy receives a path-only URI with no scheme or authority information embedded in the URI itself.

## Two issues to handle

### 1. Reconstruct the full URI for h2

HTTP/2 requires `:scheme` and `:authority` pseudo-headers. hyper's h2 client derives these from the request URI. If the URI is just `/`, these pseudo-headers are missing or wrong, and upstream servers respond with `PROTOCOL_ERROR` RST_STREAM.

**Fix**: When the incoming request URI has no scheme (path-only), reconstruct the full `https://host/path` URI before forwarding. The host and port are known from the CONNECT tunnel context.

### 2. Strip the Host header for h2

In HTTP/2, `:authority` replaces `Host`. Some servers (notably Google) reject h2 requests that include both `:authority` and `Host` with `PROTOCOL_ERROR`, even when the values match. This is allowed by RFC 9113 but not universally tolerated.

**Fix**: Remove the `Host` header before sending over h2. The `:authority` pseudo-header (derived from the URI) carries the same information.

## Debugging tips

- Use `wget -d` to see the exact request headers sent inside the tunnel
- Compare proxy log output between `curl` (h2 client) and `wget` (h1 client) — the URI form differs
- `PROTOCOL_ERROR` RST_STREAM from the remote usually means malformed pseudo-headers, not a local hyper issue
- hyper's h2 module auto-strips connection-specific headers (Connection, Keep-Alive, etc.), so those won't cause PROTOCOL_ERROR — look at the URI and Host header instead
