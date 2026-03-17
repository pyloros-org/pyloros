# Hop-by-Hop Header Stripping in Proxies

## Problem

HTTP hop-by-hop headers (RFC 7230 §6.1) must not be forwarded by proxies. These include: `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`.

## Why it's easy to miss

- hyper's HTTP/2 client auto-strips connection-specific headers before sending to the h2 crate, masking the bug when upstream negotiates h2.
- reqwest also strips hop-by-hop headers internally, so tests using reqwest as the client won't detect the leak.
- The bug only manifests when both the client and upstream use HTTP/1.1.

## Testing strategy

To reliably test hop-by-hop stripping, force both sides to HTTP/1.1:
- Use an h1-only upstream (`.h1_only()` on `TestUpstream`) to prevent hyper's h2 auto-stripping from masking the issue.
- Use an echo handler to inspect what headers the upstream actually receives.
- Don't rely on reqwest to send the headers — it strips them. Use `ReportingClient::new_h1_only()` or binary tests with wget.

## WebSocket exception

The WebSocket upgrade path must NOT strip hop-by-hop headers — it requires `Connection: Upgrade`. WebSocket always uses HTTP/1.1, so this is safe.
