# HTTP/2 to HTTP/1.1 Forwarding in CONNECT Tunnels

Companion to `h1-to-h2-forwarding.md` — same h1/h2 Host-vs-`:authority`
asymmetry, opposite direction.

## Problem

When pyloros's hyper h2 server received a request from an h2 client and
forwarded it to an h1-only upstream, the request went out **without a
`Host` header**. RFC 9112 §3.2 mandates Host on HTTP/1.1 — strict servers
reject without it. AWS STS regional endpoints (which only advertise
`http/1.1` over ALPN) responded with `HTTP/2 400 + content-length: 0 +
date` only. The 400 reaches the client because pyloros faithfully relays
the upstream response.

## Root cause

hyper's h2 server constructs `Request<Incoming>` with `:scheme` and
`:authority` collapsed into `req.uri()`. It does **not** synthesize a
`Host` header in `req.headers()`. h1 clients send Host themselves, so the
h1→h1 path was unaffected.

`rebuild_request_for_upstream` only touched Host when it found one in the
incoming headers:

```rust
for (name, value) in parts.headers.iter() {
    if name == hyper::header::HOST {
        builder = builder.header(name, &host_value);
    } else {
        builder = builder.header(name, value);
    }
}
```

For h2-originated requests `parts.headers` had no Host, so the loop never
fired the override, and the upstream request shipped without it.

## Fix

Set Host unconditionally:

```rust
let mut host_set = false;
for (name, value) in parts.headers.iter() {
    if name == hyper::header::HOST {
        builder = builder.header(name, &host_value);
        host_set = true;
    } else {
        builder = builder.header(name, value);
    }
}
if !host_set {
    builder = builder.header(hyper::header::HOST, &host_value);
}
```

The h2-upstream branch in `forward_request_boxed` still strips Host before
sending (h2 derives `:authority` from the URI, and some servers reject
both being present — see `h1-to-h2-forwarding.md`).

## Symptom checklist (h2 client → strict h1 upstream)

- `HTTP/2 400` from upstream with empty body and only `date` header.
- Works with `--http1.1` because curl includes Host itself.
- ALPN check: `openssl s_client -alpn h2,http/1.1 -connect host:443` shows
  the upstream advertises `http/1.1`. If both your client and pyloros use
  h2 but the upstream doesn't, the asymmetric bridge is exercised.

## Debugging trick

Reproducing this against a local TestUpstream initially fails to repro
because hyper's h1 *server* (used by `TestUpstream`) is lenient about
missing Host. Use a handler that explicitly returns 400 when Host is
absent — that mirrors AWS's strictness. See
`tests/h2_to_h1_bodyless_test.rs`.

False leads encountered:
- "Transfer-Encoding: chunked on GET" — plausible (h2 streaming bodies
  can become chunked over h1), but raw-socket tests against AWS STS
  showed chunked GETs hang silently rather than returning 400. Always
  validate the wire-level hypothesis before patching.
- Header case differences (lowercase from h2 server vs Title-Case from
  h1) — AWS STS accepts both.
