# pyloros — agent instructions

You are running behind **pyloros**, an HTTPS allowlist proxy. Outbound HTTP
requests that don't match an active allow rule are blocked with HTTP **451
"Unavailable For Legal Reasons"**. A 451 from this proxy is **not** an error
in the target server — it means *you* need permission first.

When you hit a 451 (or want to make an outbound call you expect will be
blocked), request approval from the human via the agent API.

The API is only reachable through the proxy at the magic hostname
`pyloros.internal`. The hostname does not resolve externally — it's
intercepted by the proxy.

This page itself lives at `https://pyloros.internal/` so you can re-fetch
it any time to refresh your understanding of the protocol.

## Endpoints

### `POST https://pyloros.internal/approvals`

Request body (JSON):

```json
{
  "rules": [
    {"method": "GET", "url": "https://api.example.com/*"}
  ],
  "reason": "short human-readable explanation",
  "context": {
    "triggered_by": {"method": "GET", "url": "https://api.example.com/whatever"}
  },
  "suggested_ttl": "one_hour"
}
```

`rules` is required; `reason`, `context`, and `suggested_ttl` are optional but
strongly recommended — `reason` is shown to the human in the dashboard, and
`triggered_by` lets the dashboard pre-fill defaults.

Responses:

- `200` `{"status":"approved", ...}` — already covered by an active rule;
  proceed immediately. (Dedup short-circuit; no human round-trip.)
- `202` `{"id":"apr_...","status":"pending", ...}` — waiting on the human.
- `429` — rate limited (60 POSTs/minute). Back off; do **not** retry tightly.
- `400` — malformed JSON or invalid rule shape.

### `GET https://pyloros.internal/approvals/{id}?wait=60s`

Long-poll the decision. Returns when the human approves or denies, or when
the wait window elapses (in which case the request is still `pending` and
you should re-poll). Status values:

- `"approved"` — rule(s) are now active in the proxy. Retry your request.
- `"denied"` — may include a `"message"` field. Respect it; do **not** retry
  the same request or propose minor variants of the same rule.
- `"pending"` — the wait window elapsed without a decision. Re-poll.

The `wait` query parameter accepts `Ns`, `Nms`, or a bare integer (seconds).
Maximum 60s; longer values are clamped.

## Rule shape

Rules are JSON objects with the same fields as a `[[rules]]` entry in the
TOML config. Common shapes:

| JSON | Meaning |
|---|---|
| `{"method":"GET","url":"https://api.foo.com/*"}` | plain HTTP rule |
| `{"method":"*","url":"https://api.foo.com/*"}` | any method |
| `{"git":"fetch","url":"https://github.com/foo/bar.git"}` | `git clone`/`git fetch` (expands to all the smart-HTTP + LFS endpoints automatically) |
| `{"git":"push","url":"https://github.com/foo/bar.git"}` | `git push` |
| `{"git":"*","url":"https://github.com/foo/bar.git"}` | fetch + push |
| `{"method":"GET","url":"https://api.foo.com/*","websocket":true}` | WebSocket upgrade |
| `{"method":"GET","url":"https://foo.com/dl/*","allow_redirects":["https://cdn.foo.com/*"]}` | follow redirects to a signed CDN URL |

Wildcards (`*`) are valid in path segments and as the method. Wildcards in
the host (e.g. `https://*.foo.com/`) are accepted but you should prefer the
exact host the human is most likely to recognise.

## Redirects (`allow_redirects`)

A rule only allows the URL you asked for. If the server answers with a 3xx to
a different host (release assets, CDNs, package mirrors, signed download URLs),
the follow-up request is a *separate* request and gets its own 451 — even
though the first one was allowed.

Symptom: your download tool reports 451 on a URL you never typed, or a
`curl -L` that got a 302 then died. Fix it in the *original* rule with
`allow_redirects`, a list of URL patterns (same wildcard syntax as `url`):

```json
{
  "rules": [
    {
      "method": "GET",
      "url": "https://github.com/neovim/neovim/releases/download/*",
      "allow_redirects": ["https://release-assets.githubusercontent.com/*"]
    }
  ],
  "reason": "download neovim release tarball",
  "suggested_ttl": "one_hour"
}
```

When a request matching that rule returns 3xx, the `Location` (resolved
against the request URL, so relative Locations work) is checked against these
patterns; on match the **exact** resolved URL is whitelisted for a short
window (default 60s) and your follow-up request goes through. Chains are
followed recursively, each hop re-checked against the original rule's
patterns.

Guidelines:

- Redirects are **not** followed unless the rule opts in. Omitted or empty
  `allow_redirects` means the follow-up is blocked as usual.
- Name the redirect host you actually observed. The 451 you got on the
  follow-up tells you the URL; use its host, e.g.
  `["https://release-assets.githubusercontent.com/*"]`.
- `["*"]` accepts any redirect target. It's the one place a bare `"*"` is a
  valid pattern (other fields require a scheme). Use it only when the target
  host is unpredictable, and expect the human to push back.
- `allow_redirects` belongs on the rule for the **origin** URL, not on a
  separate rule for the redirect target. Don't request a second rule for a
  signed URL — it's single-use and expires.
- The whitelist entry is short-lived. Retry promptly after approval, and
  don't reuse a redirect target across a long pause; re-request the origin
  URL instead.

## Guidelines

- **Ask for the narrowest rule that covers your task.** The human is more
  likely to approve `{"method":"GET","url":"https://api.example.com/v1/weather/*"}`
  than `{"method":"*","url":"https://*.example.com/*"}`.
- **Always include a `reason`** — the human reads it before deciding.
- **For git, prefer `git=fetch` (or `git=push`)** over a plain method rule.
  It expands to all the smart-HTTP endpoints the operation needs and is
  what the human probably wants to grant in one click.
- **If denied with a message, read it.** Don't paper over the denial; don't
  re-submit a slightly-different rule that ignores the feedback.
- **Don't burst-poll.** The rate limit is 60 POSTs/minute; tight retry
  loops will trip it and you'll have to back off anyway.
