# Approvals — Design Doc

Status: **draft / brainstorming**. Not yet reflected in `SPEC.md`. This doc is the scratchpad; once we converge, the user-facing requirements get lifted into `SPEC.md` and the implementation rationale into `INTERNALS.md`.

## Motivation

pyloros blocks requests that don't match any allow rule, returning HTTP 451. Today, unblocking requires the human to stop the agent, edit the config, and restart. That's high friction and breaks autonomous runs.

We want: a **coding agent running inside the sandbox can request permission from the human to add one or more rules**. Approving adds them to the active ruleset; denying is remembered (optionally, with a reason) so the agent doesn't retry blindly.

### Why not auto-promote every 451 into an approval?

1. The rule the agent actually needs may be **broader** than the specific URL that 451'd — e.g. an entire `api.foo.com/*` instead of `/v1/endpoint`. The agent can generalize.
2. The agent can attach a **human-readable reason** ("need to fetch weather data for the demo") so the user isn't just staring at a URL.
3. The agent can **preemptively** request access before hitting 451, reducing mid-run stalls.

## Non-goals (v1)

- Multi-user / team approvals. One pyloros instance, one human.
- Audit review / post-hoc approval logs beyond what the existing audit log already records.
- Strong agent identity / attestation. The sandbox boundary is the trust boundary; anything inside can ask.

## Threat model / trust boundaries

- Everything inside the sandbox is **equally trusted**. We do not try to distinguish "the coding agent" from "a compromised build step that also ran in the sandbox." They both get to ask.
- The **human** is the decision authority. The proxy's job is to render the request faithfully and never forge an approval.
- Consequence: no self-reported agent identity in the payload. If we can't verify it, displaying it is misleading.

## User flow

1. User starts pyloros (sidecar to their devcontainer). User's SSH config has `LocalForward 7777 localhost:7777` (or pyloros is bound to a host-reachable port some other way).
2. User opens `http://localhost:7777/` in their laptop browser. First-time: grants browser notification permission. Page stays pinned.
3. Agent inside sandbox hits a blocked endpoint (or anticipates one). It calls the pyloros approval API with proposed rules + reason.
4. Pyloros queues the request. The open browser page receives an SSE/WebSocket push and fires a native OS notification via the browser's Notification API.
5. User clicks the notification → focuses the tab → sees rule(s), reason, optional triggering URL. Picks a lifetime (session / 1h / 1d / permanent) and approves *or* denies (optionally with a message back to the agent).
6. Pyloros updates the live ruleset (for approve) and the agent's long-polling request returns with the decision.

## API

All endpoints are served by the proxy itself under a **magic hostname**: `https://pyloros.internal/`. The proxy intercepts requests to this host (just as it intercepts everything via MITM) and routes them to the internal API handler instead of forwarding upstream. No separate admin port, no dedicated listener — the sandbox already trusts and reaches the proxy, so this reuses the existing trust/reachability path.

Implications:
- **Works in both connection modes.** In HTTP-proxy mode the sandbox client sends `CONNECT pyloros.internal:443` and the proxy terminates TLS itself instead of dialing upstream. In direct-https mode the client just opens a TLS connection to the proxy and sends SNI `pyloros.internal`. Same handler either way; no new listener needed.
- Any HTTP client that trusts the pyloros CA can hit `https://pyloros.internal/approvals` directly from inside the sandbox.
- The browser dashboard is served at `https://pyloros.internal/` too. For the laptop browser, the user forwards the proxy port with SSH `LocalForward` and points their browser at it (via `/etc/hosts` entry or the direct-https entry point). Cert trust is the same install step as any MITM setup.
- `pyloros.internal` is chosen because `.internal` is a reserved TLD (RFC-scoped for private use) and won't collide with real DNS.

### `POST https://pyloros.internal/approvals`

Request:
```json
{
  "rules": ["GET https://api.foo.com/*"],
  "reason": "need to fetch weather data for the demo",
  "context": {
    "triggered_by": { "method": "GET", "url": "https://api.foo.com/v1/weather" }
  },
  "suggested_ttl": "1h"
}
```

Response `202`:
```json
{ "id": "apr_01J...", "status": "pending" }
```

No agent-identity field. Self-reported strings we can't verify don't belong in the UI.

### `GET https://pyloros.internal/approvals/{id}?wait=60s`

Long-poll. Returns when the decision is made, or when `wait` elapses (then poll again).

Response `200`:
```json
{
  "id": "apr_01J...",
  "status": "approved" | "denied" | "pending",
  "rules_applied": ["GET https://api.foo.com/*"],      // on approve, may differ from proposed if user edited
  "ttl": "1h" | "session" | "permanent",               // on approve
  "message": "rule too broad, scope to /v1/weather"    // on deny, optional
}
```

Long-poll (not streaming, not blocking-forever) because it survives proxy restart, TCP hiccups, and bounded idle connections.

### Browser-facing endpoints (loopback only, not for the agent)

- `GET /` — the approval dashboard HTML.
- `GET https://pyloros.internal/events` — SSE stream of pending/resolved approvals.
- `POST https://pyloros.internal/approvals/{id}/decision` — approve/deny with lifetime + optional message.

## Rule lifetime and storage

- The user picks at approval time, with agent's `suggested_ttl` as the form default. Choices: **session-only** (in-memory, gone at proxy restart) / **1h** / **1d** / **permanent**.
- Permanent approvals go to a separate `approvals.toml` sidecar file, loaded-and-merged with the main config at startup. The user-authored config is **never mutated** by the proxy.
- Timed approvals live in-memory with an expiry timestamp; on expiry, the rule stops matching. Not persisted — a restart drops them.
- Deleting `approvals.toml` revokes everything cleanly.

## Anti-spam

Simple per-minute rate limit on `POST https://pyloros.internal/approvals`. Excess → `429`. A burst triggers a visible warning on the dashboard ("20 approval requests in the last minute"). No shared secret — the sandbox already reaches the proxy, that's the trust boundary.

## Notification channel

v1: **browser Notification API**, triggered by SSE push to the open dashboard tab. Requires the tab to be open; if it's not, approvals just queue until the user comes back (strictly better than today, where the agent stalls).

Future layers, same approval UI:
- **ntfy.sh** push — reaches the phone when user is AFK. The notification body is a link back to the same dashboard URL.
- **Companion desktop app** — wraps the dashboard in a webview and auto-pops on new approvals, no browser tab needed.
- **Web Push + VAPID** — works with tab closed, but reintroduces a third-party push service. Probably skip.

The internal abstraction is a `Notifier` trait with one method (`notify(approval_summary, url)`); each channel is an impl.

## Extensions to think about

These came up during design — not all go into v1, but the design should not preclude them.

### I1 — Deny with message

User can attach a free-text message when denying ("rule too broad, scope to /v1/weather"). Returned to the agent in the long-poll response. Lets the agent self-correct and re-request, rather than silently giving up.

**In v1?** Yes — trivial to add and strictly improves the loop.

### I2 — Automatic redirect probing

Agents don't always know whether a URL redirects. Proposal: the request can include an `example_url` the proxy will fetch (following redirects, up to a cap) before showing the approval. The redirect chain is shown to the user, and the dashboard offers a pre-checked "also allow redirects to these hosts" checkbox.

**In v1?** Probably not — useful but adds outbound fetch responsibility to the approval path, which has security implications (SSRF-adjacent). Defer until v1 is shipped and we see if it's actually needed.

### I3 — Transitive dependency expansion for package managers

Agents installing `npm install foo` know the top-level package but not the dep tree. Proposal: if the proposed rule looks like a package-registry URL (npm, PyPI, rubygems, crates.io, Go modules), pyloros queries the registry for the dep closure and offers the expanded set as additional proposed rules.

**In v1?** No. This is a real scope expansion — the proxy starts doing package-manager-specific metadata fetching. It's a compelling feature but it deserves its own design doc and probably its own SPEC section. Flagging it here so v1's API shape doesn't preclude returning an expanded rule set (the `rules_applied` field in the approval response already supports that).

### I4 — Deduplication / subsumption

If all proposed rules are already matched by the active ruleset, the approval auto-resolves as approved immediately (no notification shown). Pure convenience; prevents approval fatigue when the agent is cautious and asks for things it already has.

**In v1?** Yes — cheap and clearly good. Matching logic reuses the existing `FilterEngine`.

## Open questions

1. **Session-only rules and the Notifier trait** — if the approval is resolved with `session` lifetime, is the "session" the proxy process lifetime, or something narrower (one run of the agent)? Proxy lifetime is simpler; a narrower notion requires the agent to identify its session, which we said we don't trust.

2. **What does the dashboard show for historical approvals?** A simple scrollback of resolved approvals is nice for the user to audit their own past decisions. Pull from the existing audit log rather than a second store.

3. **Do denied approvals get remembered across requests?** We said "not crucial for v1." Leaving unbuilt but not precluded.

4. **Bootstrapping the browser URL** — how does the user know to open `https://pyloros.internal/`? Print it on proxy startup; document in README; maybe auto-open on first blocked request if running under a TTY.
