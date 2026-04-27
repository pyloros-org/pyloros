# Approvals — Design Doc

**Status: implemented (PR #108).** The user-facing spec lives in
[`devdocs/SPEC.md` § Approvals](../SPEC.md). This document retains the design
rationale, the considered alternatives, and the deferred / open work that's
useful when extending the feature but isn't part of the product surface.

If you want to know *what the feature does*, read SPEC. If you want to know
*why it's shaped this way and what was deliberately left out*, read on.

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
- The dashboard has no built-in auth — **bind isolation is the trust boundary** for it. The user is responsible for binding `dashboard_bind` to an address the sandbox cannot reach (loopback on the host, or a host-only IP in a container deployment).

## Why two listeners (agent API vs. dashboard)

The agent and the human are two different audiences with different network reachability:

- The agent is *inside* the sandbox and reaches the proxy listener. It must **not** reach the dashboard.
- The human is *outside* the sandbox and reaches the dashboard. They have no business sending agent-API traffic.

The agent API rides on the existing proxy listeners and is gated by the `pyloros.internal` magic hostname (intercepted via CONNECT-MITM or direct-HTTPS SNI). The hostname doesn't resolve externally; only clients configured to use the proxy can hit it. The dashboard is its own dedicated listener (`dashboard_bind`) that the agent's network namespace can't reach.

A previous draft of this design put the dashboard on the proxy's direct-HTTP listener. That conflated the two audiences in one network reachability surface and was abandoned in favor of separate listeners.

## Notification channel

v1: **browser Notification API**, triggered by SSE push to the open dashboard tab. Requires the tab to be open; if it's not, approvals just queue until the user comes back (strictly better than today, where the agent stalls).

The Notification API technically requires a "secure context," but browsers explicitly treat `http://localhost` and `http://127.0.0.1` as secure contexts for exactly this kind of local-dev scenario (per W3C Secure Contexts). So plain HTTP on the dashboard listener is fine in v1 — no TLS cert needed. If we later want to serve the dashboard over HTTPS (to avoid the scary URL bar, or for Web Push w/ service workers), the proxy can mint a cert for `localhost` signed by its own CA, and the user already trusts that CA.

Future layers, same approval UI:

- **ntfy.sh** push — reaches the phone when user is AFK. The notification body is a link back to the same dashboard URL.
- **Companion desktop app** — wraps the dashboard in a webview and auto-pops on new approvals, no browser tab needed.
- **Web Push + VAPID** — works with tab closed, but reintroduces a third-party push service. Probably skip.

The internal abstraction is a `Notifier` trait with one method (`notify(approval_summary, url)`); each channel is an impl. v1 ships only the SSE-to-browser impl; the trait shape is in place so adding ntfy / a companion app is additive.

## Extensions

These came up during design. v1 ships **I1** and **I4**; **I2** and **I3** are deliberately deferred.

### I1 — Deny with message *(in v1)*

The human attaches a free-text message when denying ("rule too broad, scope to /v1/weather"). Returned to the agent in the long-poll response so the agent can self-correct and re-request, rather than silently giving up.

### I2 — Automatic redirect probing *(deferred)*

Agents don't always know whether a URL redirects. Proposal: the request can include an `example_url` the proxy will fetch (following redirects, up to a cap) before showing the approval. The redirect chain is shown to the user, and the dashboard offers a pre-checked "also allow redirects to these hosts" checkbox.

Useful but adds outbound fetch responsibility to the approval path, with security implications (SSRF-adjacent). Defer until we see if it's actually needed in practice.

#### Why we can't just auto-follow redirects under the originating approval

Tempting shortcut: when an approved request 3xx's, treat the `Location` as covered by the same approval (with hop/protocol caps). Argument is "if we trusted the origin, we trust where it points us." This is wrong in our threat model.

The blocker is **agent-writable origins**. Any approved host where the agent can place content — S3 buckets, gists, the agent's own repo, a pastebin, a comment field that reflects input — is a self-served open redirect. The agent uploads a 302 (or `<meta http-equiv="refresh">`, or HTML+JS) and bounces to anywhere. A narrow approval like `PUT https://my-bucket.s3.amazonaws.com/*` then silently authorizes arbitrary egress. This isn't hypothetical: many real approvals are exactly write-capable origins.

The same risk applies (less acutely) to **classic open-redirect vulns** on benign hosts (`approved.com/redirect?url=evil.com`).

Per-hop approval (proxy intercepts the 3xx, creates a fresh pending approval for the redirect target with chain context) addresses this but is **not "no new UX"** as I initially claimed: today the proxy returns 451 immediately and the agent uses the approval API out-of-band. Per-hop intercept means either holding the client connection during human review (new behavior, breaks proxy/HTTP semantics for clients that aren't approval-aware) or returning 451 + trusting the client to re-request — which is what already happens for the first hop, so no proxy work is actually needed unless we want transparency for non-cooperating clients.

If we add explicit redirect support, the safer shape is: the agent declares `follow_redirects: true|false` in the approval request, defaulting to `false` for write methods (`POST`/`PUT`/`PATCH`/`DELETE`) and surfacing the choice in the approval UI as a separately-visible bit. The human, not the proxy, decides whether redirect-following is safe for this origin.

#### Rule-writing guidance (general)

Open-redirect-as-egress generalizes beyond redirects: **any approved origin that reflects agent-controlled content can be used to launder requests through the approval boundary** (e.g. an approved API that returns agent-supplied URLs in JSON, which the agent then "follows" — same problem one indirection up). When writing or approving rules, the question is not just "do I trust this host" but "can the agent influence what this host serves back to it." Write-capable origins, reflective endpoints, and user-content surfaces deserve narrower scopes (specific paths, no redirect-following, read-only methods where possible) than read-only public APIs.

### I3 — Transitive dependency expansion for package managers *(deferred)*

Agents installing `npm install foo` know the top-level package but not the dep tree. Proposal: if the proposed rule looks like a package-registry URL (npm, PyPI, rubygems, crates.io, Go modules), pyloros queries the registry for the dep closure and offers the expanded set as additional proposed rules.

Real scope expansion — the proxy starts doing package-manager-specific metadata fetching. It's a compelling feature but it deserves its own design doc and probably its own SPEC section. Flagging it here so v1's API shape doesn't preclude returning an expanded rule set (the `rules_applied` field already supports that, since the human may edit it before approving).

### I4 — Deduplication / subsumption *(in v1)*

If all proposed rules are already matched by the active ruleset, the approval auto-resolves as approved immediately (no notification shown). Pure convenience; prevents approval fatigue when the agent is cautious and asks for things it already has.

Implementation: synthesize probe URLs from each proposed rule and run them through the existing `FilterEngine`. Plain method rules need one probe; git rules probe each direction (`/info/refs?service=git-{upload,receive}-pack` AND `/git-{upload,receive}-pack`) so a partial method-rule doesn't falsely subsume a `git=fetch`. Wildcard hosts → probe synthesis bails → not subsumed (ask the human). See `src/approvals/dedup.rs`.

## Open questions (post-v1)

1. **Session-only rules** — currently "session" means the proxy process lifetime. A narrower notion (one run of the agent) would require the agent to identify its session, which we said we don't trust. Live with the wider scope unless a real problem appears.

2. **Historical approvals view** — a scrollback of resolved approvals would let the user audit their own past decisions. Probably pull from the existing audit log rather than maintaining a second store. Not in v1.

3. **Persistent denials** — denied approvals don't persist across requests today; the agent could re-request the same rule (with the same message guidance) and the human would see it again. Was deemed not crucial for v1; revisit if approval fatigue appears.

4. **Specificity collapses for closure-shaped requests.** Surfaced while testing `npm install`. The current contract pushes the agent to "request specific packages, not host wildcards" — fine for a top-level package, but a real install pulls a transitive closure (express ≈ 50 packages across 3+ layers). The agent ends up POSTing a 50-rule batch where every rule is structurally `GET https://registry.npmjs.org/<name>` + `/<name>/*`. The human approver cannot meaningfully verify whether each `<name>` is actually in express's closure vs. something the agent hallucinated or was tricked into adding (typosquats, a poisoned upstream metadata response, etc.) — the list is too long to scan and the names are unfamiliar. The "specificity" guardrail degrades to rubber-stamping. Same shape will appear for `cargo`, `pip`, `apt`, container pulls, anything closure-typed.

   Possible directions, none implemented:

   a. **Server-side closure resolution.** The approval payload becomes a single root spec (`npm:express@5`); the proxy/dashboard expands the closure itself by querying a trusted resolver (registry, lockfile generator, deps.dev) and presents the human with one decision: "approve the closure of express@5 as resolved at <timestamp>", with the full URL list available to inspect but not the unit of approval. Trust shifts from "agent told me these names" to "registry told me these names." (This is essentially I3 with the closure source moved server-side.)

   b. **Lockfile-anchored approval.** User commits `package-lock.json` / `Cargo.lock` / equivalent into the repo; the agent's request is "fetch the URLs in this lockfile, integrity-checked against its hashes." The approver verifies the lockfile once (or trusts the repo); the proxy enforces "URL must appear in the lockfile and content must match its hash." The human is not asked to verify package names at all.

   c. **Bounded host-wide rules with post-hoc audit.** Allow `* https://registry.npmjs.org/*` as a single approval, but require structured logging of every package + version + hash actually fetched, surfaced as a post-install diff for the human to review. Trust boundary moves from "what URLs" to "what code ended up on disk."

   d. **Schema-constrained batches.** Even without (a)-(c), the proxy could enforce that a single approval batch is "all rules must be `<scheme> <host>/<exactname>` or `<host>/<exactname>/*` for one host, ≤ N rules". This doesn't fix verifiability but caps blast radius: no smuggled second host, no path wildcards, bounded size.

   (a) and (b) are the substantive fixes; (c) and (d) are mitigations. Pick a direction before v2 of the approval flow ships, because the agent-side "enumerate + batch" workaround we have today actively trains the human to approve unreadable lists.
