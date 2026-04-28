# Pyloros Spec

A default-deny allowlist-based HTTPS filtering proxy for controlling AI agent network access.

## Purpose of this document

It is a declarative specification of what we want this product to be: features, behavior, technical choices (libraries, protocols), configuration format, and developer experience (CI/CD, tooling, workflow). It describes *what* and *why*, not *how* — implementation details like internal APIs, struct names, or macro usage belong in code and code comments, not here. Code and infrastructure should ultimately be maintained to match the requirements here. When we want to change something, we first modify the SPEC.

## Deployment Model

The intended deployment is one proxy per VM/container running an AI agent. All outbound traffic from the agent is routed through the proxy via `HTTP_PROXY`/`HTTPS_PROXY` environment variables, giving the proxy full visibility and control over the agent's network access.

## Features

### Core
- Explicit HTTP proxy mode (clients configured via `HTTP_PROXY`/`HTTPS_PROXY` env vars)
- MITM TLS interception for HTTPS traffic via CONNECT tunnels
- Plain HTTP forwarding for non-CONNECT proxy requests (e.g. `http://` URLs used by apt-get)
- Hop-by-hop header stripping per RFC 7230 for forwarded HTTP requests
- CONNECT restricted to port 443 (non-443 CONNECT requests are blocked)
- Allowlist rule engine: requests must match at least one rule to be allowed; everything else is blocked with HTTP 451
- **Default-deny for unverifiable restrictions**: when a rule requires fine-grained inspection (e.g. branch-level body inspection for git push) but the request arrives on a code path that cannot perform that inspection (e.g. plain HTTP instead of HTTPS CONNECT), the request is blocked rather than silently allowed. If we can't verify a restriction, we deny.
- TOML configuration file

### Rule Matching
- Rules specify: method, URL pattern, optional `websocket = true` flag
- `*` wildcard matches any character sequence (including across segments) in host, path, and query
- Method `*` matches any HTTP method
- Example: `https://*.github.com/api/*` matches `https://foo.github.com/api/v1/repos`

### Redirect Following

Many allowed destinations (GitHub release assets, CDNs, package mirrors) respond with a 3xx redirect to a freshly-signed, short-lived URL on a different host that cannot realistically be listed in config. A rule may opt in to following redirects:

```toml
[[rules]]
method = "GET"
url = "https://github.com/neovim/neovim/releases/download/*"
allow_redirects = ["https://release-assets.githubusercontent.com/*"]

# Accept any redirect target
[[rules]]
method = "GET"
url = "https://example.com/download/*"
allow_redirects = ["*"]
```

Semantics:
- `allow_redirects` is a list of URL patterns (same wildcard syntax as `url`). The bare string `"*"` is a shorthand for "match any URL" (accepted here but not in other pattern fields, which require a scheme). Omitted or empty = redirects are not followed (follow-up request will be blocked as usual).
- When a rule-matched request produces a response with a 3xx status and a `Location` header, the Location URL is resolved against the request URL (absolute or relative) and checked against the rule's `allow_redirects` patterns. On match, the exact resolved URL is added to a time-limited global whitelist. Any subsequent request matching that URL exactly is allowed regardless of other rules.
- Chains are followed recursively. If a whitelisted-by-redirect request itself returns a 3xx, the new Location is checked against the **original** rule's patterns (which travel with the whitelist entry).
- The whitelist TTL is controlled by `redirect_whitelist_ttl_secs` under `[proxy]` (default **60**). The whitelist is global — keying per client is not feasible when `direct_https_bind` is used.
- Applies to both plain HTTP and MITM'd HTTPS (all HTTPS in pyloros is MITM'd).

Logging:
- Normal logs distinguish redirect-whitelisted allowances from direct rule matches.
- Audit log: follow-up requests allowed via the whitelist record `reason = "redirect_whitelisted"` (as opposed to `"rule_matched"`).

#### Known limitation: client-cached redirects can outlive the whitelist

3xx responses are cacheable per RFC 9111. A client may cache the original
redirect (serving future requests to the origin URL from its own cache
without re-hitting the proxy) and then attempt the cached target URL later,
after our whitelist entry has expired. The proxy will block that follow-up.

- 301 and 308 are **heuristically cacheable** — a cache may store them
  effectively indefinitely when no `Cache-Control`/`Expires` is present.
  Browsers commonly do (hours to days).
- 302/303/307 are heuristically cacheable too, but most caches only store
  them when explicit freshness headers are provided.

The signed-URL case the feature is designed for is less exposed in practice:
redirect responses in that flow typically carry `Cache-Control: no-store`
and the signed target URL itself expires in minutes. But the race is real
for rule authors relying on vanilla 301/308.

A principled fix (future work): parse `Cache-Control: max-age` / `Expires`
on the 3xx response and size the whitelist entry's TTL to match (capped at
the proxy's configured maximum, with a floor). For 301/308 without explicit
freshness headers, strip or rewrite the caching headers so the client can't
outlive the whitelist entry. A simpler alternative is to always force
`Cache-Control: no-store` on any 3xx we whitelist.

### Git Rules

Git-specific rules provide a high-level way to control git smart HTTP operations (clone, fetch, push) without requiring users to understand the underlying protocol endpoints.

A rule has **either** `method` (HTTP rule) **or** `git` (git rule), never both. Having both is a config validation error. `websocket = true` and `git` are mutually exclusive.

```toml
# Allow clone/fetch from any repo in myorg
[[rules]]
git = "fetch"
url = "https://github.com/myorg/*"

# Allow push only to a specific repo, only to feature branches
[[rules]]
git = "push"
url = "https://github.com/myorg/deploy-tools"
branches = ["feature/*", "fix/*"]

# Allow all git operations to any github.com repo
[[rules]]
git = "*"
url = "https://github.com/*"
```

#### `git` field values

| Value   | Operations allowed   |
|---------|---------------------|
| `fetch` | clone, fetch, pull  |
| `push`  | push                |
| `*`     | all                 |

The `url` is the repo base URL (what you'd pass to `git clone`). The trailing `.git` suffix is optional: rules match both `repo` and `repo.git` request forms regardless of which form was written in the rule, so `url = "https://github.com/org/repo"` and `url = "https://github.com/org/repo.git"` are equivalent.

#### Branch restriction

The optional `branches` field restricts which refs a push can target. It is only valid on `git = "push"` or `git = "*"` rules; using it with `git = "fetch"` is a config error.

- Bare patterns like `feature/*` match against `refs/heads/feature/*`.
- Patterns starting with `refs/` are matched literally (escape hatch for tags, notes, etc.).
- Patterns prefixed with `!` are **deny** patterns — they exclude matching refs.
- Omitting `branches` means any ref is allowed.
- If a push updates multiple refs and **any** ref is disallowed, the **entire push** is blocked.
- When a push is blocked by branch restrictions, the proxy returns a proper git `receive-pack` response (HTTP 200 with `report-status` and sideband error messages) instead of HTTP 451. This allows git clients to display clear per-ref errors like `! [remote rejected] main -> main (blocked by proxy policy)`.

**Deny pattern semantics (`!` prefix):**

- Patterns without `!` are allow patterns (existing behavior).
- Patterns with `!` prefix are deny patterns — the `!` is stripped before matching.
- **Deny wins**: if a ref matches both an allow and a deny pattern, it is blocked.
- If only deny patterns are present (no explicit allow patterns), there is an implicit allow-all (`*`). So `["!main"]` means "all branches except main".
- A bare `!` (empty pattern after stripping the prefix) is a config validation error.

**Examples:**

```toml
# Allow push to any branch except main and release/*
[[rules]]
git = "push"
url = "https://github.com/myorg/*"
branches = ["*", "!main", "!release/*"]

# Allow push only to feature/* but not feature/dangerous
[[rules]]
git = "push"
url = "https://github.com/myorg/deploy-tools"
branches = ["feature/*", "!feature/dangerous"]

# Shorthand: allow all except main (implicit allow-all)
[[rules]]
git = "push"
url = "https://github.com/myorg/repo"
branches = ["!main"]
```

See `INTERNALS.md` for implementation details (smart HTTP endpoint mapping, pkt-line inspection, compilation model).

#### Git-LFS support

Git-LFS uses a separate HTTP endpoint (`POST {repo}/info/lfs/objects/batch`) to negotiate large file transfers. Git rules automatically include this endpoint so that LFS operations work without additional manual rules.

- `git = "fetch"` allows LFS **download** operations (batch requests with `"operation": "download"`)
- `git = "push"` allows LFS **upload** operations (batch requests with `"operation": "upload"`)
- `git = "*"` allows both download and upload
- The proxy inspects the JSON body of LFS batch requests to verify the `operation` field matches what the rule allows
- **Branch restrictions do not apply** to LFS. LFS blobs are content-addressed; the actual ref update goes through `git-receive-pack` which is already branch-checked
- **Plain HTTP is blocked** for LFS batch requests (same default-deny principle as branch checks — body inspection requires HTTPS)
- **Transfer URLs (dynamic whitelisting)**: LFS batch responses contain transfer URLs (often on external hosts like `lfs.github.com` or `github-cloud.s3.amazonaws.com`) for the actual object upload/download and post-upload verify callbacks. The proxy parses the JSON body of successful batch responses and inserts each `objects[*].actions.{download,upload,verify}.href` into a short-lived dynamic whitelist, pinned to the action's HTTP method (`download`→GET, `upload`→PUT, `verify`→POST).
  - Activation is automatic for any rule with `git = "fetch" | "push" | "*"`. Whitelisted actions are filtered by the rule's allowed LFS operations: a fetch-only rule whitelists `download` actions; a push-only rule whitelists `upload` and `verify`; `*` whitelists all three.
  - TTL: per-action `expires_at` (RFC 3339) or `expires_in` (seconds) from the response is used when present, clamped to `[60s, 3600s]`. Otherwise falls back to the existing `proxy.redirect_whitelist_ttl_secs` setting (default 60s).
  - Body size for inspection is capped at 10 MiB; oversized batch responses are forwarded unchanged with no whitelisting (warn-logged).
  - `Content-Encoding: gzip`/`deflate` is decoded for parsing; the original (compressed) bytes are forwarded unchanged to the client. Other encodings (e.g. `br`, `zstd`) are not decoded — the response forwards through but no actions are whitelisted.
  - Trust model is identical to redirect whitelisting: the upstream is MITM-inspected and authenticated, so we trust its instructions about where the client will go next.
  - The whitelist is method-pinned: a leaked `verify` URL cannot be used for `GET` or `PUT`.

#### Git-LFS Locks API

Git-LFS has a [locks API](https://github.com/git-lfs/git-lfs/blob/main/docs/api/locking.md) for file-level locking coordination. Git rules automatically generate rules for the lock endpoints so that `git lfs locks` and lock verification work without additional manual rules.

Lock endpoints are plain pass-through rules (no body inspection needed):

| Method | Path | `fetch` | `push` | `*` |
|--------|------|---------|--------|-----|
| GET | `{repo}/info/lfs/locks` | yes | yes | yes |
| POST | `{repo}/info/lfs/locks` | no | yes | yes |
| POST | `{repo}/info/lfs/locks/verify` | yes | yes | yes |
| POST | `{repo}/info/lfs/locks/*/unlock` | no | yes | yes |

- `git = "push"` includes all four endpoints (create, list, verify, unlock)
- `git = "fetch"` includes list (GET) and verify (POST) only — these are informational and prevent the git-lfs client from warning "Remote does not support the Git LFS locking API"
- `git = "*"` includes all four (superset of push)

### Protocol Support
- HTTP/1.1
- HTTP/2
- WebSocket (upgrade detection + bidirectional frame forwarding; upstream connections use HTTP/1.1 ALPN only, since the Upgrade mechanism is not available in HTTP/2)

### Certificate Management
- User-provided or auto-generated CA certificate/key
- Per-host certificate generation with in-memory LRU cache (1000 entries, 12h TTL)
- CLI command to generate CA cert/key pair

### Direct HTTPS Mode

In addition to the standard explicit HTTP proxy mode, pyloros supports a **direct HTTPS mode** where
clients connect directly to the proxy's TLS listener without using proxy protocol. This is useful in
sandboxed environments where programs don't respect `HTTP_PROXY` environment variables.

**How it works:**
1. The proxy listens on an additional address (e.g. `127.0.0.12:443`) for raw TLS connections
2. When a client connects, the proxy extracts the target hostname from TLS SNI (Server Name Indication)
3. The proxy generates/caches a MITM certificate for that hostname (reusing the same CA)
4. Once TLS is established, HTTP requests are handled identically to CONNECT tunnel requests — same
   filtering, credential injection, and upstream forwarding

**Configuration:**
```toml
[proxy]
direct_https_bind = "127.0.0.12:443"  # optional, enables direct HTTPS mode
```

The `direct_https_bind` field is optional. When set, the proxy spawns an additional TLS listener alongside
the standard proxy listener. Both can run simultaneously. The standard proxy listener handles `HTTP_PROXY`
traffic; the direct HTTPS listener handles transparent TLS interception.

**Integration with `/etc/hosts`:** In a bwrap sandbox, an `/etc/hosts` file maps allowed hostnames to
the loopback address where pyloros listens. Programs connect to what they think is the real server, but
traffic is routed to the proxy for filtering and forwarding.

The `generate-hosts` CLI subcommand extracts literal hostnames from config rules and outputs them in
`/etc/hosts` format for this purpose.

### Direct HTTP Mode

A plain-HTTP counterpart to direct-HTTPS, used when a sandboxed program must fetch plain `http://`
URLs (e.g. `apt` pulling `.deb` packages from a mirror) and does not honour `HTTP_PROXY`.

**How it works:**
1. The proxy listens on an additional address (e.g. `0.0.0.0:80`) for plain-HTTP connections.
2. When a request arrives, the target hostname is read from the `Host` header (no SNI since no TLS).
3. The path and query come from the request URI, which is origin-form (`GET /path HTTP/1.1`).
4. Filtering and audit logging mirror the plain-HTTP path used by the regular proxy listener.
   Rules that require body inspection (branch restrictions, LFS operation checks) still block —
   plain HTTP is not trusted for body-gated rules.
5. Credentials are **not** injected (consistent with the plain-HTTP handling elsewhere — see
   "Credential Injection"). Direct-HTTP is for allowing plain traffic through a policy gate, not
   for adding secrets to it.

**Configuration:**
```toml
[proxy]
direct_http_bind = "0.0.0.0:80"  # optional, enables direct HTTP mode
```

The same `/etc/hosts` / wildcard-DNS setup used for direct-HTTPS works for direct-HTTP: a single
IP can carry both ports simultaneously.

### Approvals

Opt-in feature: a coding agent running inside the sandbox can request permission from the human
to add allowlist rules at runtime. The human approves (with a lifetime) or denies (optionally
with a message) via a browser dashboard. Approved rules enter the live ruleset without
restarting the proxy.

Enabled by adding an `[approvals]` section to the config:

```toml
[approvals]
permanent_rules_file = "/path/to/approvals.toml"  # required: where permanent rules persist
dashboard_bind = "127.0.0.1:7778"         # required: dashboard listener address
```

Without this section, the agent API returns 404 and no dashboard listener is bound.

**Two endpoints:**

- **Agent API at `https://pyloros.internal/`.** Served on the proxy's existing listeners (CONNECT
  MITM or direct-HTTPS SNI). Only reachable through the proxy; the hostname does not resolve
  externally. Endpoints:
  - `POST /approvals` — body: `{rules, reason?, context?, suggested_ttl?}`. Returns `202` with
    a pending id, or `200` with `status:"approved"` immediately if all proposed rules are
    already covered by the current ruleset. Returns `429` on rate limit (60 POSTs/minute),
    `400` on a malformed/inconsistent rule.
  - `GET /approvals/{id}?wait=60s` — long-poll the decision. Returns
    `{status, rules_applied?, ttl?, message?}`.

  **Rules** are JSON objects with the same shape as a `[[rules]]` entry in the TOML config
  (`{method, url, websocket?, git?, branches?, allow_redirects?, log_body?}`); for example
  `{"method":"GET","url":"https://api.foo.com/*"}` for a plain HTTP rule, or
  `{"git":"fetch","url":"https://github.com/foo/bar.git"}` for a git fetch (which expands to
  the full smart-HTTP + LFS endpoint set, just like in the TOML config).

- **Dashboard at `dashboard_bind`.** Its own dedicated listener, plain HTTP. Endpoints:
  - `GET /` — HTML page listing pending approvals; fires browser notifications via the
    Notification API when new approvals arrive.
  - `GET /events` — Server-Sent Events stream of pending/resolved approval events.
  - `POST /approvals/{id}/decision` — body: `{action, rules_applied?, ttl?, message?}`.

**Lifetimes** (chosen at decision time): `session`, `1h`, `1d`, `permanent`. The dashboard form
defaults to `permanent` — in steady-state projects nearly every approval is something the user
will need every time, and forcing them to flip the dropdown for the common case is the wrong
default. The agent's `suggested_ttl` overrides the form default if present. Permanent rules go
to the configured `permanent_rules_file`; the main config is never modified. Deleting the permanent-rules file
revokes all permanent rules.

**Deduplication.** If the proposed rules are already covered by the active ruleset, the POST
returns `200 approved` immediately, with no pending state and no dashboard notification.

**Deny with message.** When denying, the human may include a free-text `message` which is
returned to the agent in the long-poll response, giving the agent a chance to refine and
re-request.

**Security model:**

- Agent API: the sandbox boundary is the trust boundary. Anything inside the sandbox that can
  reach the proxy can request approvals. A per-minute rate limit mitigates approval-fatigue
  attacks.
- Dashboard: **bind isolation is the trust boundary.** The dashboard has no built-in
  authentication. The user MUST bind `dashboard_bind` to an address the sandbox cannot reach.
  In a typical docker-compose setup this means binding to a host loopback or external-only IP,
  NOT to a network shared with the sandbox container. Plain HTTP is intentional: the dashboard
  is meant to be reached over a loopback or SSH-tunneled connection, where `http://localhost`
  is a secure context for browser APIs.

**Non-goals for v1:** automatic redirect-chain probing, transitive package-dependency expansion
for package-registry URLs, and deny-with-memory. These are documented in `devdocs/design/approvals.md`
as future extensions.

### CLI

subcommands:

- `run --config config.toml` — start proxy
- `generate-ca --out ./certs/` — generate CA cert/key
- `validate-config --config config.toml` — validate config file
- `generate-hosts --config config.toml --ip 127.0.0.12` — generate `/etc/hosts` entries for direct HTTPS mode

### Permissive Mode

When deploying pyloros for the first time, operators may not know what rules they need. Permissive mode provides a "learning" phase where unmatched requests are allowed through but logged distinctly, so operators can discover traffic patterns and build rules from the audit log. Named after SELinux's permissive mode.

- Enabled via `permissive = true` in `[proxy]` (default: `false`)
- Only converts `FilterResult::Blocked` (no matching rule) to allow-through
- All other block reasons (branch restriction, LFS check, body-inspection-requires-HTTPS, non-HTTPS CONNECT, auth failure) still block — those represent matched rules with failed constraints
- Permitted requests emit a distinct audit event `"request_permitted"` with `decision: "allowed"`, `reason: "no_matching_rule"` — easy to grep, distinct from `"request_allowed"` (which means a rule matched)
- Permitted requests ALWAYS emit a tracing log line (regardless of `log_allowed_requests`/`log_blocked_requests`) since the point is visibility
- Requests matching an explicit rule are logged normally as `"request_allowed"`

### Configuration Live-Reload

When a config file is provided (`--config`), the proxy watches it for changes using OS-native
file system notifications (inotify on Linux, kqueue on macOS) and automatically reloads on
modification. On Unix systems, sending `SIGHUP` to the proxy process also triggers a reload.

**Reloadable settings** (take effect for new connections after reload):
- `[[rules]]` — filter rules
- `[[credentials]]` — credential injection entries
- `[proxy]` `auth_username` / `auth_password` — proxy authentication (re-resolves `${ENV_VAR}`)
- `[proxy]` `permissive` — permissive mode toggle
- `[logging]` `log_requests` — request logging flags
- `[logging]` `audit_log` — audit log file path

**Non-reloadable settings** (require restart; changing them logs a warning):
- `[proxy]` `bind_address`
- `[proxy]` `ca_cert` / `ca_key`

**Behavior:**
- Invalid config files are rejected; the proxy continues with the previous valid config
- Existing connections are not affected; only new connections use the new config
- File changes are debounced (200ms) to handle editor save patterns (write-to-temp + rename)
- Successful reloads are logged at info level with rule/credential counts
- Failed reloads are logged at error level with the parse/compile failure message

### Signal Handling

The proxy shuts down cleanly on both `SIGINT` (Ctrl+C) and `SIGTERM`. On receiving either signal, the proxy logs a shutdown message and exits with code 0. `SIGTERM` handling is Unix-only (on non-Unix platforms, only Ctrl+C is supported).

### Logging
- Configurable log level (error/warn/info/debug/trace)
- Separate control over logging of allowed and blocked requests (e.g., log only blocked to reduce noise, or only allowed for auditing)
- Error messages for failed upstream requests must include the request method and URL for diagnostics

#### TLS Key Logging
When the `SSLKEYLOGFILE` environment variable is set to a writable path, pyloros writes TLS session secrets in NSS Key Log Format for both legs of every MITM connection (client↔proxy and proxy↔upstream). Load the file into Wireshark (Preferences → Protocols → TLS → (Pre)-Master-Secret log filename) to decrypt captures. Unset by default; no configuration required. Intended for debugging — do not enable in production.

### Audit Log

An optional structured audit log records every request decision as a JSON object per line (JSONL) in a dedicated file. This is separate from the human-readable tracing output and designed for compliance, SIEM integration, and post-hoc analysis.

- Disabled by default; enabled via `audit_log = "/path/to/file.jsonl"` in `[logging]`
- Every proxied request produces exactly one audit entry
- Entries are emitted at the decision point (before forwarding), so all needed info is available
- Audit write errors are logged via tracing but never fail the request
- No built-in log rotation — use external tools (logrotate, etc.)

Each audit entry contains:
- `timestamp` — ISO 8601 / RFC 3339 UTC timestamp
- `event` — one of `request_allowed`, `request_blocked`, `auth_failed`
- `method` — HTTP method
- `url` — full request URL
- `host` — target hostname
- `scheme` — `http` or `https`
- `protocol` — `http` or `https` (transport-level)
- `decision` — `allowed` or `blocked`
- `reason` — why the decision was made: `rule_matched`, `no_matching_rule`, `body_inspection_requires_https`, `branch_restriction`, `lfs_operation_not_allowed`, `non_https_connect`, `auth_failed`, `redirect_whitelisted`, `lfs_action_whitelisted`
- `credential` (optional) — `{ "type": "header"|"aws-sigv4", "url_pattern": "..." }` for injected credentials
- `git` (optional) — `{ "blocked_refs": ["refs/heads/main"] }` when branch restrictions apply

Optional fields are omitted when not applicable.

#### Body Logging

Rules can opt in to capturing request and response bodies in the audit log. This is useful for traffic inspection — e.g. logging GraphQL queries to develop tighter filter rules.

- Enabled per-rule via `log_body = true` (default false). Valid on both HTTP and git rules.
- When a rule with `log_body = true` matches and the request is **allowed**, both request and response bodies are captured and included in the audit entry.
- Blocked requests do not log bodies (there is no response body, and the request body may not have been received).
- Global size limit: `max_body_log_size` in `[logging]` (default 1 MB / 1,048,576 bytes). Bodies exceeding this limit are truncated.
- Body encoding: UTF-8 if valid; otherwise base64-encoded.
- Audit entries with body logging are emitted **after** the response is received (deferred from the normal pre-forward emission point).

Additional audit entry fields when body logging is active:
- `request_body` — captured request body (string)
- `request_body_encoding` (optional) — `"base64"` if the body is not valid UTF-8; absent means UTF-8
- `response_body` — captured response body (string)
- `response_body_encoding` (optional) — same encoding convention
- `body_truncated` (optional) — `true` if either body was truncated to `max_body_log_size`

Example rule:
```toml
[[rules]]
method = "*"
url = "https://api.example.com/graphql"
log_body = true
```

### Proxy Authentication

The proxy can require clients to authenticate before processing any requests. This prevents unauthorized network entities from using the proxy's credential injection and URL allowlisting capabilities — critical when the proxy is reachable over a network (e.g. Docker internal networks where other containers could connect).

- Authentication uses the HTTP Basic scheme via the `Proxy-Authorization` header (RFC 7235)
- When enabled, unauthenticated or incorrectly authenticated requests receive HTTP `407 Proxy Authentication Required` with a `Proxy-Authenticate: Basic realm="pyloros"` header
- For CONNECT tunnels, authentication is checked on the CONNECT request before the tunnel is established
- For plain HTTP proxy requests, authentication is checked on each request
- Configured via `auth_username` and `auth_password` fields in `[proxy]` — both must be present, or both absent
- `auth_password` supports `${ENV_VAR}` placeholders, resolved at startup (same mechanism as credential injection values)
- When auth is not configured, the proxy accepts all connections (backward compatible)
- Failed auth attempts are logged at warn level (client IP, username if provided) but never log the submitted password
- The `validate-config` command reports whether auth is enabled (never prints the password)

**Client configuration:** Most HTTP clients support proxy auth via embedded credentials in the proxy URL:
```
HTTP_PROXY=http://agent:secretpass@proxy:8080
HTTPS_PROXY=http://agent:secretpass@proxy:8080
```
This works with curl, git, npm, pip, and Docker — no client-side code changes needed.

### Credential Injection
The proxy can inject credentials (API keys, tokens) into outgoing requests so the agent never sees real secrets, preventing credential exfiltration.

- Credentials are configured in `[[credentials]]` sections in the config file
- Each credential has a `type` field: `"header"` (default if omitted) or `"aws-sigv4"`
- All string values support `${ENV_VAR}` placeholders resolved at startup from environment variables
- Credentials are **not** injected for plain HTTP requests (only HTTPS CONNECT tunnel)
- The `validate-config` command displays credential count, types, and URL patterns (never secret values)
- Credential secret values are never logged; only the type and match status are logged at debug level

#### Header credentials (type = "header")

Simple header injection/replacement — the original credential type.

- Each credential specifies a URL pattern, a header name, and a header value
- At request time, if a request URL matches, the proxy injects/overwrites the specified header before forwarding upstream
- If multiple credentials match the same request and set the same header, last match wins (config file order)
- Multiple credentials matching different headers on the same request all get injected

#### AWS SigV4 credentials (type = "aws-sigv4")

Re-signs requests with real AWS credentials using AWS Signature Version 4. This allows AI agents to use fake AWS credentials while the proxy transparently re-signs with real ones.

- Each credential specifies a URL pattern, `access_key_id`, `secret_access_key`, and optionally `session_token`
- At request time, if a request URL matches, the proxy:
  1. Parses the agent's existing `Authorization` header to extract the region and service from the credential scope
  2. Strips old AWS auth headers (`Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`, `X-Amz-Security-Token`)
  3. Re-signs the request with the real credentials using SigV4
  4. Sets the new `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`, and optionally `X-Amz-Security-Token` headers
- The request body is fully buffered for signing (required by SigV4 which hashes the body)
- If the original request has no parseable `Authorization` header (no region/service), the credential is skipped

#### Local credential verification

Every credential entry must have a corresponding **local credential** — a substitute credential known to the sandboxed agent but different from the real one. The proxy verifies the local credential before injecting the real one. This prevents credential exfiltration by unauthorized parties who may have network access to the proxy.

- Every `[[credentials]]` entry must specify a local credential; config validation rejects entries without one
- On mismatch (wrong or missing local credential), the proxy returns **403 Forbidden** and logs an audit entry with reason `local_credential_mismatch`
- Verification happens after the filter allows the request but before injection/forwarding

**Two sources for local credentials:**

1. **Environment variable** — the local credential value comes from an env var, like the real credential:
   - Header type: `local_value = "${INSIDE_KEY}"`
   - SigV4 type: `local_access_key_id = "${INSIDE_AWS_KEY}"` + `local_secret_access_key = "${INSIDE_AWS_SECRET}"`

2. **Generated** — the proxy generates a random local credential at startup and writes it to a secrets env file:
   - `local_generated = true` on any credential type
   - The proxy writes all generated values to `generated_secrets_file` (configured in `[proxy]`) in `KEY=value` format
   - Default env var names are inferred from the `${VAR}` reference in the real credential field (e.g., `value = "${ANTHROPIC_API_KEY}"` → env name `ANTHROPIC_API_KEY`). When the real field is a literal (no `${VAR}`), config validation requires the explicit `local_env_name` / `local_access_key_id_env_name` / `local_secret_access_key_env_name` field — there is **no** fallback to header names or AWS env-var names, since header names are not valid POSIX identifiers and the inferred name is part of the contract with the sandbox.
   - Override with `local_env_name` (header) or `local_access_key_id_env_name`/`local_secret_access_key_env_name` (SigV4)
   - The secrets file is written atomically with 0600 permissions (Unix); existing values are reused across proxy restarts and config reloads (matched by env-var name) so a long-lived sandbox keeps working without re-sourcing the file. Reloads also drop entries for credentials no longer in the config.

**Value templates:** the real `value` (header) and `access_key_id` / `secret_access_key` (SigV4) fields accept at most one `${VAR}` placeholder, in the form `prefix${VAR}suffix`. Multiple placeholders are rejected — the proxy needs the literal prefix/suffix to verify the agent's header.

**Verification rules:**
- Header credentials: when the real value is `prefix${VAR}suffix`, the incoming header must start with `prefix`, end with `suffix`, and the middle must equal the local secret. For `value = "Bearer ${TOKEN}"`, the agent sends `Authorization: Bearer <local-token>` and the proxy strips the `Bearer ` prefix before comparing. For literal real values (no `${VAR}`), the entire header value must match the local secret exactly.
- SigV4 credentials: the proxy performs full SigV4 signature verification using the local `access_key_id` and `secret_access_key`, ensuring the agent actually possesses the local secret key (not just the key ID)
- On mismatch the audit entry includes the failing credential's `type` and `url_pattern` so operators can identify which rule the sandbox failed against.

**Generated value formats:**
- Header: 32-byte random hex string (64 characters)
- SigV4 access_key_id: `AKIA` + 16 alphanumeric characters
- SigV4 secret_access_key: 40-character base64 string

## Technical Decisions

- Explicit HTTP proxy (no iptables)
- MITM with CA for HTTPS inspection
- Tokio async runtime
- rustls + rcgen for TLS (pure Rust, no OpenSSL) — see `INTERNALS.md` for evaluation
- Upstream TLS root CAs: `webpki-roots` (Mozilla bundle) + `rustls-native-certs` (OS certificate store). The `upstream_tls_ca` config option overrides both (for testing with self-signed upstreams).
- TOML config
- `*` wildcard = multi-segment match
- HTTP 451 for blocked requests
- In-memory LRU cert cache
- clap (derive) CLI
- hyper for HTTP

## Configuration Format

The `bind_address` field accepts either a TCP socket address (`host:port`) or a Unix domain socket
path (any value containing `/`). When a Unix path is given, the proxy removes any stale socket file
before binding. This enables communication via bind-mounted Unix sockets in sandboxed environments
(see Bubblewrap Sandbox below).

```toml
[proxy]
bind_address = "127.0.0.1:8080"   # TCP (default)
# bind_address = "/tmp/pyloros.sock" # Unix domain socket
ca_cert = "/path/to/ca.crt"
ca_key = "/path/to/ca.key"
# Optional: allow unmatched requests through (learning mode, default false)
# permissive = true
# Optional: require proxy authentication (both fields required if either is set)
# auth_username = "agent"
# auth_password = "${PROXY_PASSWORD}"
# Optional: override upstream port for all CONNECT forwards (testing only)
# upstream_override_port = 9443
# Optional: PEM CA cert to trust for upstream TLS (testing only)
# upstream_tls_ca = "/path/to/upstream-ca.crt"
# Optional: path to write generated local credentials as KEY=value env file
# Required if any credential uses local_generated = true
# generated_secrets_file = "/run/pyloros/secrets.env"

[logging]
level = "info"
# log_requests accepts a bool (backward compat) or a table:
#   log_requests = true              # both allowed + blocked
#   log_requests = false             # neither
#   log_requests = { allowed = true, blocked = false }  # granular
log_requests = { allowed = true, blocked = true }
# Optional: structured JSONL audit log for compliance/SIEM
# audit_log = "/var/log/pyloros/audit.jsonl"
# Optional: max bytes to capture per body for log_body rules (default 1048576)
# max_body_log_size = 1048576

[[rules]]
method = "GET"
url = "https://api.example.com/health"

[[rules]]
method = "*"
url = "https://*.github.com/*"

[[rules]]
method = "GET"
url = "wss://realtime.example.com/socket"
websocket = true

# Git-specific rules
[[rules]]
git = "fetch"
url = "https://github.com/myorg/*"

[[rules]]
git = "push"
url = "https://github.com/myorg/agent-workspace"
branches = ["feature/*", "fix/*"]

# Allow push to any branch except main and release/*
[[rules]]
git = "push"
url = "https://github.com/myorg/shared-repo"
branches = ["*", "!main", "!release/*"]

# Credential injection — inject API keys/tokens into matching requests
# Every credential requires a local credential (local_value or local_generated)

# Header credential with local from env var
[[credentials]]
url = "https://api.anthropic.com/*"
header = "x-api-key"
value = "${ANTHROPIC_API_KEY}"
local_value = "${LOCAL_ANTHROPIC_KEY}"

# Header credential with generated local
[[credentials]]
url = "https://api.openai.com/*"
header = "authorization"
value = "Bearer ${OPENAI_API_KEY}"
local_generated = true
# local_env_name = "OPENAI_API_KEY"  # optional, defaults to env var from value

# AWS SigV4 credential with generated local
[[credentials]]
type = "aws-sigv4"
url = "https://*.amazonaws.com/*"
access_key_id = "${AWS_ACCESS_KEY_ID}"
secret_access_key = "${AWS_SECRET_ACCESS_KEY}"
# session_token = "${AWS_SESSION_TOKEN}"
local_generated = true
# local_access_key_id_env_name = "AWS_ACCESS_KEY_ID"  # optional
# local_secret_access_key_env_name = "AWS_SECRET_ACCESS_KEY"  # optional
```

## Testing

- Unit tests where it makes sense
- End-to-end integration tests covering all features: filtering rules, plain HTTP forwarding, HTTPS (MITM), HTTP/2, WebSocket
- CLI integration tests for all subcommands (`run`, `generate-ca`, `validate-config`)
- Tests run in GitHub Actions; coverage is reported
- When testing integration with external tools (git, curl, claude CLI, etc.), always verify that traffic actually went through the proxy — don't just check that the tool succeeded. Record requests at the upstream handler or check proxy logs for expected entries.
- When testing that an activity is blocked, don't only verify that the standard tool (e.g., `git push`) fails — also verify that individual protocol requests are independently blocked, since an attacker may craft requests directly, skipping discovery/negotiation steps.
- For functions with guard clauses or validation checks, test at the exact boundaries — not just "valid input" and "clearly invalid input". A test that only sends well-formed data and completely empty data leaves all the boundary logic untested.

See `INTERNALS.md` for implementation details (E2E test architecture, port override mechanism).

### Binary-Level Tests

Binary-level smoke tests spawn the actual `pyloros` binary and drive it with
`curl`, configured via `http_proxy`/`HTTPS_PROXY` environment variables — the same
mechanism real clients use. Tests prefer environment variables over curl CLI flags
(e.g. `--proxy`, `--cacert`) where possible to mirror real-world usage. They verify
end-to-end behavior including config parsing, CLI argument handling, and process
lifecycle.

Binary tests should enable proxy authentication to mirror realistic deployment
configurations. Proxy credentials are passed via embedded credentials in the proxy
URL (e.g. `http://user:pass@127.0.0.1:PORT`), the same way real clients configure
them.

### Live API Tests

Binary-level tests that send real requests to external APIs (e.g. `api.anthropic.com`) through the proxy, verifying the full MITM TLS pipeline against production servers. These tests require the `claude` CLI to be installed and authenticated, and are skipped when either is unavailable (e.g. in CI).

### Mutation Testing

Mutation testing with `cargo-mutants` validates test suite quality. It is run manually (not in CI) and does not need automation. The goal is to kill all viable mutants for core logic (filtering, header manipulation, protocol handling). Surviving mutants in logging/debug/cosmetic code are acceptable.

Guidelines for writing mutation-resistant tests:

- **Boundary values for guards**: When code has a numeric/length check (e.g. `len < 4`, `pos + n > data.len()`), test at the exact boundary: one below, exactly at, and one above. Off-by-one mutations (`<` vs `<=`, `>` vs `>=`) should fail at least one test.
- **Malformed and adversarial input for parsers**: Parsers that handle untrusted input (pkt-line, URL patterns, config) need tests with truncated data, overlong length fields, zero-length payloads, and invalid UTF-8 — not just well-formed happy-path packets.
- **Assert rejection, not just acceptance**: For every boolean/predicate function, test at least one input that returns `true` and one that returns `false`. For functions that filter or classify, test both matching and non-matching cases.
- **Non-trivial operand values**: When code does arithmetic on a value that could be >1 (e.g. `+= char.len_utf8()`), include a test where the value is >1 (e.g. multi-byte UTF-8) so that `+=` vs `*=` mutations produce different results.

### Git Smart HTTP Tests

Integration tests verify that git smart HTTP operations (clone, push) work correctly through the proxy's HTTPS MITM pipeline using git-specific config rules (`git = "fetch"`, `git = "push"`, `git = "*"`). Tests run a local git smart HTTP server (via `git http-backend` CGI), route `git clone`/`git push` commands through the proxy, and verify end-to-end correctness.

Test coverage includes:
- Basic clone/push through proxy with git rules (`git_smart_http_test.rs`)
- Operation-level filtering: fetch-only rule blocks push, push-only blocks clone (`git_rules_test.rs`)
- Repo-level filtering: URL patterns restrict which repos are accessible (`git_rules_test.rs`)
- Branch-level restriction: `branches` patterns allow/block pushes to specific refs (`git_rules_test.rs`)
- Pkt-line parser unit tests: ref extraction, capabilities handling, branch matching (`pktline.rs`)
- Git-LFS: LFS batch endpoint filtering by operation type, plain HTTP blocking, merged-scan for combined fetch+push rules (`git_lfs_test.rs`)
- Proxy authentication: correct credentials accepted, wrong/missing credentials get 407, auth disabled works without credentials (`proxy_auth_test.rs`)

### Test Report Generation

Tests produce a human-readable report showing, for each test: what was done, what the result was, and what assertions were checked. The report is tightly coupled to actual test execution — descriptions are derived from real parameters (URLs, rules, CLI args), making drift between tests and report impossible.

- A standalone report generator tool (`tools/test-report/`) runs the test suite and produces Markdown + HTML output.
- The Markdown report is published to the GitHub Actions job summary so it's visible directly in the run without downloading artifacts.
- Reports are also uploaded as CI artifacts.

Test actions (HTTP requests, CLI invocations, etc.) should be performed through wrapper functions that both execute the action and emit a matching report entry. Bare `t.action()` + manual code pairs are not acceptable — the action description and execution must be coupled in a single API call so they can't drift apart. Examples: `ReportingClient` for HTTP requests, `_reported()` variants of test helpers.

### Fuzzing

Fuzz testing with `cargo-fuzz` (libFuzzer) targets parser and matching code that handles untrusted input. Targets: pkt-line parsing, pattern matching, URL pattern parsing, config parsing. Run manually, not in CI. Seed corpora live in `fuzz/seeds/<target>/`.

## Distribution

Statically-linked Linux x86_64 binaries (musl) are published as GitHub Release assets on version tags (`v*`). The release workflow builds the binary, runs tests against it, verifies static linking, and packages it as a tarball with SHA256 checksums.

A rolling `latest` pre-release is built from `main` on every push. It uses a fixed `latest` git tag (force-moved to HEAD) and is marked as a prerelease with `make_latest: false` so it doesn't override the versioned "Latest release" in the GitHub UI.

### Docker Image

A Docker image is published to `ghcr.io/pyloros-org/pyloros` with the following tags:
- `v1.2.3` + `latest` — on version tags
- `edge` — on every push to `main`

The image uses Alpine as the base (~7MB overhead), containing only the statically-linked binary. The same release workflow that publishes GitHub Release assets also builds and pushes the Docker image.

The Docker Compose example defaults to the published image, so users can start immediately without building from source.

### Docker Compose Example

A Docker Compose example (`examples/docker-compose/`) provides a declarative way to run containers
with all network access routed through the pyloros proxy using a two-network architecture (external
bridge + internal isolated). The sandbox container is placed on an `--internal` Docker network with
no direct internet access; the proxy container bridges the internal and external networks, forwarding
only allowed requests. A test script (`scripts/test-docker-compose.sh`) verifies allowed/blocked
behavior and network isolation.

When proxy authentication is enabled, the compose file passes the proxy secret to the workload
container via Docker Compose environment variables or secrets.

### Bubblewrap Sandbox

A shell script (`scripts/pyloros-bwrap.sh`) provides a lightweight alternative to Docker for running
commands with network isolation on Linux. It uses `bwrap` (bubblewrap) with `--unshare-net` to cut
off all network access, communicating with the proxy via a Unix domain socket bind-mounted into the
namespace. Inside the sandbox, `socat` bridges a local TCP port to the Unix socket so that standard
`HTTP_PROXY`/`HTTPS_PROXY` environment variables work with unmodified clients.

Architecture:
```
Host:  pyloros proxy ── listens on /tmp/pyloros-bwrap.XXXX/proxy.sock
                                          │ (bind-mounted)
bwrap:  socat TCP-LISTEN:8080 ── UNIX-CONNECT:/run/pyloros-proxy.sock
         ↑
        sandboxed command (HTTP_PROXY=http://127.0.0.1:8080)
```

The script handles: prerequisite checks (`bwrap`, `socat`, pyloros binary), temp directory and
socket lifecycle, proxy startup/shutdown, CA cert mounting, environment variable injection, and
cleanup on exit. A companion test script (`scripts/test-bwrap.sh`) verifies allowed/blocked behavior
and network isolation, following the same pattern as the Docker Compose tests.

#### Direct HTTPS mode (`--direct-https`)

When the `--direct-https` flag is passed, the bwrap script additionally:
1. Starts pyloros with a second Unix socket for direct HTTPS connections (`direct.sock`)
2. Generates `/etc/hosts` via `pyloros generate-hosts` mapping allowed hostnames to a loopback address (e.g. `127.0.0.12`)
3. Runs a second socat bridge: `127.0.0.12:443` → `direct.sock`
4. Mounts the generated hosts file into bwrap as `/etc/hosts`

This eliminates the need for `HTTP_PROXY` env vars for HTTPS traffic — programs connect directly to
hostnames that resolve to the proxy's listener. The standard proxy mode remains active for plain HTTP
traffic (e.g. apt) and as a fallback.

Architecture with `--direct-https`:
```
Host:  pyloros proxy ── proxy.sock (explicit proxy mode)
                     └─ direct.sock (direct HTTPS mode)
                                          │ (bind-mounted)
bwrap:  socat TCP-LISTEN:8080 ── UNIX-CONNECT:/run/pyloros-proxy.sock  (for HTTP_PROXY)
        socat TCP-LISTEN:443,bind=127.0.0.12 ── UNIX-CONNECT:/run/pyloros-direct.sock  (for direct HTTPS)
         ↑
        /etc/hosts: 127.0.0.12 github.com api.example.com ...
        sandboxed command (connects to github.com:443 → hits 127.0.0.12:443 → proxy)
```

## Documentation

The project README (`README.md`) must contain:

- Project name, tagline, and brief description of what it does and why
- Overview of the deployment model (one proxy per VM/container)
- Quick-start guide: generate CA, create config, start proxy, configure client
- Per-tool client configuration guide (curl, git, Node.js/Claude Code) covering proxy env vars, CA cert setup, and tool-specific gotchas
- Configuration reference with example covering `[proxy]`, `[logging]`, and `[[rules]]` sections
- CLI reference for all subcommands (`run`, `generate-ca`, `validate-config`) with flags
- Build from source instructions (prerequisites, cargo build)
- How to run tests
- License (MIT)
