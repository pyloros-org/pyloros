#!/usr/bin/env bash
#
# approvals-demo.sh — Spin up a local proxy with the approvals feature
# and launch an interactive Claude Code session "behind" it. Outbound
# HTTP from Claude's tool calls is filtered by pyloros; blocked requests
# return 451 and the agent is instructed to use the approvals API.
#
# Usage:
#   scripts/approvals-demo.sh [--no-browser] [--keep] [--no-claude] [-- <claude args...>]
#
# Options:
#   --no-browser   Don't try to open the dashboard URL in a browser
#   --keep         Keep the temp dir (CA, config, sidecar, proxy log) on exit
#   --no-claude    Don't launch claude — just run the proxy + dashboard
#                  (use raw curl from another terminal, like the old demo)
#   -h, --help     Show this help
#
# Anything after `--` is forwarded to the `claude` command.
#
set -euo pipefail

NO_BROWSER=false
KEEP=false
NO_CLAUDE=false
CLAUDE_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-browser) NO_BROWSER=true; shift ;;
        --keep)       KEEP=true; shift ;;
        --no-claude)  NO_CLAUDE=true; shift ;;
        -h|--help)
            sed -n '2,/^[^#]/{/^#/{ s/^# \?//; p }}' "$0"; exit 0 ;;
        --) shift; CLAUDE_ARGS=("$@"); break ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find or build pyloros.
PYLOROS=""
for c in "$PROJECT_DIR/target/release/pyloros" "$PROJECT_DIR/target/debug/pyloros"; do
    [[ -x "$c" ]] && PYLOROS="$c" && break
done
if [[ -z "$PYLOROS" ]]; then
    echo "Building pyloros (debug)..." >&2
    (cd "$PROJECT_DIR" && cargo build) >&2
    PYLOROS="$PROJECT_DIR/target/debug/pyloros"
fi

if [[ "$NO_CLAUDE" == "false" ]] && ! command -v claude >/dev/null 2>&1; then
    echo "claude CLI not found in PATH; pass --no-claude to skip launching it." >&2
    exit 1
fi

TMPDIR_BASE="$(mktemp -d /tmp/pyloros-approvals-demo.XXXXXXXX)"
PROXY_PID=""
cleanup() {
    local rc=$?
    [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
    [[ -n "$PROXY_PID" ]] && wait "$PROXY_PID" 2>/dev/null || true
    if [[ "$KEEP" == "true" ]]; then
        echo "Temp dir kept at: $TMPDIR_BASE" >&2
    else
        rm -rf "$TMPDIR_BASE"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# Generate CA.
"$PYLOROS" generate-ca --out "$TMPDIR_BASE" >/dev/null
CA_CERT="$TMPDIR_BASE/ca.crt"
CA_KEY="$TMPDIR_BASE/ca.key"

PROXY_BIND="127.0.0.1:7777"
DASH_BIND="127.0.0.1:7778"
SIDECAR="$TMPDIR_BASE/approvals-sidecar.toml"
CONFIG="$TMPDIR_BASE/config.toml"

# Pre-allow Anthropic + Statsig hosts so Claude Code itself can talk to
# its own backend. Everything else goes through the approvals flow.
cat > "$CONFIG" <<EOF
[proxy]
bind_address = "$PROXY_BIND"
ca_cert = "$CA_CERT"
ca_key  = "$CA_KEY"

[logging]
level = "info"
log_requests = true

[approvals]
sidecar_file   = "$SIDECAR"
dashboard_bind = "$DASH_BIND"

[[rules]]
method = "*"
url    = "https://*.anthropic.com/*"

[[rules]]
method = "*"
url    = "https://statsigapi.net/*"

[[rules]]
method = "*"
url    = "https://*.statsig.com/*"
EOF

"$PYLOROS" run --config "$CONFIG" 2>"$TMPDIR_BASE/proxy.log" &
PROXY_PID=$!

for _ in $(seq 1 50); do
    kill -0 "$PROXY_PID" 2>/dev/null || { cat "$TMPDIR_BASE/proxy.log" >&2; exit 1; }
    grep -q 'address=' "$TMPDIR_BASE/proxy.log" && break
    sleep 0.1
done

DASHBOARD_URL="http://$DASH_BIND/"
PROXY_URL="http://$PROXY_BIND"

# Agent instructions, injected as an appended system prompt. Kept short
# on purpose — the agent only needs the protocol, not editorial detail.
SYSTEM_BLURB="$(cat <<EOF
You are running behind pyloros, an HTTPS allowlist proxy. Outbound HTTP
requests that don't match an active allow rule are blocked with HTTP 451
("Unavailable For Legal Reasons"). A 451 from this proxy is NOT an error
in the target server — it means YOU need permission first.

When you hit a 451 (or want to do an outbound call you expect will be
blocked), request approval from the human via the agent API. The API is
only reachable through the proxy at the magic hostname pyloros.internal:

  POST https://pyloros.internal/approvals
  Content-Type: application/json
  {
    "rules": [
      {"method": "GET", "url": "https://api.example.com/*"}
    ],
    "reason": "short human-readable why",
    "context": {"triggered_by": {"method": "GET", "url": "<the blocked URL>"}}
  }

Each rule object uses the same fields as a [[rules]] entry in the
pyloros TOML config. Common shapes:

  {"method": "GET",  "url": "https://api.foo.com/*"}     plain HTTP rule
  {"method": "*",    "url": "https://api.foo.com/*"}     any method
  {"git":    "fetch","url": "https://github.com/foo/bar.git"}  git clone/fetch
  {"git":    "push", "url": "https://github.com/foo/bar.git"}  git push
  {"git":    "*",    "url": "https://github.com/foo/bar.git"}  fetch + push

A git rule expands automatically to all the smart-HTTP endpoints the
operation needs (info/refs, git-upload-pack/git-receive-pack, LFS), so
you don't have to enumerate them yourself.

Responses:
  - 200 {"status":"approved", ...}  — already covered by an active rule;
    proceed immediately. (Dedup short-circuit; no human round-trip.)
  - 202 {"id":"apr_...","status":"pending", ...}  — waiting on human.
  - 429  — rate limited (60 posts/minute). Back off, don't retry tightly.
  - 400  — malformed JSON or invalid rule shape.

For pending requests, long-poll the decision:

  GET https://pyloros.internal/approvals/{id}?wait=60s

Returns when the human approves or denies (or after the wait window).
Possible terminal statuses:
  - "approved" — rule(s) are now active in the proxy. Retry your request.
  - "denied"   — may include a "message" field. Respect it; do NOT retry
                 the same request or propose minor variants of the same rule.

Guidelines:
  - Ask for the narrowest rule that covers your task. The human is more
    likely to approve {"method":"GET","url":"https://api.example.com/v1/weather/*"}
    than {"method":"*","url":"https://*.example.com/*"}.
  - Always include a "reason" — the human reads it before deciding.
  - For git, prefer git=fetch over a method rule — it covers all the
    smart-HTTP endpoints and is what the human probably wants to grant.
  - If denied with a message, read it. Don't paper over it.

Use Bash with curl plus --cacert "$CA_CERT" and -x "$PROXY_URL" to
exercise the flow. (HTTP_PROXY/HTTPS_PROXY/SSL_CERT_FILE are already
set in your environment, so plain "curl https://..." also works.)
EOF
)"

cat <<EOF

================================================================
  pyloros approvals demo
================================================================

  Proxy        $PROXY_URL
  Dashboard    $DASHBOARD_URL  (open in your browser)
  CA cert      $CA_CERT
  Sidecar      $SIDECAR
  Proxy log    $TMPDIR_BASE/proxy.log

  Pre-allowed: *.anthropic.com, *.statsig.com, statsigapi.net
  Everything else: blocked (451) until approved via the dashboard.

  When Claude needs network access for a tool call, it should hit a
  451 and POST to https://pyloros.internal/approvals. Approve in the
  browser, the agent's long-poll wakes up, and the rule is live.

  Try prompts like:
    - "fetch https://httpbin.org/get and show me the JSON"
    - "clone https://github.com/anthropics/anthropic-cookbook"
    - "curl https://api.github.com/zen"

  Press Ctrl-C to stop everything.
================================================================

EOF

if [[ "$NO_BROWSER" == "false" ]]; then
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$DASHBOARD_URL" >/dev/null 2>&1 || true
    elif command -v open >/dev/null 2>&1; then
        open "$DASHBOARD_URL" >/dev/null 2>&1 || true
    fi
fi

if [[ "$NO_CLAUDE" == "true" ]]; then
    echo "Running with --no-claude; press Ctrl-C to stop the proxy." >&2
    wait "$PROXY_PID"
    exit 0
fi

# Launch Claude with proxy env vars set. NODE_EXTRA_CA_CERTS makes the
# bundled Node runtime trust our test CA. NO_PROXY keeps Claude's own
# api.anthropic.com traffic off the proxy as a belt-and-suspenders
# fallback (we also allowlist anthropic in the proxy config above).
echo "Launching claude (Ctrl-D or /exit to quit)..." >&2
echo >&2

set +e
HTTP_PROXY="$PROXY_URL" \
HTTPS_PROXY="$PROXY_URL" \
http_proxy="$PROXY_URL" \
https_proxy="$PROXY_URL" \
SSL_CERT_FILE="$CA_CERT" \
CURL_CA_BUNDLE="$CA_CERT" \
NODE_EXTRA_CA_CERTS="$CA_CERT" \
REQUESTS_CA_BUNDLE="$CA_CERT" \
NO_PROXY="api.anthropic.com,statsigapi.net,.anthropic.com,.statsig.com,localhost,127.0.0.1" \
no_proxy="api.anthropic.com,statsigapi.net,.anthropic.com,.statsig.com,localhost,127.0.0.1" \
    claude --dangerously-skip-permissions \
           --append-system-prompt "$SYSTEM_BLURB" \
           "${CLAUDE_ARGS[@]}"
CLAUDE_RC=$?
set -e

exit "$CLAUDE_RC"
