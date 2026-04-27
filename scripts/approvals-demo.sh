#!/usr/bin/env bash
#
# approvals-demo.sh — Spin up a local proxy with the approvals feature for manual play.
#
# Generates a temporary CA, writes a config with [approvals] enabled, starts the
# proxy, opens the dashboard in your browser, and prints a few example agent
# commands you can paste into another terminal. Cleans up on exit.
#
# Usage:
#   scripts/approvals-demo.sh [--no-browser] [--keep]
#
# Options:
#   --no-browser   Don't try to open the dashboard URL in a browser
#   --keep         Keep the temp dir (CA, config, sidecar, proxy log) on exit
#   -h, --help     Show this help
#
set -euo pipefail

NO_BROWSER=false
KEEP=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-browser) NO_BROWSER=true; shift ;;
        --keep)       KEEP=true; shift ;;
        -h|--help)
            sed -n '2,/^[^#]/{/^#/{ s/^# \?//; p }}' "$0"; exit 0 ;;
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

# No [[rules]] — every request needs approval.
EOF

"$PYLOROS" run --config "$CONFIG" 2>"$TMPDIR_BASE/proxy.log" &
PROXY_PID=$!

# Wait for the proxy to be ready (look for "address=" line).
for _ in $(seq 1 50); do
    kill -0 "$PROXY_PID" 2>/dev/null || { cat "$TMPDIR_BASE/proxy.log" >&2; exit 1; }
    grep -q 'address=' "$TMPDIR_BASE/proxy.log" && break
    sleep 0.1
done

DASHBOARD_URL="http://$DASH_BIND/"
PROXY_URL="http://$PROXY_BIND"

cat <<EOF

================================================================
  pyloros approvals demo
================================================================

  Proxy        $PROXY_URL
  Dashboard    $DASHBOARD_URL  (open in your browser)
  CA cert      $CA_CERT
  Sidecar      $SIDECAR
  Proxy log    $TMPDIR_BASE/proxy.log

  In another terminal, simulate the agent inside the sandbox:

  # 1) Request an approval (returns 202 + an approval id).
  curl -x $PROXY_URL --cacert $CA_CERT \\
    -X POST https://pyloros.internal/approvals \\
    -H 'Content-Type: application/json' \\
    -d '{"rules":["GET https://httpbin.org/*"],"reason":"fetch test data"}'

  # 2) Long-poll for the human's decision (replace apr_XXX):
  curl -x $PROXY_URL --cacert $CA_CERT \\
    "https://pyloros.internal/approvals/apr_XXX?wait=60s"

  # 3) After you approve in the dashboard, the rule is live:
  curl -x $PROXY_URL --cacert $CA_CERT https://httpbin.org/get

  Things to try in the dashboard:
    - Approve with "permanent" -> check $SIDECAR, restart, rule survives.
    - Deny with a free-text message -> agent's long-poll returns it.
    - POST a rule already covered by an active rule -> instant 200 (dedup).
    - Burst >60 POSTs in 60s -> some return 429 (rate limit).

  Press Ctrl-C to stop the proxy and clean up.
================================================================

EOF

if [[ "$NO_BROWSER" == "false" ]]; then
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$DASHBOARD_URL" >/dev/null 2>&1 || true
    elif command -v open >/dev/null 2>&1; then
        open "$DASHBOARD_URL" >/dev/null 2>&1 || true
    fi
fi

wait "$PROXY_PID"
