#!/usr/bin/env bash
#
# pyloros-test-proxy.sh — Start a temporary proxy for manual testing.
#
# Generates a temporary CA, writes a config with the given rules, starts
# the proxy, and runs a command with HTTP(S)_PROXY and SSL_CERT_FILE set.
# Cleans up everything on exit.
#
# Usage:
#   pyloros-test-proxy.sh [OPTIONS] -- COMMAND [ARGS...]
#
# Options:
#   --rule 'METHOD URL'  Add an allow rule (repeatable, required at least once)
#   --pyloros PATH       Path to pyloros binary (default: search PATH and build dirs)
#   --keep               Don't clean up temp dir on exit (for debugging)
#   -h, --help           Show this help message
#
# Examples:
#   # Test wget against google.com
#   pyloros-test-proxy.sh --rule 'GET https://www.google.com/*' -- wget -O /dev/null https://www.google.com/
#
#   # Test curl against multiple sites
#   pyloros-test-proxy.sh --rule 'GET https://api.github.com/*' --rule 'GET https://httpbin.org/*' \
#     -- curl -sS https://api.github.com/zen
#
#   # Interactive shell with proxy configured
#   pyloros-test-proxy.sh --rule '* https://*.example.com/*' -- bash
#
set -euo pipefail

# ---- Defaults ----
PYLOROS=""
KEEP=false
RULES=()

# ---- Parse arguments ----
usage() {
    sed -n '2,/^[^#]/{/^#/{ s/^# \?//; p }}' "$0"
    exit "${1:-0}"
}

COMMAND_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rule)     RULES+=("$2"); shift 2 ;;
        --pyloros)  PYLOROS="$2"; shift 2 ;;
        --keep)     KEEP=true; shift ;;
        -h|--help)  usage 0 ;;
        --)         shift; COMMAND_ARGS=("$@"); break ;;
        *)          echo "Error: unknown option: $1" >&2; usage 1 ;;
    esac
done

if [[ ${#RULES[@]} -eq 0 ]]; then
    echo "Error: at least one --rule is required" >&2
    usage 1
fi

if [[ ${#COMMAND_ARGS[@]} -eq 0 ]]; then
    echo "Error: no command specified after --" >&2
    usage 1
fi

# ---- Find pyloros binary ----
if [[ -z "$PYLOROS" ]]; then
    if command -v pyloros >/dev/null 2>&1; then
        PYLOROS="$(command -v pyloros)"
    else
        # Search common build directories
        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
        PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
        MAIN_WORKTREE=""
        if git -C "$PROJECT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            MAIN_WORKTREE="$(git -C "$PROJECT_DIR" worktree list --porcelain | head -1 | sed 's/^worktree //')"
        fi
        for search_dir in "$PROJECT_DIR" ${MAIN_WORKTREE:+"$MAIN_WORKTREE"}; do
            for candidate in \
                "$search_dir/target/release/pyloros" \
                "$search_dir/target/debug/pyloros"; do
                if [[ -x "$candidate" ]]; then
                    PYLOROS="$candidate"
                    break 2
                fi
            done
        done
    fi
fi

if [[ -z "$PYLOROS" || ! -x "$PYLOROS" ]]; then
    echo "Error: cannot find pyloros binary. Build it or pass --pyloros PATH" >&2
    exit 1
fi

# ---- Create temp directory ----
TMPDIR_BASE="$(mktemp -d /tmp/pyloros-test.XXXXXXXX)"

# ---- Cleanup trap ----
PROXY_PID=""
cleanup() {
    local exit_code=$?
    if [[ -n "$PROXY_PID" ]]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    if [[ "$KEEP" == "false" ]]; then
        rm -rf "$TMPDIR_BASE"
    else
        echo "Temp dir kept at: $TMPDIR_BASE" >&2
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

# ---- Generate CA ----
"$PYLOROS" generate-ca --out "$TMPDIR_BASE" >/dev/null 2>&1
CA_CERT="$TMPDIR_BASE/ca.crt"
CA_KEY="$TMPDIR_BASE/ca.key"

# ---- Write config ----
CONFIG="$TMPDIR_BASE/config.toml"
cat > "$CONFIG" <<EOF
[proxy]
bind_address = "127.0.0.1:0"
ca_cert = "$CA_CERT"
ca_key = "$CA_KEY"

[logging]
level = "info"
log_requests = true

EOF

for rule in "${RULES[@]}"; do
    # Split "METHOD URL" on first space
    method="${rule%% *}"
    url="${rule#* }"
    cat >> "$CONFIG" <<EOF
[[rules]]
method = "$method"
url = "$url"

EOF
done

# ---- Start the proxy ----
"$PYLOROS" run --config "$CONFIG" 2>"$TMPDIR_BASE/proxy.log" &
PROXY_PID=$!

# Wait for proxy to print its listening address
TIMEOUT=10
ELAPSED=0
PORT=""
while [[ -z "$PORT" ]]; do
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "Error: proxy exited before it was ready" >&2
        cat "$TMPDIR_BASE/proxy.log" >&2
        exit 1
    fi
    # Strip ANSI codes and parse the port
    PORT="$(sed 's/\x1b\[[0-9;]*m//g' "$TMPDIR_BASE/proxy.log" | grep 'address=' | sed 's/.*address=.*:\([0-9]*\)/\1/' | head -1 || true)"
    if [[ -z "$PORT" ]]; then
        if [[ $ELAPSED -ge $TIMEOUT ]]; then
            echo "Error: timed out waiting for proxy to start" >&2
            cat "$TMPDIR_BASE/proxy.log" >&2
            exit 1
        fi
        sleep 0.2
        ELAPSED=$((ELAPSED + 1))
    fi
done

PROXY_URL="http://127.0.0.1:$PORT"
echo "Proxy listening on $PROXY_URL (PID $PROXY_PID)" >&2
echo "CA cert: $CA_CERT" >&2
echo "Config: $CONFIG" >&2
echo "---" >&2

# ---- Run the command with proxy env vars ----
CMD_EXIT=0
HTTP_PROXY="$PROXY_URL" \
HTTPS_PROXY="$PROXY_URL" \
http_proxy="$PROXY_URL" \
https_proxy="$PROXY_URL" \
SSL_CERT_FILE="$CA_CERT" \
CURL_CA_BUNDLE="$CA_CERT" \
NODE_EXTRA_CA_CERTS="$CA_CERT" \
REQUESTS_CA_BUNDLE="$CA_CERT" \
    "${COMMAND_ARGS[@]}" || CMD_EXIT=$?

# Show proxy errors if command failed
if [[ $CMD_EXIT -ne 0 ]]; then
    ERRORS="$(sed 's/\x1b\[[0-9;]*m//g' "$TMPDIR_BASE/proxy.log" | grep -i 'ERROR\|BLOCKED' || true)"
    if [[ -n "$ERRORS" ]]; then
        echo "---" >&2
        echo "Proxy log (errors/blocked):" >&2
        echo "$ERRORS" >&2
    fi
fi

exit "$CMD_EXIT"
