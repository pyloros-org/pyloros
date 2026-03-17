#!/usr/bin/env bash
#
# test-bwrap.sh — Integration tests for the bubblewrap sandbox script
#
# Prerequisites: bwrap, socat, cargo build completed.
# Skips gracefully if bwrap or socat is unavailable.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PASSED=0
FAILED=0
SKIPPED=0

# Colors (if terminal supports them)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    GREEN='' RED='' YELLOW='' NC=''
fi

pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; FAILED=$((FAILED + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC}: $1"; SKIPPED=$((SKIPPED + 1)); }

# Check prerequisites
for tool in bwrap socat curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "$tool is not available. Skipping all tests."
        exit 0
    fi
done

# Verify bwrap can actually create network namespaces (requires unprivileged user
# namespaces or CAP_SYS_ADMIN — not available on all CI runners)
if ! bwrap --unshare-net --ro-bind / / -- true 2>/dev/null; then
    echo "bwrap --unshare-net is not supported on this system. Skipping all tests."
    exit 0
fi

# Find the pyloros binary
BINARY=""
MAIN_WORKTREE=""
if git -C "$PROJECT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    MAIN_WORKTREE="$(git -C "$PROJECT_DIR" worktree list --porcelain | head -1 | sed 's/^worktree //')"
fi
for search_dir in "$PROJECT_DIR" ${MAIN_WORKTREE:+"$MAIN_WORKTREE"}; do
    for candidate in \
        "$search_dir/target/release/pyloros" \
        "$search_dir/target/debug/pyloros"; do
        if [[ -x "$candidate" ]]; then
            BINARY="$candidate"
            break 2
        fi
    done
done
if [[ -z "$BINARY" ]]; then
    echo "Cannot find pyloros binary. Run 'cargo build' first."
    exit 1
fi

# Generate CA certs to a temp directory
CA_DIR="$(mktemp -d)"

echo "Generating CA certificate..."
"$BINARY" generate-ca --out "$CA_DIR" >/dev/null

# Create test config
CONFIG="$CA_DIR/config.toml"
cat > "$CONFIG" << EOF
[proxy]
bind_address = "127.0.0.1:0"
ca_cert = "$CA_DIR/ca.crt"
ca_key = "$CA_DIR/ca.key"

[logging]
level = "info"
log_requests = true

# Allow curl to example.com
[[rules]]
method = "*"
url = "https://example.com/*"
EOF

BWRAP_SCRIPT="$SCRIPT_DIR/pyloros-bwrap.sh"
RESULT_FILE="$CA_DIR/result"
STDERR_FILE="$CA_DIR/stderr"

# Cleanup on exit
cleanup() {
    local exit_code=$?
    rm -rf "$CA_DIR"
    exit "$exit_code"
}
trap cleanup EXIT

echo ""
echo "=== Bubblewrap Sandbox Integration Tests ==="
echo ""
echo "Binary: $BINARY"
echo "Config: $CONFIG"
echo ""

# Helper: run bwrap script, stdout goes to RESULT_FILE, stderr to STDERR_FILE.
run_bwrap() {
    timeout 30 "$BWRAP_SCRIPT" --config "$CONFIG" --pyloros "$BINARY" -- "$@" \
        > "$RESULT_FILE" 2>"$STDERR_FILE"
}

# Test 1: Allowed HTTPS request through proxy
echo "Test 1: Allowed HTTPS request through proxy"
set +e
run_bwrap curl -sf https://example.com/
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]] && grep -q "Example Domain" "$RESULT_FILE" 2>/dev/null; then
    pass "Allowed HTTPS request succeeds and returns expected content"
else
    fail "Allowed HTTPS request (exit=$EXIT_CODE)"
    echo "    stdout (last 10 lines):"
    tail -10 "$RESULT_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
    echo "    stderr (last 10 lines):"
    tail -10 "$STDERR_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
fi

# Test 2: Blocked URL returns 451
echo "Test 2: Blocked URL returns HTTP 451"
set +e
run_bwrap curl -so /dev/null -w '%{http_code}' https://httpbin.org/get
EXIT_CODE=$?
set -e

HTTP_CODE=$(cat "$RESULT_FILE" 2>/dev/null | tr -d '[:space:]')

if [[ "$HTTP_CODE" == "451" ]]; then
    pass "Blocked URL returns HTTP 451"
else
    fail "Expected HTTP 451, got '$HTTP_CODE' (exit=$EXIT_CODE)"
    echo "    stderr (last 5 lines):"
    tail -5 "$STDERR_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
fi

# Test 3: Direct connection blocked (network isolation)
echo "Test 3: Direct connection blocked (no proxy)"
set +e
run_bwrap curl --noproxy '*' --connect-timeout 3 http://1.1.1.1/
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -ne 0 ]]; then
    pass "Direct connection is blocked (exit=$EXIT_CODE)"
else
    fail "Direct connection should have been blocked but succeeded"
    echo "    Output (last 5 lines):"
    tail -5 "$RESULT_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (no output)"
fi

# =====================================================
# Direct HTTPS mode tests
# =====================================================
echo ""
echo "=== Direct HTTPS Mode Tests ==="
echo ""

# Direct HTTPS tests need sudo bwrap so socat can bind port 443 as root
# (the user command still runs unprivileged via su).
# Skip these tests if passwordless sudo is not available.
if ! sudo -n true 2>/dev/null; then
    echo "Passwordless sudo not available. Skipping direct HTTPS tests."
    skip "Direct HTTPS: allowed request (needs sudo)"
    skip "Direct HTTPS: blocked host (needs sudo)"
    skip "Direct HTTPS: proxy coexistence (needs sudo)"
else

# Helper: run bwrap script with --direct-https and --sudo-bwrap
run_bwrap_direct() {
    timeout 30 "$BWRAP_SCRIPT" --config "$CONFIG" --pyloros "$BINARY" \
        --direct-https --sudo-bwrap -- "$@" \
        > "$RESULT_FILE" 2>"$STDERR_FILE"
}

# Test 4: Allowed HTTPS request via direct HTTPS (no proxy env, using /etc/hosts)
echo "Test 4: Allowed HTTPS request via direct HTTPS mode (port 443)"
set +e
# --noproxy '*' ensures curl does NOT use HTTP_PROXY, so it connects directly
# to example.com:443 which /etc/hosts resolves to 127.0.0.12 -> proxy.
run_bwrap_direct curl --noproxy '*' -sf https://example.com/
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]] && grep -q "Example Domain" "$RESULT_FILE" 2>/dev/null; then
    pass "Direct HTTPS: allowed request succeeds without HTTP_PROXY"
else
    fail "Direct HTTPS: allowed request (exit=$EXIT_CODE)"
    echo "    stdout (last 10 lines):"
    tail -10 "$RESULT_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
    echo "    stderr (last 10 lines):"
    tail -10 "$STDERR_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
fi

# Test 5: Blocked host is not in /etc/hosts so DNS fails
echo "Test 5: Blocked host fails to resolve (not in generated /etc/hosts)"
set +e
run_bwrap_direct curl --noproxy '*' --connect-timeout 3 -so /dev/null https://httpbin.org/get
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -ne 0 ]]; then
    pass "Direct HTTPS: blocked host cannot be reached (exit=$EXIT_CODE)"
else
    fail "Direct HTTPS: blocked host should have failed but succeeded"
    echo "    Output (last 5 lines):"
    tail -5 "$RESULT_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (no output)"
fi

# Test 6: Proxy-mode still works alongside direct HTTPS
echo "Test 6: HTTP_PROXY still works in direct HTTPS mode"
set +e
# Without --noproxy, curl uses HTTP_PROXY (proxy mode still active in --direct-https)
run_bwrap_direct curl -sf https://example.com/
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]] && grep -q "Example Domain" "$RESULT_FILE" 2>/dev/null; then
    pass "Direct HTTPS: proxy mode coexists with direct HTTPS"
else
    fail "Direct HTTPS: proxy mode alongside direct (exit=$EXIT_CODE)"
    echo "    stdout (last 10 lines):"
    tail -10 "$RESULT_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
    echo "    stderr (last 10 lines):"
    tail -10 "$STDERR_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
fi

fi # end sudo check

# Summary
echo ""
echo "=== Results: $PASSED passed, $FAILED failed, $SKIPPED skipped ==="

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
