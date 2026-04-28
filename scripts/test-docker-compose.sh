#!/usr/bin/env bash
#
# test-docker-compose.sh — Integration tests for the Docker Compose example
#
# Prerequisites: Docker running with compose (plugin or standalone), cargo build completed.
# Skips gracefully if Docker or compose is unavailable.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$PROJECT_DIR/examples/docker-compose/compose.yaml"

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
if ! docker info >/dev/null 2>&1; then
    echo "Docker is not available. Skipping all tests."
    exit 0
fi

# Detect compose command: prefer "docker compose" (v2 plugin), fall back to "docker-compose" (v1)
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif docker-compose --version >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo "Docker Compose is not available. Skipping all tests."
    exit 0
fi

# Find the pyloros binary: check PROJECT_DIR first, then the main git worktree
BINARY=""
MAIN_WORKTREE="$(git -C "$PROJECT_DIR" worktree list --porcelain | head -1 | sed 's/^worktree //')"
for search_dir in "$PROJECT_DIR" "$MAIN_WORKTREE"; do
    for candidate in \
        "$search_dir/target/x86_64-unknown-linux-musl/release/pyloros" \
        "$search_dir/target/x86_64-unknown-linux-musl/debug/pyloros" \
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

# Build local proxy Docker image from the binary using the project Dockerfile
PROXY_IMAGE="pyloros-compose-test-proxy:$$"
echo "Building local proxy image from $BINARY..."
cp "$BINARY" "$PROJECT_DIR/pyloros"
docker build -t "$PROXY_IMAGE" -f "$PROJECT_DIR/Dockerfile" "$PROJECT_DIR"
rm -f "$PROJECT_DIR/pyloros"

# Build test image with curl and git pre-installed
SANDBOX_IMAGE="pyloros-compose-test:latest"
echo "Building test sandbox image..."
docker build -t "$SANDBOX_IMAGE" -f - . <<'DOCKERFILE'
FROM alpine:latest
RUN apk add --no-cache curl git
DOCKERFILE

# Generate CA certs to a temp directory
CA_DIR="$(mktemp -d)"

echo "Generating CA certificate..."
"$BINARY" generate-ca --out "$CA_DIR" >/dev/null

# Copy the example config into a tempdir so the config-reload test can
# mutate it without touching the checked-in file. The compose file
# bind-mounts $CONFIG_DIR (default ./conf) into the container.
CONFIG_DIR_HOST="$(mktemp -d)"
cp "$PROJECT_DIR/examples/docker-compose/conf/config.toml" "$CONFIG_DIR_HOST/config.toml"
CONFIG_FILE="$CONFIG_DIR_HOST/config.toml"  # used by reload test
CONFIG_DIR="$CONFIG_DIR_HOST"

# Use a unique project name for isolation
COMPOSE_PROJECT_NAME="pyloros-compose-test-$$"
export COMPOSE_PROJECT_NAME PROXY_IMAGE CA_DIR SANDBOX_IMAGE CONFIG_DIR

# Compose helper — runs compose with our file and project name
dc() {
    $COMPOSE_CMD -f "$COMPOSE_FILE" "$@"
}

# Cleanup on exit
cleanup() {
    local exit_code=$?
    echo ""
    echo "Cleaning up..."
    dc down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$CA_DIR"
    rm -rf "$CONFIG_DIR_HOST"
    docker rmi "$PROXY_IMAGE" >/dev/null 2>&1 || true
    exit "$exit_code"
}
trap cleanup EXIT

echo ""
echo "=== Docker Compose Integration Tests ==="
echo ""

# Start services
echo "Starting services (project: $COMPOSE_PROJECT_NAME)..."
dc up -d 2>&1

# Helper: run a command in the sandbox container
sandbox_exec() {
    dc exec -T sandbox "$@"
}

# Helper: run a command in the sandbox with all proxy env vars unset.
# Exercises direct-HTTPS mode: clients resolve hostnames via our dnsmasq
# (wildcard → proxy IP) and connect straight to the proxy on :443.
sandbox_exec_direct() {
    dc exec -T sandbox env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy "$@"
}

# Test 1: Allowed HTTPS through proxy
echo ""
echo "Test 1: Allowed HTTPS request through proxy"
set +e
OUTPUT=$(sandbox_exec curl -sf https://httpbin.org/robots.txt 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]] && echo "$OUTPUT" | grep -q "Disallow"; then
    pass "Allowed HTTPS request succeeds and returns expected content"
else
    fail "Allowed HTTPS request (exit=$EXIT_CODE)"
    echo "    Output (last 10 lines):"
    echo "$OUTPUT" | tail -10 | sed 's/^/    /'
fi

# Test 2: Direct connection blocked (bypass proxy)
echo "Test 2: Direct connection blocked (no proxy)"
set +e
OUTPUT=$(sandbox_exec curl --noproxy '*' --connect-timeout 5 http://1.1.1.1/ 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -ne 0 ]]; then
    pass "Direct connection is blocked (exit=$EXIT_CODE)"
else
    fail "Direct connection should have been blocked but succeeded"
    echo "    Output (last 5 lines):"
    echo "$OUTPUT" | tail -5 | sed 's/^/    /'
fi

# Test 3: Blocked URL returns 451
echo "Test 3: Blocked URL returns HTTP 451"
set +e
HTTP_CODE=$(sandbox_exec curl -so /dev/null -w '%{http_code}' https://httpbin.org/get 2>&1)
EXIT_CODE=$?
set -e

if [[ "$HTTP_CODE" == "451" ]]; then
    pass "Blocked URL returns HTTP 451"
else
    fail "Expected HTTP 451, got '$HTTP_CODE' (exit=$EXIT_CODE)"
fi

# Test 4: Git clone through proxy
echo "Test 4: Git clone through proxy"
set +e
OUTPUT=$(sandbox_exec git clone https://github.com/octocat/Hello-World /tmp/hello 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]]; then
    # Verify the clone produced files
    set +e
    sandbox_exec test -f /tmp/hello/README 2>/dev/null
    FILE_CHECK=$?
    set -e
    if [[ $FILE_CHECK -eq 0 ]]; then
        pass "Git clone succeeds and README exists"
    else
        fail "Git clone succeeded but README not found"
    fi
else
    fail "Git clone failed (exit=$EXIT_CODE)"
    echo "    Output (last 10 lines):"
    echo "$OUTPUT" | tail -10 | sed 's/^/    /'
fi

# --- Direct HTTPS mode tests ---
# These skip HTTP_PROXY entirely; the sandbox relies on the dns service
# resolving every hostname to the proxy's IP, then connects to :443.

# Expected proxy IP (matches default in compose.yaml).
EXPECTED_PROXY_IP="${PYLOROS_PROXY_IP:-172.30.0.254}"

# Test 5: DNS wildcard: every hostname resolves to the proxy IP.
echo ""
echo "Test 5: DNS wildcard resolves arbitrary hostname to proxy IP"
set +e
GETENT_OUT=$(sandbox_exec getent hosts some-random-host.example 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]] && echo "$GETENT_OUT" | awk '{print $1}' | grep -qx "$EXPECTED_PROXY_IP"; then
    pass "DNS wildcard returns $EXPECTED_PROXY_IP for arbitrary hostname"
else
    fail "DNS wildcard check (exit=$EXIT_CODE), got: $GETENT_OUT"
fi

# Test 6: Direct HTTPS allowed request (no HTTP_PROXY, DNS → proxy:443)
echo "Test 6: Direct HTTPS allowed request (no proxy env)"
set +e
OUTPUT=$(sandbox_exec_direct curl -sf https://httpbin.org/robots.txt 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]] && echo "$OUTPUT" | grep -q "Disallow"; then
    pass "Direct HTTPS allowed request succeeds without HTTP_PROXY"
else
    fail "Direct HTTPS allowed request (exit=$EXIT_CODE)"
    echo "    Output (last 10 lines):"
    echo "$OUTPUT" | tail -10 | sed 's/^/    /'
fi

# Test 7: Direct HTTPS blocked URL still returns 451 (proxy enforces, not DNS)
echo "Test 7: Direct HTTPS blocked URL returns HTTP 451"
set +e
HTTP_CODE=$(sandbox_exec_direct curl -so /dev/null -w '%{http_code}' https://httpbin.org/get 2>&1)
EXIT_CODE=$?
set -e

if [[ "$HTTP_CODE" == "451" ]]; then
    pass "Direct HTTPS blocked URL returns HTTP 451"
else
    fail "Expected HTTP 451 via direct HTTPS, got '$HTTP_CODE' (exit=$EXIT_CODE)"
fi

# Test 8: Direct HTTPS git clone
echo "Test 8: Direct HTTPS git clone"
set +e
OUTPUT=$(sandbox_exec_direct git clone https://github.com/octocat/Hello-World /tmp/hello-direct 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]]; then
    set +e
    sandbox_exec test -f /tmp/hello-direct/README 2>/dev/null
    FILE_CHECK=$?
    set -e
    if [[ $FILE_CHECK -eq 0 ]]; then
        pass "Direct HTTPS git clone succeeds and README exists"
    else
        fail "Direct HTTPS git clone succeeded but README not found"
    fi
else
    fail "Direct HTTPS git clone failed (exit=$EXIT_CODE)"
    echo "    Output (last 10 lines):"
    echo "$OUTPUT" | tail -10 | sed 's/^/    /'
fi

# --- Config reload tests ---
# The compose example bind-mounts the *directory* containing config.toml,
# so both editor save patterns reach the container:
#   - in-place rewrite (cat >, truncate+write) keeps the inode and is
#     observed by the proxy's polling fallback;
#   - atomic rename (mv -f new old) replaces the directory entry, which
#     inotify on the parent dir sees because the mount is the host
#     directory itself (same inode, not a single-file bind).

# wait_for_url: polls sandbox for up to ~30s waiting for $1 to return $2.
# Each docker compose exec adds latency, so we cap by attempt count.
wait_for_url() {
    local url="$1" expected="$2" i code
    for (( i = 0; i < 60; i++ )); do
        code=$(sandbox_exec curl -so /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)
        if [[ "$code" == "$expected" ]]; then return 0; fi
        sleep 0.5
    done
    return 1
}

# Sanity: httpbin.org/uuid is currently blocked (only /robots.txt is allowed)
echo ""
echo "Test 9: Pre-reload, httpbin.org/uuid is blocked (HTTP 451)"
set +e
HTTP_CODE=$(sandbox_exec curl -so /dev/null -w '%{http_code}' https://httpbin.org/uuid 2>&1)
set -e
if [[ "$HTTP_CODE" == "451" ]]; then
    pass "httpbin.org/uuid blocked before reload"
else
    fail "Expected 451 before reload, got '$HTTP_CODE'"
fi

# Test 10: Atomic-rename edit (typical editor save pattern: write tmp, mv -f)
# triggers reload via inotify on the bind-mounted directory.
echo "Test 10: Config reload after atomic-rename edit"
TMP_CFG="${CONFIG_FILE}.new"
cp "$CONFIG_FILE" "$TMP_CFG"
cat >> "$TMP_CFG" <<'EOF'

[[rules]]
method = "GET"
url = "https://httpbin.org/uuid"
EOF
mv -f "$TMP_CFG" "$CONFIG_FILE"

set +e
wait_for_url https://httpbin.org/uuid 200
RELOAD_RC=$?
HTTP_CODE=$(sandbox_exec curl -so /dev/null -w '%{http_code}' https://httpbin.org/uuid 2>&1)
set -e
if [[ $RELOAD_RC -eq 0 && "$HTTP_CODE" == "200" ]]; then
    pass "Atomic-rename edit triggered reload (httpbin.org/uuid now 200)"
else
    fail "Atomic-rename edit did not trigger reload (final HTTP=$HTTP_CODE, wait_rc=$RELOAD_RC)"
    echo "    --- proxy logs (last 30 lines) ---"
    dc logs --tail=30 proxy 2>&1 | sed 's/^/    /' || true
fi

# Summary
echo ""
echo "=== Results: $PASSED passed, $FAILED failed, $SKIPPED skipped ==="

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
