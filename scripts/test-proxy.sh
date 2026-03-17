#!/usr/bin/env bash
#
# test-proxy.sh — Integration tests for pyloros-test-proxy.sh
#
# Prerequisites: curl, cargo build completed.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_PROXY_SCRIPT="$SCRIPT_DIR/pyloros-test-proxy.sh"

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
if ! command -v curl >/dev/null 2>&1; then
    echo "curl is not available. Skipping all tests."
    exit 0
fi

echo ""
echo "=== pyloros-test-proxy.sh Integration Tests ==="
echo ""

# Test 1: Allowed HTTPS request succeeds
echo "Test 1: Allowed HTTPS request through proxy"
set +e
OUTPUT=$(timeout 30 "$TEST_PROXY_SCRIPT" --rule 'GET https://example.com/*' \
    -- curl -sf https://example.com/ 2>/dev/null)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]] && echo "$OUTPUT" | grep -q "Example Domain"; then
    pass "Allowed HTTPS request succeeds and returns expected content"
else
    fail "Allowed HTTPS request (exit=$EXIT_CODE)"
    echo "    Output (last 10 lines):"
    echo "$OUTPUT" | tail -10 | sed 's/^/    /'
fi

# Test 2: Blocked URL returns 451
echo "Test 2: Blocked URL returns HTTP 451"
set +e
HTTP_CODE=$(timeout 30 "$TEST_PROXY_SCRIPT" --rule 'GET https://example.com/*' \
    -- curl -so /dev/null -w '%{http_code}' https://httpbin.org/get 2>/dev/null)
EXIT_CODE=$?
set -e

HTTP_CODE=$(echo "$HTTP_CODE" | tr -d '[:space:]')

if [[ "$HTTP_CODE" == "451" ]]; then
    pass "Blocked URL returns HTTP 451"
else
    fail "Expected HTTP 451, got '$HTTP_CODE' (exit=$EXIT_CODE)"
fi

# Test 3: Multiple rules work
echo "Test 3: Multiple rules"
set +e
OUTPUT=$(timeout 30 "$TEST_PROXY_SCRIPT" \
    --rule 'GET https://example.com/*' \
    --rule 'GET https://httpbin.org/*' \
    -- curl -sf https://httpbin.org/robots.txt 2>/dev/null)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]]; then
    pass "Multiple rules: second rule allows request"
else
    fail "Multiple rules failed (exit=$EXIT_CODE)"
    echo "    Output (last 5 lines):"
    echo "$OUTPUT" | tail -5 | sed 's/^/    /'
fi

# Test 4: --help works
echo "Test 4: --help flag"
set +e
HELP_OUTPUT=$("$TEST_PROXY_SCRIPT" --help 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]] && echo "$HELP_OUTPUT" | grep -q "pyloros-test-proxy.sh"; then
    pass "--help prints usage"
else
    fail "--help (exit=$EXIT_CODE)"
    echo "    Output:"
    echo "$HELP_OUTPUT" | head -5 | sed 's/^/    /'
fi

# Summary
echo ""
echo "=== Results: $PASSED passed, $FAILED failed, $SKIPPED skipped ==="

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
