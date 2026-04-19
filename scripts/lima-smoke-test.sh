#!/usr/bin/env bash
#
# lima-smoke-test.sh — End-to-end smoke test for the Lima sandbox example.
#
# Starts `examples/lima/run-host.sh` in the background, boots the sandbox
# Lima VM, runs three probes, and reports pass/fail. Tears everything down
# on exit.
#
# This is NOT run in CI (CI generally doesn't permit nested virtualization).
# Use it as a dev-loop check when changing the example or the host setup.
#
# Prereqs:
#   - Build pyloros:       cargo build --release
#   - Have a CA:           ./target/release/pyloros generate-ca --out ./certs/
#   - Lima >= 2.0 with the qemu driver (Linux) or vz (macOS)
#   - dnsmasq installed on the host
#   - Passwordless sudo for `ip netns`, `ip link`, `dnsmasq` (edit sudoers
#     if running unattended)
#   - `~/.lima/_config/networks.yaml` has a `pyloros-internal` user-v2 net
#     whose subnet matches PYLOROS_VM_SUBNET in run-host.sh
#
# Usage:
#   scripts/lima-smoke-test.sh              # run all three probes
#   scripts/lima-smoke-test.sh --keep       # leave the VM up after the test
#                                             (useful for poking around)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

KEEP=false
[[ "${1:-}" == "--keep" ]] && KEEP=true

log()   { printf '[lima-smoke] %s\n' "$*"; }
die()   { printf '[lima-smoke] FAIL: %s\n' "$*" >&2; exit 1; }

host_pid=""
cleanup() {
  set +e
  local rc=$?
  if ! $KEEP; then
    log "deleting sandbox VM"
    limactl stop -f sandbox 2>/dev/null
    limactl delete -f sandbox 2>/dev/null
  else
    log "--keep: leaving sandbox VM running"
  fi
  if [[ -n "$host_pid" ]]; then
    log "stopping run-host.sh (pid=$host_pid)"
    kill "$host_pid" 2>/dev/null
    wait "$host_pid" 2>/dev/null
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

command -v limactl >/dev/null || die "limactl not on PATH"
[[ -x "$repo/target/release/pyloros" ]] || die "build pyloros first: cargo build --release"
[[ -f "$repo/certs/ca.crt" && -f "$repo/certs/ca.key" ]] || \
  die "missing CA: ./target/release/pyloros generate-ca --out ./certs/"

# --- 1. Launch run-host.sh in the background ------------------------------
log "starting host setup (netns + dnsmasq + pyloros + usernet daemon)..."
"$repo/examples/lima/run-host.sh" >/tmp/lima-smoke-host.log 2>&1 &
host_pid=$!

# Wait for pyloros's CONNECT port to accept
ready=false
for i in {1..60}; do
  if (exec 3<>/dev/tcp/10.99.0.1/8080) 2>/dev/null; then
    exec 3<&-; exec 3>&- 2>/dev/null
    ready=true
    break
  fi
  sleep 0.5
  if ! kill -0 "$host_pid" 2>/dev/null; then
    tail -40 /tmp/lima-smoke-host.log >&2
    die "run-host.sh exited before pyloros came up"
  fi
done
$ready || { tail -40 /tmp/lima-smoke-host.log >&2; die "pyloros didn't bind within 30s"; }
log "pyloros listening on 10.99.0.1:8080"

# --- 2. Boot the sandbox VM ------------------------------------------------
log "booting sandbox VM (this takes ~2 minutes)..."
limactl delete -f sandbox 2>/dev/null || true
limactl start --name sandbox --tty=false "$repo/examples/lima/sandbox.yaml" \
  >/tmp/lima-smoke-vm.log 2>&1 || {
    tail -40 /tmp/lima-smoke-vm.log >&2
    die "limactl start failed"
  }
log "sandbox VM up"

# --- 3. Probes -------------------------------------------------------------
# Each probe runs a command in the sandbox VM; passes iff the command's
# combined stdout+stderr matches the expected regex.
pass=0; fail=0
probe() {
  local name="$1" expected_re="$2"; shift 2
  # Strip the cd-error that limactl prints when the host cwd isn't present
  # in the guest; it's noise, not part of our command's output.
  local out rc=0
  out=$(limactl shell sandbox -- bash -c "$*" 2>&1 | grep -v "^bash: line 1: cd: ") || rc=$?
  if [[ "$out" =~ $expected_re ]]; then
    printf '  ok    %-34s :: %s\n' "$name" "${out//$'\n'/ | }"
    pass=$((pass+1))
  else
    printf '  FAIL  %-34s want=/%s/ rc=%s out=%s\n' "$name" "$expected_re" "$rc" "${out//$'\n'/ | }"
    fail=$((fail+1))
  fi
}

log "running probes..."

# Allowed path: HTTPS via explicit CONNECT proxy (HTTP_PROXY env is set)
probe "allowed https api.github.com" '^200$' \
  'curl -sS -o /dev/null -w "%{http_code}" https://api.github.com/zen'

# Blocked by pyloros: example.org — matches no rule, expect 451.
probe "blocked-by-pyloros example.org" '^451$' \
  'curl -sS -o /dev/null -w "%{http_code}" https://example.org/'

# Bypass attempt: connect directly to 1.1.1.1 with proxy env unset.
# This probe is CURRENTLY EXPECTED TO FAIL — see the "Known limitation"
# section in examples/lima/README.md. When the egress-hardening follow-up
# lands, this should start passing and the x-fail wrapper can be removed.
xfail_probe() {
  local name="$1" expected_re="$2"; shift 2
  local out rc=0
  out=$(limactl shell sandbox -- bash -c "$*" 2>&1 | grep -v "^bash: line 1: cd: ") || rc=$?
  if [[ "$out" =~ $expected_re ]]; then
    printf '  ok    %-34s :: (no longer x-failing — drop the wrapper)\n' "$name"
    pass=$((pass+1))
  else
    printf '  xfail %-34s :: %s\n' "$name" "known leak; see README"
    # do NOT increment fail — this is expected until the netns-or-uid fix lands
  fi
}
xfail_probe "bypass-attempt 1.1.1.1 direct" \
  '(Failed to connect|timed out|Connection refused|No route to host|Network is unreachable)' \
  'unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY; curl --noproxy "*" --max-time 4 -v https://1.1.1.1/ 2>&1'

echo
if (( fail == 0 )); then
  log "all $pass probes passed"
else
  log "$pass passed, $fail FAILED"
  exit 1
fi
