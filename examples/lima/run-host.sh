#!/usr/bin/env bash
#
# Host-side setup for the Lima sandbox example.
#
# THIS IS CURRENTLY AN "ARCHITECTURAL STUB" — see `examples/lima/README.md`
# "Known limitation" section. The intended design puts the Lima usernet
# daemon in a netns whose only route is to pyloros on the host, making
# egress kernel-enforced. That design breaks Lima's `limactl shell` port
# forwarding (the daemon's SSH listener becomes unreachable from the host
# netns), so for now this script runs everything in the host netns with
# an iptables uid-match egress restriction TODO.
#
# What it does right now:
#   - creates a dedicated IP (10.99.0.1) on a dummy interface so pyloros
#     has a stable address to bind
#   - runs dnsmasq there with a wildcard that resolves every hostname to
#     that IP
#   - runs pyloros there (proxy :8080 + direct-HTTPS :443)
#   - tells you how to point a lima VM at it
#
# What it does NOT yet do:
#   - prevent the VM from talking to arbitrary external IPs by bypassing
#     the proxy (e.g., `curl https://1.1.1.1/`). The committed
#     lima-smoke-test.sh has an x-fail probe for exactly this case.
#
# Usage:
#   examples/lima/run-host.sh   # foreground, ctrl-C tears down

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${PYLOROS_BIN:=$here/../../target/release/pyloros}"
: "${PYLOROS_CA_DIR:=$here/../../certs}"
: "${PYLOROS_CONFIG:=$here/config.toml}"
: "${PYLOROS_HOST_IP:=10.99.0.1}"

for tool in dnsmasq ip sudo; do
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done
[[ -x "$PYLOROS_BIN" ]] || { echo "pyloros not at $PYLOROS_BIN" >&2; exit 1; }
[[ -f "$PYLOROS_CA_DIR/ca.crt" ]] || { echo "ca.crt missing in $PYLOROS_CA_DIR" >&2; exit 1; }
[[ -f "$PYLOROS_CONFIG" ]] || { echo "config missing at $PYLOROS_CONFIG" >&2; exit 1; }

pids=()
cleanup() {
  set +e
  local rc=$?
  echo
  echo "tearing down..."
  for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  sudo -n ip addr del "$PYLOROS_HOST_IP/24" dev pyloros0 2>/dev/null
  sudo -n ip link del pyloros0 2>/dev/null
  exit "$rc"
}
trap cleanup EXIT INT TERM

# --- 1. a dummy interface with the stable IP --------------------------------
echo "creating dummy interface pyloros0 at $PYLOROS_HOST_IP..."
sudo ip link del pyloros0 2>/dev/null || true
sudo ip link add pyloros0 type dummy
sudo ip addr add "$PYLOROS_HOST_IP/24" dev pyloros0
sudo ip link set pyloros0 up

# --- 2. dnsmasq with wildcard -----------------------------------------------
echo "starting dnsmasq (wildcard * -> $PYLOROS_HOST_IP)..."
sudo dnsmasq \
  --keep-in-foreground --no-resolv --no-hosts \
  --listen-address="$PYLOROS_HOST_IP" --bind-interfaces \
  --port=53 \
  --address="/#/$PYLOROS_HOST_IP" \
  --log-facility=- \
  --pid-file=/run/pyloros-dnsmasq.pid \
  &
pids+=($!)

# --- 3. pyloros -------------------------------------------------------------
sudo -n setcap 'cap_net_bind_service=+ep' "$PYLOROS_BIN"
echo "starting pyloros..."
"$PYLOROS_BIN" run \
  --config "$PYLOROS_CONFIG" \
  --ca-cert "$PYLOROS_CA_DIR/ca.crt" \
  --ca-key "$PYLOROS_CA_DIR/ca.key" \
  --bind "$PYLOROS_HOST_IP:8080" \
  --direct-https-bind "$PYLOROS_HOST_IP:443" \
  &
pids+=($!)

for i in {1..60}; do
  if (exec 3<>/dev/tcp/"$PYLOROS_HOST_IP"/8080) 2>/dev/null; then
    exec 3<&-; exec 3>&- 2>/dev/null
    break
  fi
  sleep 0.25
done

echo
echo "ready."
echo "  pyloros:   $PYLOROS_HOST_IP:8080 (CONNECT), :443 (direct-HTTPS)"
echo "  dnsmasq:   $PYLOROS_HOST_IP:53 (* -> $PYLOROS_HOST_IP)"
echo "start a sandbox lima VM with:"
echo "  limactl start --tty=false examples/lima/sandbox.yaml"
echo
echo "press ctrl-C to tear down."
wait
