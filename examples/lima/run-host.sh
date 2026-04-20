#!/usr/bin/env bash
#
# Host-side setup for the Lima sandbox example (egress-hardened).
#
# Architecture:
#   - pyloros + dnsmasq listen on 10.99.0.1 (a dummy interface on the host)
#   - lima usernet daemon runs as a dedicated uid (pyloros-nat), serving
#     the `pyloros-internal` lima user-v2 network to sandbox VMs
#   - an iptables OUTPUT rule on the host REJECTs every outbound packet
#     from that uid whose destination isn't 10.99.0.1
#
# Result: the sandbox VM can only reach pyloros. A process inside the VM
# that hardcodes an external IP and bypasses HTTP_PROXY still has its
# packets translated to a net.Dial by the usernet daemon — and that dial
# is rejected by host iptables because the uid isn't allowed to reach
# anything except 10.99.0.1. Kernel-enforced; VM root can't undo it.
#
# Threat model: devdocs/threat-model.md.
# Known limitations still apply for non-network vectors (mounts, VM
# escape, compromised host).
#
# Usage: examples/lima/run-host.sh       (foreground, ctrl-C to clean up)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${PYLOROS_BIN:=$here/../../target/release/pyloros}"
: "${PYLOROS_CA_DIR:=$here/../../certs}"
: "${PYLOROS_CONFIG:=$here/config.toml}"
: "${PYLOROS_HOST_IP:=10.99.0.1}"
: "${PYLOROS_LIMA_NET:=pyloros-internal}"
: "${PYLOROS_VM_SUBNET:=192.168.199.0/24}"
: "${PYLOROS_NAT_USER:=pyloros-nat}"

lima_net_dir="$HOME/.lima/_networks/$PYLOROS_LIMA_NET"
pid_file="$lima_net_dir/usernet_${PYLOROS_LIMA_NET}.pid"
ep_sock="$lima_net_dir/${PYLOROS_LIMA_NET}_ep.sock"
qemu_sock="$lima_net_dir/${PYLOROS_LIMA_NET}_qemu.sock"
fd_sock="$lima_net_dir/${PYLOROS_LIMA_NET}_fd.sock"

for tool in limactl dnsmasq ip sudo iptables; do
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done
[[ -x "$PYLOROS_BIN" ]] || { echo "pyloros not at $PYLOROS_BIN" >&2; exit 1; }
[[ -f "$PYLOROS_CA_DIR/ca.crt" ]] || { echo "ca.crt missing in $PYLOROS_CA_DIR" >&2; exit 1; }
[[ -f "$PYLOROS_CONFIG" ]] || { echo "config missing at $PYLOROS_CONFIG" >&2; exit 1; }

# One-time check: NAT user must exist. Create with:
#   sudo useradd --system --shell /usr/sbin/nologin pyloros-nat
id "$PYLOROS_NAT_USER" >/dev/null 2>&1 || {
  echo "missing system user '$PYLOROS_NAT_USER'. Create with:" >&2
  echo "  sudo useradd --system --shell /usr/sbin/nologin $PYLOROS_NAT_USER" >&2
  exit 1
}
nat_uid=$(id -u "$PYLOROS_NAT_USER")

pids=()
cleanup() {
  set +e
  local rc=$?
  echo
  echo "tearing down..."
  for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null; done
  # kill children that backgrounded themselves as pyloros-nat
  sudo -n pkill -u "$PYLOROS_NAT_USER" -f 'limactl usernet' 2>/dev/null
  wait 2>/dev/null
  sudo -n iptables -D OUTPUT -m owner --uid-owner "$nat_uid" \
    ! -d "$PYLOROS_HOST_IP" ! -o lo -j REJECT 2>/dev/null
  sudo -n ip addr del "$PYLOROS_HOST_IP/24" dev pyloros0 2>/dev/null
  sudo -n ip link del pyloros0 2>/dev/null
  rm -f "$pid_file" "$ep_sock" "$qemu_sock" "$fd_sock"
  exit "$rc"
}
trap cleanup EXIT INT TERM

mkdir -p "$lima_net_dir"
# Socket dir must be readable + searchable by both users.
sudo -n chgrp "$PYLOROS_NAT_USER" "$lima_net_dir"
sudo -n chmod 0770 "$lima_net_dir"
sudo -n usermod -aG "$PYLOROS_NAT_USER" "$USER" >/dev/null 2>&1 || true
# (usermod change doesn't take effect in current shell — rely on sg below)

# --- 1. dummy interface with the stable IP --------------------------------
echo "creating dummy interface pyloros0 at $PYLOROS_HOST_IP..."
sudo ip link del pyloros0 2>/dev/null || true
sudo ip link add pyloros0 type dummy
sudo ip addr add "$PYLOROS_HOST_IP/24" dev pyloros0
sudo ip link set pyloros0 up

# --- 2. uid-match egress rule ---------------------------------------------
# Reject anything from the nat user going anywhere other than pyloros.
# This is the actual security boundary — kernel-enforced, host-scoped.
echo "installing iptables uid-match egress rule (uid=$nat_uid -> only $PYLOROS_HOST_IP + loopback)..."
# The `! -o lo` exception lets the daemon's SSH port-forward listener
# reply to local connections from the Lima hostagent (127.0.0.1:<port>).
# External egress is still confined to PYLOROS_HOST_IP.
sudo iptables -C OUTPUT -m owner --uid-owner "$nat_uid" \
  ! -d "$PYLOROS_HOST_IP" ! -o lo -j REJECT 2>/dev/null || \
  sudo iptables -I OUTPUT -m owner --uid-owner "$nat_uid" \
    ! -d "$PYLOROS_HOST_IP" ! -o lo -j REJECT

# --- 3. dnsmasq: wildcard * → pyloros ------------------------------------
echo "starting dnsmasq..."
sudo dnsmasq \
  --keep-in-foreground --no-resolv --no-hosts \
  --listen-address="$PYLOROS_HOST_IP" --bind-interfaces \
  --port=53 \
  --address="/#/$PYLOROS_HOST_IP" \
  --log-facility=- \
  --pid-file=/run/pyloros-dnsmasq.pid \
  &
pids+=($!)

# --- 4. pyloros (binds :443 via CAP_NET_BIND_SERVICE) --------------------
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

# --- 5. lima usernet daemon as the nat user -------------------------------
# Sockets go in $lima_net_dir; that dir is group-writable for the nat user's
# group and world-readable so Lima's hostagent (running as $USER) can
# connect to them. umask=0002 keeps the sockets group-accessible.
echo "starting limactl usernet as $PYLOROS_NAT_USER..."
# Resolve limactl explicitly from a location readable by the nat user.
# The user's PATH may point to ~/.local/lima/bin which pyloros-nat can't
# traverse (home dir is typically 700), so fall back to /usr/local/bin
# and /usr/bin.
limactl_for_nat=$(PATH=/usr/local/bin:/usr/bin command -v limactl 2>/dev/null || true)
if [[ -z "$limactl_for_nat" ]]; then
  echo "No system-wide limactl found for $PYLOROS_NAT_USER. Install it:" >&2
  echo "  sudo install -m 755 \$(command -v limactl) /usr/local/bin/limactl" >&2
  echo "  sudo cp -r \$(dirname \$(command -v limactl))/../share/lima /usr/local/share/" >&2
  exit 1
fi
sudo -n -u "$PYLOROS_NAT_USER" \
    env HOME=/var/lib/pyloros-nat PATH=/usr/local/bin:/usr/bin \
    bash -c "umask 0002; exec '$limactl_for_nat' usernet \
      --subnet '$PYLOROS_VM_SUBNET' \
      -p '$pid_file' \
      -e '$ep_sock' \
      --listen-qemu '$qemu_sock' \
      --listen '$fd_sock'" \
  &
pids+=($!)

# wait for the sockets to exist, then fix perms so $USER can talk to them
for i in {1..30}; do
  [[ -S "$qemu_sock" ]] && break
  sleep 0.2
done
[[ -S "$qemu_sock" ]] && sudo -n chmod 0666 "$qemu_sock" "$fd_sock" "$ep_sock" 2>/dev/null

echo
echo "ready."
echo "  pyloros:    $PYLOROS_HOST_IP:{8080,443}"
echo "  dnsmasq:    $PYLOROS_HOST_IP:53 (* -> $PYLOROS_HOST_IP)"
echo "  lima net:   $PYLOROS_LIMA_NET (subnet $PYLOROS_VM_SUBNET)"
echo "  egress:     iptables REJECT uid=$nat_uid ! -> $PYLOROS_HOST_IP"
echo
echo "start a sandbox VM with:"
echo "  limactl start --tty=false examples/lima/sandbox.yaml"
echo
echo "ctrl-C to tear down."
wait
