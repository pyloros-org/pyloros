# Lima sandbox example

Two Lima VMs: a **pyloros proxy VM** with internet access, and a **sandbox VM**
whose only egress is through the proxy. Mirrors the `examples/docker-compose/`
setup but at VM scope instead of container scope — useful when you want
blast-radius isolation against a compromised guest process.

```
                host (your Linux/macOS box)
               ┌────────────────────────────────────┐
               │                                    │
               │   pyloros VM (eth0=192.168.104.1)  │
               │   └─ NIC on user-v2 only ──────────┼── internet (via user-v2
               │        (slirp is replaced)         │          gateway 192.168.104.2)
               │            │                       │
               │       192.168.104.0/24             │
               │            │                       │
               │   sandbox VM (eth0=192.168.104.3)  │
               │   └─ NIC on user-v2                │
               │        iptables OUTPUT DROP except │
               │        dst=192.168.104.1 :80/443/  │
               │        8080 and :53/udp            │
               └────────────────────────────────────┘
```

## Status

**Experimental.** Verified end-to-end on Lima v2.1.1 / Ubuntu 24.04 guest /
nested QEMU with KVM. Three smoke tests pass inside the sandbox:

- `curl https://api.github.com/zen` via `$PROXY_IP:8080` → HTTP 200
- `curl https://example.org/` via `$PROXY_IP:8080` → HTTP 451 (blocked by pyloros)
- `curl --noproxy '*' https://1.1.1.1/` → timeout (dropped by iptables)

## Caveats vs. the docker-compose example

- **Isolation is enforced by iptables inside the sandbox VM**, not by network
  topology. Lima on Linux only exposes `user-v2` for VM-to-VM networking, and
  that network has a NAT gateway to the host. If iptables is bypassed, the
  sandbox reaches the internet directly. The compose example's
  `networks.internal.internal: true` is a stricter topology-level block.
- **No DNS in the sandbox by default.** `resolv.conf` points at the proxy
  VM but pyloros isn't running a DNS server. Proxy-aware clients work
  (they send `CONNECT host:443` and let the proxy resolve), but tools that
  resolve names themselves will fail. Either add a dnsmasq sidecar on the
  proxy VM (like `examples/docker-compose/dns/`) or rely on `HTTP_PROXY`.
- Provisioning hardcodes absolute paths to the worktree checkout in the YAML.
  The `mounts:` blocks need hand-editing; a future pass can templatize via
  lima's `param:` + `--set` once the shape is locked in.

## Prereqs

- Linux host with KVM + vhost-vsock (`/dev/kvm`, `/dev/vhost-vsock`)
- `qemu-system-x86` + `qemu-utils`
- `limactl` v2.0+ (https://github.com/lima-vm/lima/releases)
- User in the `kvm` group
- Pyloros built (`cargo build --release`) and CA generated
  (`./target/release/pyloros generate-ca --out ./certs/`)

## Usage

```bash
# 1. Edit the three mount paths in pyloros.yaml and one in sandbox.yaml to
#    match your absolute checkout paths.

# 2. Register the user-v2 network in ~/.lima/_config/networks.yaml:
cat >> ~/.lima/_config/networks.yaml <<'EOF'
networks:
  pyloros-v2:
    mode: user-v2
    gateway: 192.168.104.1
    netmask: 255.255.255.0
EOF

# 3. Start the proxy VM
limactl start --name pyloros --tty=false examples/lima/pyloros.yaml

# 4. Start the sandbox VM (after proxy is Running)
limactl start --name sandbox --tty=false examples/lima/sandbox.yaml

# 5. Smoke test
limactl shell sandbox -- curl -sS https://api.github.com/zen      # allowed
limactl shell sandbox -- curl -sS https://example.org/            # blocked by pyloros
limactl shell sandbox -- curl -sS --max-time 3 https://1.1.1.1/   # dropped by iptables

# Tear down
limactl stop pyloros sandbox && limactl delete pyloros sandbox
```
