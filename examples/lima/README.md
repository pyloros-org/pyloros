# Lima sandbox example

Run a Lima VM whose only network egress is a pyloros instance on the host.
Kernel-enforced: the VM has no route to the internet except through pyloros,
and pyloros applies rule-based filtering on top.

For the threat model — what this architecture does and doesn't protect
against — see [`devdocs/threat-model.md`](../../devdocs/threat-model.md).

## Architecture

```
  Host netns                              Sandbox netns (pyloros-sandbox)
  ┌──────────────────────┐    veth pair   ┌──────────────────────────────┐
  │ pyloros              │                │ limactl usernet              │
  │   :443 direct-HTTPS  │◄──────────────►│   (user-v2 netstack for      │
  │   :8080 CONNECT      │  10.99.0.1     │    the sandbox VM)           │
  │ dnsmasq              │  10.99.0.2     │                              │
  │   :53 * → 10.99.0.1  │                │ netns default route →        │
  └──────────────────────┘                │   10.99.0.1 only             │
                                          └──────────────────────────────┘
                                                        ▲
                                                        │ qemu sockets
                                                        │
                                          ┌──────────────────────────────┐
                                          │ Sandbox VM                   │
                                          │   resolv.conf → 10.99.0.1    │
                                          │   CA trust: pyloros CA       │
                                          │   HTTP_PROXY=http://10.99… │
                                          └──────────────────────────────┘
```

Every packet the VM emits is handled by the usernet daemon inside the
netns. That daemon's only possible `dial()` destination is `10.99.0.1`
(the netns's sole route). pyloros listens there; dnsmasq also listens
there and answers every DNS query with `10.99.0.1`. So the VM *can't even
learn* about another IP, and even if it tried one, the netns has no route.

## Status

Verified on Linux (Lima v2.1.1, qemu driver, Ubuntu 24.04 guest, nested
KVM). All three smoke-test probes pass:

- `curl https://api.github.com/zen` (rule-allowed) → 200
- `curl https://example.org/` (not allowlisted) → 451 from pyloros
- `curl --noproxy '*' https://1.1.1.1/` with proxy env unset → `Connection refused`

The bypass probe is the load-bearing one: it proves that a process inside
the VM can't escape to the internet by hardcoding an IP and skipping
`HTTP_PROXY`. Enforcement is kernel-level and uses no iptables inside
the sandbox.

macOS / vz would use `socket_vmnet` in `mode: host` instead of the
uid-match machinery below, and is not implemented here yet.

## How enforcement works (Path A — uid-match iptables)

The Lima usernet daemon is what translates the sandbox VM's virtual NIC
traffic into host-kernel `net.Dial()` calls. We run that daemon as a
dedicated system user (`pyloros-nat`) and add a host iptables rule:

```
iptables -I OUTPUT -m owner --uid-owner pyloros-nat \
  ! -d 10.99.0.1 ! -o lo -j REJECT
```

Anything that uid tries to send outbound that *isn't* a packet to
`10.99.0.1` (pyloros/dnsmasq) or via loopback (for Lima's own SSH
port-forward) gets rejected by the kernel before leaving the box. The VM
has no way to change that rule — it lives in the host netns, which the
VM's root has no access to.

The daemon still runs in the host netns so Lima's `limactl shell` SSH
port-forward keeps working (it needs to listen on `127.0.0.1:<port>` in
the host netns, reachable from the Lima hostagent).

## Prereqs

- Linux host with KVM (`/dev/kvm` accessible to your user)
- `qemu-system-x86` + `qemu-utils`
- `limactl` v2.0+ from https://github.com/lima-vm/lima/releases
- `dnsmasq`
- A pyloros release build (`cargo build --release`)
- A CA pair (`./target/release/pyloros generate-ca --out ./certs/`)
- A system user `pyloros-nat` that runs the Lima usernet daemon:
  ```bash
  sudo useradd --system --shell /usr/sbin/nologin pyloros-nat
  sudo usermod -aG zyla pyloros-nat    # traversal into ~/.lima
  ```
- `limactl` reachable on a path `pyloros-nat` can execute (typically
  `/usr/local/bin/limactl`; copy from your user install if needed):
  ```bash
  sudo install -m 755 "$(command -v limactl)" /usr/local/bin/limactl
  sudo cp -r "$(dirname $(command -v limactl))/../share/lima" /usr/local/share/
  ```
- Passwordless `sudo` for `ip`, `iptables`, `dnsmasq`, `chmod`, `usermod`,
  `setcap`, and `sudo -u pyloros-nat` (or accept the password prompt at
  `run-host.sh` startup)

Register the lima network once:

```bash
cat >> ~/.lima/_config/networks.yaml <<'EOF'
networks:
  pyloros-internal:
    mode: user-v2
    gateway: 192.168.199.1
    netmask: 255.255.255.0
EOF
```

The subnet here must match `PYLOROS_VM_SUBNET` in `run-host.sh`.

## Usage

Terminal A — host-side setup (leave running):

```bash
cd pyloros
examples/lima/run-host.sh
```

Terminal B — bring up the sandbox VM and shell in:

```bash
# Edit the `mounts:` path in examples/lima/sandbox.yaml to match your
# checkout, then:
limactl start --name sandbox --tty=false examples/lima/sandbox.yaml
limactl shell sandbox
```

Inside the sandbox:

```bash
curl -sS https://api.github.com/zen       # HTTP 200 — allowed by rule
curl -sS https://example.org/             # HTTP 451 — blocked by pyloros
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
curl --noproxy '*' --max-time 3 https://1.1.1.1/   # fails — no route
```

Tear down:

```bash
limactl stop -f sandbox && limactl delete -f sandbox
# then ctrl-C in terminal A
```

## Smoke test

`scripts/lima-smoke-test.sh` automates "start everything, run the three
probes, tear down, report pass/fail." Not run in CI (VMs generally aren't
available there) but useful locally:

```bash
scripts/lima-smoke-test.sh           # full cycle
scripts/lima-smoke-test.sh --keep    # leave the VM up after the checks
```

## What's enforced where

| Control                            | Enforced by                         |
| ---------------------------------- | ----------------------------------- |
| No route to anywhere but pyloros   | Host kernel routing in the netns    |
| Every DNS lookup → pyloros's IP    | dnsmasq wildcard                    |
| TLS MITM-able by pyloros           | CA trust in the VM                  |
| Rule-level host/path/method filter | pyloros `config.toml` rules         |
| Audit log of every request         | pyloros `logging.log_requests`      |

The top two are kernel-level and the VM's root cannot bypass them. The
bottom two are enforced by pyloros as a userspace process and assume the
netns boundary holds.

## Tuning

- **Multiple sandbox VMs**: attach them all to `pyloros-internal`. They
  share one pyloros and one CA but are each a separate qemu process.
- **Different rulesets per VM**: either run a second `run-host.sh` with a
  second network name + different `config.toml`, or switch to a single
  pyloros that routes by SNI to different rule sets (not currently a
  pyloros feature; file an issue if you want it).
- **No internet at all for the sandbox**: remove the dnsmasq `--address`
  wildcard so DNS returns NXDOMAIN; pyloros will never see traffic.

## Known rough edges

- The `mounts:` path in `sandbox.yaml` is a hardcoded absolute path. A
  follow-up can templatize via Lima's `param:` + `--set`.
- `dns:` in the Lima YAML isn't always honored by the `user-v2` driver;
  the provision script also rewrites `/etc/resolv.conf` as a backstop.
- First VM boot pulls ~600MB of cloud image + ~200MB of nerdctl archive
  (Lima's default). You can disable the nerdctl download by adding
  `containerd: {system: false, user: false}` to `sandbox.yaml`.
