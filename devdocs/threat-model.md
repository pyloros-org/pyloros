# Threat model

This doc describes what pyloros is and isn't trying to protect against when
used as a sandbox egress control. Pair it with `examples/lima/README.md`
(full-machine sandbox) and `examples/docker-compose/README.md` (container
sandbox) for the two deployment shapes.

## What pyloros is

A forward HTTP(S) proxy with a rule engine. When deployed as an egress
chokepoint — meaning the thing being sandboxed cannot reach the network
*except* through pyloros — it can decide which requests are allowed based
on method, host, path, and (for git / git-LFS) repo URL and branch. It
logs every decision to a structured JSONL audit log.

Pyloros is not an IDS, not a WAF, and not a general-purpose packet filter.
It sees HTTP requests and TLS ClientHello SNIs; it does not see raw TCP,
UDP, or non-HTTP protocols.

## Assumed adversary

A process running inside the sandbox that is either:

- **Misbehaving**: a typosquatted dependency, a proc-macro with a bad
  `build.rs`, an AI agent that went off-script, a buggy script that
  accidentally posts secrets.
- **Compromised**: an attacker who achieved code execution inside the
  sandbox via one of the above and is now trying to exfiltrate data, pull
  a second-stage payload, or maintain a C2 channel.

The adversary has **root in the sandbox**. They can rewrite files, patch
binaries, flip iptables, disable DNS. They do *not* have root on the host
and cannot reach the kernel that enforces the sandbox boundary.

**Out of scope**: a local attacker on the developer's host, a compromised
pyloros binary, CA key theft from the host, supply-chain compromise of
pyloros itself.

## Enforcement layers

Pyloros can only enforce what a user can't bypass. The layer that provides
"can't bypass" is not pyloros — it's the sandbox boundary below it. There
are three commonly used shapes, ordered weakest → strongest:

### 1. Dev-loop (no sandbox boundary)

Pyloros started locally, shell/tools use `HTTP_PROXY` and trust the CA.
**Only enforces cooperation.** Any process that ignores `HTTP_PROXY` or
doesn't trust the CA bypasses pyloros entirely. Useful as a safety net for
honest tools and for generating audit logs, *not* as a security boundary.

### 2. Container sandbox (`examples/docker-compose/`)

Sandbox container on a Docker network with `internal: true`. No route to
the host/internet except via the pyloros container. Container-level kernel
isolation.
  - Holds against a process inside the container flipping its own env vars,
    iptables, or /etc/resolv.conf — there's still nowhere for packets to
    go except the pyloros container.
  - Does *not* hold against a container escape (CVE-class bugs in the
    runtime, privileged containers, exposed docker.sock, etc.).

### 3. VM sandbox (`examples/lima/`)

Sandbox VM whose network is a user-v2 network hosted by a Lima usernet
daemon. The daemon runs as a dedicated uid (`pyloros-nat`), and a host
iptables `OUTPUT ... -m owner --uid-owner pyloros-nat ! -d 10.99.0.1
! -o lo -j REJECT` rule caps the daemon's egress at the kernel level.
The VM's root cannot affect that rule — it lives in the host netns,
which the VM has no access to. See `examples/lima/README.md` for the
working setup.

  - Holds against: everything the container layer does, plus
    container-escape CVEs (the VM boundary absorbs those), plus an
    in-VM process that ignores `HTTP_PROXY` and tries to reach a
    hardcoded external IP — the daemon's `dial()` returns
    `ECONNREFUSED` from the host iptables reject.
  - Does *not* hold against a VM escape (CVE-class bugs in qemu/KVM)
    or anyone with shell on the host: that person can edit iptables,
    run as a different uid, or steal the pyloros CA key.

## Vectors that pyloros *does* block

These require being in layer 2 or 3 (actual sandbox boundary). In layer 1
they're advisory only.

### Unauthorized HTTPS destinations
A rule matches host+path+method. Requests to non-allowlisted hosts get
an HTTP 451 from pyloros and don't leave the proxy. The adversary can't
avoid this by resolving a different IP — SNI in the ClientHello is what
pyloros filters on, and the SNI is inside the TLS handshake the adversary
itself sends.

### Unauthorized git operations
Git rules distinguish `clone`/`fetch`/`push` by parsing the git smart-HTTP
protocol (pkt-line). Push to a non-allowlisted repo is blocked even if the
HTTPS endpoint is `github.com/*` broadly allowed.

### Branch-restricted push
`git.branches = ["main"]` limits the pkt-line refs an adversary can push.
They can't sneak a `refs/heads/exfil` push through a `refs/heads/main`
allowance.

### Hardcoded-IP exfiltration
In the VM sandbox the netns has no route except to pyloros. A process
that tries `curl https://1.2.3.4/` gets no route at all — the packet is
dropped at the routing layer before anything reaches TLS. The adversary
cannot exfil by pre-resolving and skipping DNS.

### C2 over arbitrary TCP
Any non-HTTP(S) TCP connection (reverse shell, custom protocol) lands on
pyloros's HTTPS or CONNECT port, where it either fails a TLS handshake
or is refused as a malformed proxy request. There's no unprotected TCP
channel out.

### DNS tunneling / DoH
Inside the VM sandbox, UDP/53 either has no route (if blocked) or goes to
the dnsmasq that answers every name with pyloros's IP — no wildcard
channel to an attacker-controlled resolver. DoH over HTTPS to
`cloudflare-dns.com` resolves to pyloros's IP, pyloros sees the SNI and
blocks it unless explicitly allowed.

## Vectors pyloros *does not* block

### Application-layer exfil inside allowed destinations
If your allowlist lets the adversary hit `api.github.com`, they can exfil
through `POST /gists`, `PATCH /repos/.../issues/N` (title/body), issue
comments, or any other API path within the allowlist. **Narrow the
allowlist at the path and method level** to limit this. Pyloros has
path-level rules for exactly this — use them.

### Exfil via git push to an allowed fork
A `git push` to an allowed repo *is* an exfil channel; the adversary can
push a branch containing stolen secrets. Branch restrictions narrow this
(`branches = ["claude/*"]`); a human code-review gate before merge is the
real defense. No proxy-level mitigation is complete here.

### Credential capture by the MITM
Pyloros sees every request body in the clear, including auth tokens.
That's a *feature* for audit logging, but it means the pyloros host
becomes a credential-bearing system. Protect the host accordingly; don't
run pyloros on a machine the adversary already has on-host access to.

### Covert channels inside allowed protocols
HTTP request timing, TLS record sizes, Server-Sent Events cadences — all
can carry data. Mitigation is out of scope; pyloros is not an anti-covert-
channel system.

### Any non-network vector
Clipboard, shared filesystem mounts, USB, the X11 socket, the docker
socket bind-mounted into the container, `/proc` leakage, etc. Pyloros
has zero visibility into these; they're the sandbox boundary's job.

### Compromised pyloros host
Already stated above. If the adversary gets code execution on the
pyloros host (or steals the CA key), the boundary collapses. The CA
key is equivalent in power to a CA trusted by every client in the
sandbox — treat it like one.

## Rule-writing principles

1. **Default-deny**. Pyloros is default-deny when configured correctly —
   no implicit allowlist. Adding a rule expands the surface; removing one
   reduces it.

2. **Method + path, not just host.** `* https://api.github.com/*` is a
   wide hole through which many bad things fit. `POST
   https://api.github.com/repos/$org/$repo/pulls` is narrow.

3. **Name the intent.** Every rule should exist because a specific tool
   or workflow needs it. Rules without an identifiable use get removed
   when audit logs show they're unused.

4. **Audit first, tighten after.** Run a week in a permissive mode with
   `log_requests = true`, look at what the honest workflow actually
   produces, then build the minimum ruleset that covers it. Rules derived
   from observed traffic are harder to socially-engineer additions to.

5. **Review the audit log when tightening.** After narrowing a rule,
   watch for `BLOCKED` entries that represent legitimate workflow — those
   are candidates for a further, narrower rule, not for reverting the
   tightening.
