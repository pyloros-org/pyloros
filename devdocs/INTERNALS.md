# Internals

Implementation-level rationale and architecture details that supplement the high-level
spec in `SPEC.md`. Record design decisions and tool issues directly here.

## rustls + rcgen vs OpenSSL

Evaluated shelling out to `openssl` CLI for cert generation — it would only replace
~85 lines of rcgen code while adding a runtime system dependency, fork+exec latency
on the per-host hot path, and temp file management. Not worth the tradeoff.

## E2E Test Architecture

E2E tests exercise the full request flow: client → proxy (MITM) → upstream → response.

The proxy binds to port 0 and exposes its actual address via `bind()` /
`serve_until_shutdown()` split on `ProxyServer`.

Since CONNECT is restricted to port 443 but test upstreams run on random ports,
`TunnelHandler` supports an `upstream_port_override` that redirects forwarded
connections to the test upstream's actual port. Similarly, `upstream_tls_config`
allows injecting a `rustls::ClientConfig` that trusts the test CA (instead of webpki
roots).

These overrides are also exposed as optional config fields (`upstream_override_port`,
`upstream_tls_ca`) so that binary-level tests can exercise the real CLI binary with
`curl`.

For binary-level tests, the proxy prints its actual listening address to stderr so
tests can use `bind_address = "127.0.0.1:0"` and discover the port at runtime.

Live API tests check for OAuth credentials at `~/.claude/.credentials.json` and skip
when unavailable.

## Git Rules Implementation

Git rules are syntactic sugar over the git smart HTTP protocol endpoints. A git rule
compiles into internal URL matchers at rule load time, so there is no runtime overhead
compared to writing the raw HTTP rules by hand.

### Smart HTTP endpoint mapping

Git smart HTTP uses four endpoints per repo:

| Operation | Method | URL                                            |
|-----------|--------|------------------------------------------------|
| fetch discovery | GET | `<repo>/info/refs?service=git-upload-pack`  |
| fetch data      | POST | `<repo>/git-upload-pack`                   |
| push discovery  | GET | `<repo>/info/refs?service=git-receive-pack` |
| push data       | POST | `<repo>/git-receive-pack`                  |

A `git = "fetch"` rule expands into matchers for the first two; `git = "push"` into the
last two; `git = "*"` into all four. The `url` from the rule is used as the `<repo>`
prefix — wildcards in the URL carry through naturally (e.g.
`https://github.com/org/*` → `https://github.com/org/*/info/refs?service=git-upload-pack`).

Additionally, each git rule generates LFS endpoints:

| Operation | Method | URL | fetch | push |
|-----------|--------|-----|-------|------|
| LFS batch | POST | `<repo>/info/lfs/objects/batch` | yes (body-inspected) | yes (body-inspected) |
| Lock list | GET | `<repo>/info/lfs/locks` | yes | yes |
| Lock create | POST | `<repo>/info/lfs/locks` | no | yes |
| Lock verify | POST | `<repo>/info/lfs/locks/verify` | yes | yes |
| Lock unlock | POST | `<repo>/info/lfs/locks/*/unlock` | no | yes |

The LFS batch endpoint uses `AllowedWithLfsCheck` for body inspection of the
`operation` field. Lock endpoints are plain `Allowed` rules (no body inspection
needed). For `git = "*"`, the push superset of lock endpoints is used (via
`else if` to avoid duplicates).

### Branch restriction via pkt-line inspection

The `branches` field on push rules requires inspecting the request body of the
`POST .../git-receive-pack` request. The body format is:

```
<old-sha> <new-sha> <ref-name>\0<capabilities>\n   ← first command
<old-sha> <new-sha> <ref-name>\n                   ← subsequent commands
0000                                                ← flush packet
<...pack data...>
```

Each line is prefixed with a 4-hex-digit length (pkt-line format). The ref update
commands are plaintext and come before any binary pack data, so inspection only needs
to buffer the first few hundred bytes.

The proxy reads pkt-lines until the flush packet (`0000`), extracts the ref names from
each command, checks them against the `branches` patterns, and either blocks the entire
request or forwards it (re-sending the buffered pkt-lines followed by the remaining
body stream).

### Git protocol error responses for blocked pushes

When a push is blocked by branch restrictions, the proxy returns a proper git
`receive-pack` response instead of HTTP 451. Git clients can't display HTTP response
bodies, so HTTP 451 produces cryptic errors like "the remote end hung up unexpectedly".

The proxy generates an HTTP 200 response with `Content-Type: application/x-git-receive-pack-result`
containing:

1. The client's capabilities are extracted from the first pkt-line (`report-status` or
   `report-status-v2`, `side-band-64k`).
2. A `report-status` payload is built: `unpack ok\n` followed by `ng <ref> blocked by
   proxy policy\n` for each blocked ref, terminated by a flush packet.
3. When `side-band-64k` is negotiated, the report-status is wrapped in sideband channel 1,
   and a human-readable message is sent on channel 2 (displayed as `remote: ...`).

This matches how server-side `pre-receive` hooks report errors, so git clients display:
```
remote: pyloros: push to branch 'main' blocked by proxy policy
 ! [remote rejected] main -> main (blocked by proxy policy)
```

Both `report-status` (v1) and `report-status-v2` capabilities are recognized; the v1
response format is a valid subset of v2, so the same response works for both.

This approach only applies to branch-level blocking (`AllowedWithBranchCheck`). Endpoint-level
blocking (`FilterResult::Blocked` for git-receive-pack URLs) and plain HTTP continue to
return HTTP 451, since the proxy doesn't have the request body available to extract
capabilities.

### Git-LFS batch endpoint support

Git-LFS uses `POST {repo}/info/lfs/objects/batch` with a JSON body containing an
`"operation"` field (`"download"` or `"upload"`). Each git rule now generates an
additional compiled rule for this endpoint alongside the smart HTTP endpoint rules.

**Operation mapping**: `git = "fetch"` → `"download"`, `git = "push"` → `"upload"`,
`git = "*"` → both. This is a natural extension of how fetch/push map to smart HTTP
endpoints.

**Merged-scan for LFS rules**: Unlike branch checks (which short-circuit on first match),
LFS batch endpoint rules accumulate allowed operations across all matching rules before
checking the body. This prevents a common configuration pattern — separate `git = "fetch"`
and `git = "push"` rules for the same repo — from blocking LFS: the fetch rule's
`["download"]` and push rule's `["upload"]` merge to `["download", "upload"]`.

**Branch restrictions don't apply to LFS**: LFS blobs are content-addressed by SHA-256.
The blob itself carries no ref information — the actual ref update goes through
`git-receive-pack` where branch restrictions are already enforced. Applying branch
patterns to LFS would be meaningless and would break uploads.

**Transfer URLs are out of scope**: LFS batch responses contain transfer URLs (often on
external hosts like S3/Azure Blob) for actual object upload/download. These are opaque
to the proxy and not automatically allowed — users must add separate HTTP rules for the
transfer hosts. This is intentional: the proxy shouldn't assume which external hosts are
acceptable just because git smart HTTP access is allowed.

**Plain HTTP blocking**: Like `AllowedWithBranchCheck`, `AllowedWithLfsCheck` requires
HTTPS body inspection. On plain HTTP, it is blocked with HTTP 451 (default-deny for
unverifiable restrictions).

## Config Live-Reload

The proxy watches its config file for changes using the `notify` crate (inotify on
Linux, kqueue on macOS) and reloads when the file is modified. SIGHUP is also
supported on Unix.

### Architecture

`serve(mut self, ...)` owns all `ProxyServer` fields. A `tokio::sync::mpsc` channel
carries reload triggers from three sources:

1. **File watcher** — a background `std::thread` runs `notify::recommended_watcher`
   on the config file's parent directory, filtering by filename and debouncing at
   200ms. Watching the parent (not the file) handles editor write-to-tmp + rename
   patterns that change the file's inode.
2. **SIGHUP handler** (Unix) — a `tokio::spawn`ed task listens for `SIGHUP` signals.
3. **Explicit channel** (tests) — `reload_trigger()` returns a `Sender<()>` that
   tests use to trigger deterministic reloads.

All three send `()` to the same channel. The accept loop receives via
`tokio::select!` alongside shutdown and accept branches.

### What gets reloaded

On reload, `apply_reload()` re-reads the config file from disk and:

- Compiles a new `FilterEngine` and `CredentialEngine`
- Re-resolves `auth_username` / `auth_password` (including `${ENV_VAR}` expansion)
- Reopens the audit logger if the path changed
- Replaces `self.config` and rebuilds `tunnel_handler`

Non-reloadable fields (`bind_address`, `ca_cert`, `ca_key`) are compared against
the running config; changes log a warning but are not applied.

If any step fails (bad TOML, rule compilation error, missing env var), the entire
reload is aborted and the proxy continues with the previous valid config.

### Connection isolation

Existing connections are unaffected by reloads. `spawn_connection()` clones the
current `Arc<FilterEngine>`, `Arc<TunnelHandler>`, etc. at connection time. After
a reload, only new connections see the updated config. This is the same isolation
model used for all shared state in the proxy.

### Test infrastructure

`ReloadableProxy` (in `tests/config_reload_test.rs`) wraps `ProxyServer` with a
temp config file, explicit reload trigger, and `Notify`-based completion signal.
Tests write a new config, send on the trigger, and `await` the `Notify` to ensure
the reload is fully applied before making assertions. A new `reqwest::Client` must
be created after reload because reqwest pools CONNECT tunnels.

## Upstream TLS Root CAs

By default, the proxy trusts both `webpki-roots` (Mozilla's bundled root CA bundle) and
native/system root certificates loaded via `rustls-native-certs`. This matches the behavior
of most Rust HTTP clients (reqwest, etc.) and ensures compatibility with servers whose
certificate chains use roots present in the OS store but not in the Mozilla bundle.

The `upstream_tls_ca` config option overrides both sources — when set, only the specified
CA cert is trusted. This is used in tests with self-signed upstream servers.

The Alpine Docker image includes `ca-certificates` so that native cert loading works
inside containers.

## Docker Image

### Alpine over scratch

Alpine adds ~7MB over a `scratch` image but provides a shell (ash) for healthchecks
and debugging. `wget --spider` is available out of the box for compose healthchecks,
whereas `scratch` would require a custom healthcheck binary or none at all.

### Single-stage Dockerfile

The Dockerfile copies a pre-built binary rather than building inside Docker. The CI
workflow already builds a statically-linked musl binary and verifies it — duplicating
that build in a multi-stage Dockerfile would add complexity and build time for no
benefit. The binary is copied to the build context root before `docker build`.

### Healthcheck with nc

Alpine doesn't include bash, so the previous `bash -c 'echo > /dev/tcp/...'` healthcheck
doesn't work. Since the proxy returns HTTP 451 for unmatched requests (including
healthcheck probes to `http://127.0.0.1:8080/`), HTTP-level checks like `wget --spider`
fail. Instead, `nc -z 127.0.0.1 8080` performs a TCP port check — available via BusyBox
in Alpine without extra packages.

## Force-push detection

`protected_branches` (see SPEC) requires fast-forward-only updates. Detection runs
against the receive-pack body after the pkt-line ref commands: the remaining bytes
are a git packfile, and we walk commit parents in that pack from `new-sha` toward
`old-sha`. A true fast-forward pack always contains the chain of new commits linking
back to `old-sha`; a forced/rewrite pack does not.

### Why a hand-rolled pack parser (src/filter/pack.rs)

The obvious choice was `gix` / `gix-pack`, but gitoxide pulls a very large dep tree
(ICU, the whole object-database machinery, async glue) for what is — in our case —
a small, read-only, in-memory task. The parser we need only has to:

1. Read the pack header and per-object headers.
2. Decompress zlib streams for commit objects.
3. Resolve OFS_DELTA and REF_DELTA chains (since git frequently deltifies commits
   against each other within its pack window).
4. Compute object SHAs (SHA-1 via `ring`, already a dep).
5. Extract `parent <sha>` lines from commit objects.

That fits in one file (~500 LOC) plus `flate2` for zlib, which has a much smaller
surface than the full gitoxide stack. If we ever need tree/blob inspection or index
writing, revisit this tradeoff — `gix` is then the right call.

### Thin-pack handling

Git push packs are thin by default: base objects the server already has are omitted.
For our check this means the commit object whose SHA is `old-sha` is usually NOT in
the pushed pack. That is fine — a fast-forward pack still contains a commit `C`
whose `parent` line is `old-sha`. Our BFS walks commits in the pack and reports
`IsAncestor` as soon as any visited commit's parent list contains `old-sha`, even
when `old-sha` itself is not resolvable as a pack object.

REF_DELTA objects with bases outside the pack are unresolvable. If any commit delta
chain hits such an external base, we return `Indeterminate`, which the caller treats
as a block (fail closed). In practice commit deltification within a single push
tends to stay inside the pack (OFS_DELTA); external REF_DELTA bases are uncommon
for commits.

### Why no index file

`gix-pack` wants a `.idx` file to look up objects by SHA. We don't have one. Rather
than build one, we do two linear passes: first, SHA-ify all non-delta objects and
build an in-memory SHA → index map; second, iteratively resolve deltas whose bases
(by offset or SHA) are already known. Iteration terminates because each pass either
resolves at least one object or makes no progress (all remaining deltas have
unresolvable external bases).

### Upstream want/have fallback (src/filter/upstream_negotiate.rs)

The pack walk alone produces false positives: if a fast-forward push carries zero
or few new commits (because `new-sha` already exists on the server under another
ref, or because an intermediate commit in the chain is server-known and the pack
is thin), the walk has no edges to follow and reports `NotAncestor`. We can't
distinguish that from a genuine force-push.

So on `NotAncestor`/`Indeterminate` from the pack walk, the proxy issues its own
`POST <repo>/git-upload-pack` to the upstream, using protocol v2 with
`command=fetch` + `want=<new-sha>` + `have=<old-sha>` + `done`. The server is the
authoritative source on its own commit graph and responds with:

- `ACK <old-sha> ready` — `old-sha` is reachable from `new-sha`. Fast-forward.
- `NAK` — no common ancestor. Force-push.
- Anything else (transport error, `ERR unknown want`, unparseable response) —
  fail closed: block.

Credentials are copied from the client's `Authorization` header (same as the
normal push forward). Host/port/TLS use the same overrides as the main proxy
path, so tests can point the sidecar at a local test upstream.

### Natural extension (not implemented)

The same negotiation machinery generalizes to tree/content inspection: v2
`command=fetch` with `want`/`have` returns a `packfile` section after
`acknowledgments` containing the commits (and optionally trees, via `filter=...`)
between the two SHAs. A future "ban binaries on protected branches" or "require
signed commits" check could walk the pushed pack first, then fetch a completion
pack for any missing range, and inspect trees/blobs across the combined object
set. The pack parser already handles all object types via the same delta
resolution. Not built yet — noted for future reference.

