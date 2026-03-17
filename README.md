# Pyloros

*From Greek πυλωρός (pyloros) — πύλη (gate) + οὖρος (guard). A gatekeeper.*

A default-deny allowlist-based HTTPS filtering proxy for controlling AI agent network access.

## Overview

Pyloros is an HTTP/HTTPS proxy that blocks all network requests by default and only allows traffic matching explicit allowlist rules. It is designed for environments where AI agents need controlled internet access — the proxy intercepts HTTPS traffic via MITM TLS, inspects the full URL (host, path, query), and enforces method-level allowlist rules.

The intended deployment is **one proxy per VM or container** running an AI agent. All outbound traffic is routed through the proxy via standard `HTTP_PROXY`/`HTTPS_PROXY` environment variables, giving full visibility and control over the agent's network access.

Blocked requests receive HTTP 451 (Unavailable For Legal Reasons).

## Installation

### Pre-built binary (Linux x86_64)

Download the latest statically-linked binary from [GitHub Releases](https://github.com/zyla/pyloros/releases/latest):

```bash
curl -sL https://github.com/zyla/pyloros/releases/latest/download/pyloros-$(curl -sL https://api.github.com/repos/zyla/pyloros/releases/latest | grep tag_name | cut -d '"' -f4)-x86_64-unknown-linux-musl.tar.gz | tar xz
sudo mv pyloros-*/pyloros /usr/local/bin/
```

Or download a specific version:

```bash
VERSION=v0.1.0
curl -sL https://github.com/zyla/pyloros/releases/download/${VERSION}/pyloros-${VERSION}-x86_64-unknown-linux-musl.tar.gz | tar xz
sudo mv pyloros-${VERSION}-x86_64-unknown-linux-musl/pyloros /usr/local/bin/
```

### Docker image

A Docker image is published to `ghcr.io/zyla/pyloros`:

```bash
docker pull ghcr.io/zyla/pyloros:latest
```

Available tags:
- `vX.Y.Z` — specific release version
- `latest` — most recent release
- `edge` — latest build from `main` (may be unstable)

Run directly:

```bash
docker run --rm \
  -v ./config.toml:/etc/pyloros/config.toml:ro \
  -v ./certs:/certs:ro \
  -p 8080:8080 \
  ghcr.io/zyla/pyloros:latest \
  run --config /etc/pyloros/config.toml \
      --ca-cert /certs/ca.crt --ca-key /certs/ca.key \
      --bind 0.0.0.0:8080
```

### Latest development build

A rolling pre-release is built from `main` on every push:

```bash
curl -sL https://github.com/zyla/pyloros/releases/download/latest/pyloros-latest-x86_64-unknown-linux-musl.tar.gz | tar xz
sudo mv pyloros-latest-x86_64-unknown-linux-musl/pyloros /usr/local/bin/
```

### Building from source

Prerequisites: [Rust](https://www.rust-lang.org/tools/install) (stable toolchain).

```bash
git clone https://github.com/zyla/pyloros.git
cd pyloros
cargo build --release
```

The compiled binary is at `target/release/pyloros`.

## Quick Start

### 1. Generate a CA certificate

```bash
pyloros generate-ca --out ./certs/
```

This creates `certs/ca.crt` and `certs/ca.key`.

### 2. Trust the CA

On Ubuntu/Debian:

```bash
sudo cp certs/ca.crt /usr/local/share/ca-certificates/pyloros.crt
sudo update-ca-certificates
```

### 3. Create a configuration file

```toml
[proxy]
bind_address = "127.0.0.1:8080"
ca_cert = "./certs/ca.crt"
ca_key = "./certs/ca.key"

[logging]
level = "info"
log_requests = { allowed = true, blocked = true }

# Allow GitHub API access
[[rules]]
method = "*"
url = "https://api.github.com/*"

# Allow GitHub raw content
[[rules]]
method = "GET"
url = "https://raw.githubusercontent.com/*"
```

See [`examples/basic_config.toml`](examples/basic_config.toml) for a more complete example.

### 4. Start the proxy

```bash
pyloros run --config config.toml
```

### 5. Configure the client

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

### 6. Test it

```bash
# Should succeed (matches a rule)
curl https://api.github.com/zen

# Should fail with 451 (no matching rule)
curl https://example.com/
```

## Client Configuration

After starting the proxy and trusting the CA system-wide (step 2), configure individual tools as follows. System-wide CA trust works for most native tools, but some (notably Node.js-based tools) bundle their own CA store and need explicit configuration.

### curl

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
```

System CA trust works for the certificate. To override explicitly:

```bash
export CURL_CA_BUNDLE=/path/to/certs/ca.crt
```

**Gotchas:**
- For plain HTTP URLs, use **lowercase** `http_proxy` — curl ignores uppercase `HTTP_PROXY` for `http://` URLs as a CGI security measure.
- curl skips the proxy for localhost by default. Set `no_proxy=""` if you need to test with localhost URLs.

### git

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
```

System CA trust works for the certificate. To override explicitly:

```bash
export GIT_SSL_CAINFO=/path/to/certs/ca.crt
# or
git config --global http.sslCAInfo /path/to/certs/ca.crt
```

### Node.js / Claude Code

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export NODE_EXTRA_CA_CERTS=/path/to/certs/ca.crt
```

Node.js does **not** use the system CA store, so `NODE_EXTRA_CA_CERTS` is required. This applies to all Node.js-based tools including Claude Code.

### Haskell (http-client-tls / wreq / amazonka)

http-client-tls respects `HTTPS_PROXY` / `HTTP_PROXY` environment variables (case-insensitive).

For the CA certificate, the Haskell TLS stack (`x509-system` / `crypton-x509-system`) does **not** read `SSL_CERT_FILE`. Instead, it uses `SYSTEM_CERTIFICATE_PATH`:

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export SYSTEM_CERTIFICATE_PATH=/path/to/certs/ca.crt
```

**Gotchas:**
- `SSL_CERT_FILE` is **ignored** by the Haskell TLS stack — use `SYSTEM_CERTIFICATE_PATH` instead.
- `SYSTEM_CERTIFICATE_PATH` replaces (not supplements) the default cert paths. This is fine when all traffic goes through the proxy (which handles upstream TLS), but if the process also makes direct HTTPS connections you'll need a combined bundle.
- The cert store is loaded once at process startup and cached globally. The env var must be set before the process starts.

## Configuration

Configuration uses TOML format. Pass it via `--config` or set values with CLI flags.

### `[proxy]`

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `bind_address` | No | `127.0.0.1:8080` | Address and port to listen on |
| `ca_cert` | Yes | — | Path to CA certificate PEM file |
| `ca_key` | Yes | — | Path to CA private key PEM file |

### `[logging]`

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `level` | No | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace` |
| `log_requests` | No | `true` | Log individual requests. Accepts a bool or a table: `{ allowed = true, blocked = false }` |

### `[[rules]]`

Each rule defines an allowed request pattern. A request must match **at least one rule** to be permitted; everything else is blocked.

| Field | Required | Description |
|-------|----------|-------------|
| `method` | Yes | HTTP method (`GET`, `POST`, etc.) or `*` for any method |
| `url` | Yes | URL pattern. `*` wildcard matches any sequence of characters (including across path segments) |
| `websocket` | No | Set to `true` to allow WebSocket upgrades to this URL |

URL patterns use `https://` for HTTPS and `wss://` for WebSocket (treated as `https://` for matching).

**Examples:**

```toml
# Exact URL
[[rules]]
method = "GET"
url = "https://api.example.com/health"

# Wildcard host and path
[[rules]]
method = "*"
url = "https://*.github.com/*"

# Wildcard in path segment
[[rules]]
method = "GET"
url = "https://api.example.com/users/*/profile"

# Query parameter matching
[[rules]]
method = "GET"
url = "https://api.example.com/search?q=*"

# WebSocket
[[rules]]
method = "GET"
url = "wss://realtime.example.com/events"
websocket = true
```

### `[[credentials]]`

Credential injection lets the proxy inject API keys and tokens into outgoing requests so the AI agent never sees real secrets — preventing credential exfiltration. Credentials are only injected for HTTPS requests (never plain HTTP).

All string values support `${ENV_VAR}` placeholders, resolved from environment variables at startup.

#### Header credentials (type = "header")

Injects or overwrites a single HTTP header on matching requests. The `type` field defaults to `"header"` if omitted.

| Field | Required | Description |
|-------|----------|-------------|
| `type` | No | `"header"` (default if omitted) |
| `url` | Yes | URL pattern (same syntax as rules) |
| `header` | Yes | Header name to inject |
| `value` | Yes | Header value (supports `${ENV_VAR}`) |

If multiple credentials match the same request and set the same header, last match wins (config file order). Multiple credentials matching different headers on the same request all get injected.

```toml
# Inject an API key for Anthropic
[[credentials]]
url = "https://api.anthropic.com/*"
header = "x-api-key"
value = "${ANTHROPIC_API_KEY}"

# Inject a bearer token for a private API
[[credentials]]
url = "https://internal.example.com/*"
header = "Authorization"
value = "Bearer ${INTERNAL_TOKEN}"
```

#### AWS SigV4 credentials (type = "aws-sigv4")

Re-signs requests with real AWS credentials using AWS Signature Version 4. The agent can use fake/dummy AWS credentials while the proxy transparently re-signs with real ones.

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Must be `"aws-sigv4"` |
| `url` | Yes | URL pattern (same syntax as rules) |
| `access_key_id` | Yes | AWS access key ID (supports `${ENV_VAR}`) |
| `secret_access_key` | Yes | AWS secret access key (supports `${ENV_VAR}`) |
| `session_token` | No | AWS session token for temporary credentials (supports `${ENV_VAR}`) |

The proxy extracts the region and service from the agent's existing `Authorization` header, strips old AWS auth headers, and re-signs with the real credentials. If the original request has no parseable AWS `Authorization` header, the credential is skipped.

```toml
[[credentials]]
type = "aws-sigv4"
url = "https://*.amazonaws.com/*"
access_key_id = "${AWS_ACCESS_KEY_ID}"
secret_access_key = "${AWS_SECRET_ACCESS_KEY}"
# session_token = "${AWS_SESSION_TOKEN}"
```

## CLI Reference

### `run` — Start the proxy server

```
pyloros run [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-c, --config <PATH>` | Path to configuration file |
| `--ca-cert <PATH>` | Path to CA certificate (overrides config) |
| `--ca-key <PATH>` | Path to CA private key (overrides config) |
| `-b, --bind <ADDR>` | Bind address (overrides config) |
| `-l, --log-level <LEVEL>` | Log level: error, warn, info, debug, trace (default: info) |

### `generate-ca` — Generate a CA certificate and key

```
pyloros generate-ca [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-o, --out <DIR>` | Output directory (default: current directory) |
| `--cert-name <NAME>` | Certificate filename (default: `ca.crt`) |
| `--key-name <NAME>` | Key filename (default: `ca.key`) |

### `validate-config` — Validate a configuration file

```
pyloros validate-config --config <PATH>
```

| Flag | Description |
|------|-------------|
| `-c, --config <PATH>` | Path to configuration file (required) |

## Running Tests

```bash
cargo test                    # Run all tests
cargo test --lib              # Unit tests only
cargo test --test proxy_basic_test  # Specific test file
cargo clippy                  # Lint
cargo fmt --check             # Check formatting
```

### Manual testing with real servers

`scripts/pyloros-test-proxy.sh` starts a temporary proxy and runs a command with all proxy env vars configured:

```bash
# Test with curl
scripts/pyloros-test-proxy.sh --rule 'GET https://httpbin.org/*' -- curl -sS https://httpbin.org/get

# Test with wget
scripts/pyloros-test-proxy.sh --rule 'GET https://www.google.com/*' -- wget -O /dev/null https://www.google.com/

# Interactive shell
scripts/pyloros-test-proxy.sh --rule '* https://*.example.com/*' -- bash
```

See `scripts/pyloros-test-proxy.sh --help` for all options.

### Test coverage

Test coverage (requires one-time setup: `rustup component add llvm-tools-preview && cargo install cargo-llvm-cov`):

```bash
cargo llvm-cov                # Text summary
cargo llvm-cov --html         # HTML report in coverage/
```

## License

[MIT](./LICENSE)
