#!/usr/bin/env bash
#
# pyloros-bwrap.sh — Run a command in a bubblewrap sandbox with network isolation.
#
# All network access is cut off (--unshare-net). The pyloros proxy runs outside
# the sandbox; communication happens via a Unix domain socket bind-mounted into
# the namespace. Inside the sandbox, socat bridges a local TCP port to the Unix
# socket so that standard HTTP_PROXY/HTTPS_PROXY env vars work with unmodified
# clients.
#
# Usage:
#   pyloros-bwrap.sh --config config.toml [OPTIONS] -- COMMAND [ARGS...]
#
# Options:
#   --config FILE      Proxy config file (required)
#   --ca-cert FILE     CA certificate (extracted from config if omitted)
#   --ca-key FILE      CA private key (extracted from config if omitted)
#   --pyloros PATH     Path to pyloros binary (default: search PATH and build dirs)
#   --proxy-port PORT  TCP port for socat relay inside sandbox (default: 8080)
#   --direct-https     Enable direct HTTPS mode (generate /etc/hosts, SNI listener)
#   --direct-ip IP     IP address for direct HTTPS hosts entries (default: 127.0.0.12)
#   --direct-port PORT TCP port for direct HTTPS socat relay (default: 443)
#   --sudo-bwrap       Run bwrap under sudo (needed for --cap-add, port 443)
#   --bwrap-arg ARG    Extra argument passed to bwrap (repeatable)
#   --keep             Don't clean up temp dir on exit (for debugging)
#   -h, --help         Show this help message
#
set -euo pipefail

# ---- Defaults ----
CONFIG=""
CA_CERT=""
CA_KEY=""
PYLOROS=""
PROXY_PORT=8080
DIRECT_HTTPS=false
DIRECT_IP="127.0.0.12"
DIRECT_PORT=443
SUDO_BWRAP=false
KEEP=false
BWRAP_EXTRA_ARGS=()

# ---- Parse arguments ----
usage() {
    sed -n '2,/^$/{ s/^# \?//; p }' "$0"
    exit "${1:-0}"
}

COMMAND_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)   CONFIG="$2"; shift 2 ;;
        --ca-cert)  CA_CERT="$2"; shift 2 ;;
        --ca-key)   CA_KEY="$2"; shift 2 ;;
        --pyloros)  PYLOROS="$2"; shift 2 ;;
        --proxy-port) PROXY_PORT="$2"; shift 2 ;;
        --direct-https) DIRECT_HTTPS=true; shift ;;
        --direct-ip)  DIRECT_IP="$2"; shift 2 ;;
        --direct-port) DIRECT_PORT="$2"; shift 2 ;;
        --sudo-bwrap) SUDO_BWRAP=true; shift ;;
        --bwrap-arg)  BWRAP_EXTRA_ARGS+=("$2"); shift 2 ;;
        --keep)     KEEP=true; shift ;;
        -h|--help)  usage 0 ;;
        --)         shift; COMMAND_ARGS=("$@"); break ;;
        *)          echo "Unknown option: $1" >&2; usage 1 ;;
    esac
done

if [[ -z "$CONFIG" ]]; then
    echo "Error: --config is required" >&2
    usage 1
fi

if [[ ${#COMMAND_ARGS[@]} -eq 0 ]]; then
    echo "Error: no command specified after --" >&2
    usage 1
fi

# Resolve config to absolute path
CONFIG="$(cd "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")"

# ---- Check prerequisites ----
for tool in bwrap socat; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: '$tool' is required but not found in PATH" >&2
        exit 1
    fi
done

# ---- Find pyloros binary ----
if [[ -z "$PYLOROS" ]]; then
    if command -v pyloros >/dev/null 2>&1; then
        PYLOROS="$(command -v pyloros)"
    else
        # Search common build directories
        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
        PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
        MAIN_WORKTREE=""
        if git -C "$PROJECT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            MAIN_WORKTREE="$(git -C "$PROJECT_DIR" worktree list --porcelain | head -1 | sed 's/^worktree //')"
        fi
        for search_dir in "$PROJECT_DIR" ${MAIN_WORKTREE:+"$MAIN_WORKTREE"}; do
            for candidate in \
                "$search_dir/target/release/pyloros" \
                "$search_dir/target/debug/pyloros"; do
                if [[ -x "$candidate" ]]; then
                    PYLOROS="$candidate"
                    break 2
                fi
            done
        done
    fi
fi

if [[ -z "$PYLOROS" || ! -x "$PYLOROS" ]]; then
    echo "Error: cannot find pyloros binary. Build it or pass --pyloros PATH" >&2
    exit 1
fi

# ---- Extract CA cert/key from config if not provided ----
if [[ -z "$CA_CERT" ]]; then
    CA_CERT="$(grep -E '^\s*ca_cert\s*=' "$CONFIG" | head -1 | sed 's/.*=\s*"\(.*\)".*/\1/')"
    if [[ -z "$CA_CERT" ]]; then
        echo "Error: cannot extract ca_cert from config. Pass --ca-cert explicitly." >&2
        exit 1
    fi
fi

if [[ -z "$CA_KEY" ]]; then
    CA_KEY="$(grep -E '^\s*ca_key\s*=' "$CONFIG" | head -1 | sed 's/.*=\s*"\(.*\)".*/\1/')"
    if [[ -z "$CA_KEY" ]]; then
        echo "Error: cannot extract ca_key from config. Pass --ca-key explicitly." >&2
        exit 1
    fi
fi

# Resolve to absolute paths
CA_CERT="$(cd "$(dirname "$CA_CERT")" && pwd)/$(basename "$CA_CERT")"
CA_KEY="$(cd "$(dirname "$CA_KEY")" && pwd)/$(basename "$CA_KEY")"

if [[ ! -f "$CA_CERT" ]]; then
    echo "Error: CA certificate not found: $CA_CERT" >&2
    exit 1
fi
if [[ ! -f "$CA_KEY" ]]; then
    echo "Error: CA key not found: $CA_KEY" >&2
    exit 1
fi

# ---- Create temp directory for the Unix socket ----
TMPDIR_BASE="$(mktemp -d /tmp/pyloros-bwrap.XXXXXXXX)"
SOCK_PATH="$TMPDIR_BASE/proxy.sock"
DIRECT_SOCK_PATH="$TMPDIR_BASE/direct.sock"

# ---- Cleanup trap ----
PROXY_PID=""
cleanup() {
    local exit_code=$?
    if [[ -n "$PROXY_PID" ]]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    if [[ "$KEEP" == "false" ]]; then
        rm -rf "$TMPDIR_BASE"
    else
        echo "Temp dir kept at: $TMPDIR_BASE" >&2
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

# ---- Start the proxy ----
PROXY_ARGS=(
    run
    --config "$CONFIG"
    --ca-cert "$CA_CERT"
    --ca-key "$CA_KEY"
    --bind "$SOCK_PATH"
    --log-level info
)

if [[ "$DIRECT_HTTPS" == "true" ]]; then
    PROXY_ARGS+=(--direct-https-bind "$DIRECT_SOCK_PATH")
fi

"$PYLOROS" "${PROXY_ARGS[@]}" &
PROXY_PID=$!

# Wait for proxy socket to appear
TIMEOUT=10
ELAPSED=0
while [[ ! -S "$SOCK_PATH" ]]; do
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "Error: proxy exited before socket was ready" >&2
        wait "$PROXY_PID" || true
        exit 1
    fi
    if [[ $ELAPSED -ge $TIMEOUT ]]; then
        echo "Error: timed out waiting for proxy socket at $SOCK_PATH" >&2
        exit 1
    fi
    sleep 0.2
    ELAPSED=$((ELAPSED + 1))
done

# If direct HTTPS is enabled, also wait for the direct socket
if [[ "$DIRECT_HTTPS" == "true" ]]; then
    ELAPSED=0
    while [[ ! -S "$DIRECT_SOCK_PATH" ]]; do
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            echo "Error: proxy exited before direct socket was ready" >&2
            wait "$PROXY_PID" || true
            exit 1
        fi
        if [[ $ELAPSED -ge $TIMEOUT ]]; then
            echo "Error: timed out waiting for direct HTTPS socket at $DIRECT_SOCK_PATH" >&2
            exit 1
        fi
        sleep 0.2
        ELAPSED=$((ELAPSED + 1))
    done
fi

echo "Proxy listening on $SOCK_PATH (PID $PROXY_PID)" >&2

# ---- Generate /etc/hosts for direct HTTPS mode ----
HOSTS_FILE=""
if [[ "$DIRECT_HTTPS" == "true" ]]; then
    HOSTS_FILE="$TMPDIR_BASE/hosts"
    # Start with a basic hosts file
    echo "127.0.0.1 localhost" > "$HOSTS_FILE"
    echo "::1 localhost" >> "$HOSTS_FILE"
    # Append entries from pyloros config
    "$PYLOROS" generate-hosts --config "$CONFIG" --ip "$DIRECT_IP" >> "$HOSTS_FILE" 2>/dev/null
    echo "Generated /etc/hosts with direct HTTPS entries (IP $DIRECT_IP)" >&2
fi

# ---- Run the sandboxed command ----
# Build the inner script that socat runs before exec-ing the user command.
# socat bridges TCP on localhost to the Unix socket, then the user command runs
# with HTTP_PROXY pointing at that TCP port.
INNER_SOCK="/run/pyloros-proxy.sock"
INNER_DIRECT_SOCK="/run/pyloros-direct.sock"
INNER_CA="/run/pyloros/ca.crt"

# Build bwrap arguments
BWRAP_ARGS=(
    --ro-bind / /
    --dev /dev
    --proc /proc
    --tmpfs /tmp
    --tmpfs /run
    --unshare-net
    --bind "$SOCK_PATH" "$INNER_SOCK"
    --dir /run/pyloros
    --ro-bind "$CA_CERT" "$INNER_CA"
    --setenv HTTP_PROXY "http://127.0.0.1:${PROXY_PORT}"
    --setenv HTTPS_PROXY "http://127.0.0.1:${PROXY_PORT}"
    --setenv http_proxy "http://127.0.0.1:${PROXY_PORT}"
    --setenv https_proxy "http://127.0.0.1:${PROXY_PORT}"
    --setenv SSL_CERT_FILE "$INNER_CA"
    --setenv CURL_CA_BUNDLE "$INNER_CA"
    --setenv NODE_EXTRA_CA_CERTS "$INNER_CA"
    --setenv REQUESTS_CA_BUNDLE "$INNER_CA"
    --setenv SYSTEM_CERTIFICATE_PATH "$INNER_CA"
)

# Add direct HTTPS bwrap arguments
if [[ "$DIRECT_HTTPS" == "true" ]]; then
    BWRAP_ARGS+=(
        --bind "$DIRECT_SOCK_PATH" "$INNER_DIRECT_SOCK"
        --ro-bind "$HOSTS_FILE" /etc/hosts
    )
fi

BWRAP_ARGS+=("${BWRAP_EXTRA_ARGS[@]+"${BWRAP_EXTRA_ARGS[@]}"}")

# When --sudo-bwrap is used, the inner process runs as root. Socat binds
# privileged ports as root, then we drop to the original user for the command.
ORIG_USER="$(id -un)"

# Build the exec-command portion: either direct exec or su-wrapped
if [[ "$SUDO_BWRAP" == "true" ]]; then
    # Drop privileges back to the original user for the actual command.
    # su -- -c prevents su from interpreting command args as its own flags.
    EXEC_CMD="exec su -s /bin/sh ${ORIG_USER} -- -c 'exec \"\$@\"' _ \"\$@\""
else
    EXEC_CMD='exec "$@"'
fi

# Build the inner shell script
if [[ "$DIRECT_HTTPS" == "true" ]]; then
    INNER_SCRIPT="
        # Bridge proxy protocol (for HTTP_PROXY)
        socat TCP-LISTEN:${PROXY_PORT},fork,reuseaddr,bind=127.0.0.1 UNIX-CONNECT:${INNER_SOCK} &
        # Bridge direct HTTPS (for programs that ignore HTTP_PROXY)
        socat TCP-LISTEN:${DIRECT_PORT},fork,reuseaddr,bind=${DIRECT_IP} UNIX-CONNECT:${INNER_DIRECT_SOCK} &
        # Wait for both socat instances to start
        for i in 1 2 3 4 5 6 7 8 9 10; do
            if socat /dev/null \"TCP:127.0.0.1:${PROXY_PORT}\" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        for i in 1 2 3 4 5 6 7 8 9 10; do
            if socat /dev/null \"TCP:${DIRECT_IP}:${DIRECT_PORT}\" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        ${EXEC_CMD}
    "
else
    INNER_SCRIPT="
        socat TCP-LISTEN:${PROXY_PORT},fork,reuseaddr,bind=127.0.0.1 UNIX-CONNECT:${INNER_SOCK} &
        # Wait for socat to start listening
        for i in 1 2 3 4 5 6 7 8 9 10; do
            if socat /dev/null \"TCP:127.0.0.1:${PROXY_PORT}\" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        ${EXEC_CMD}
    "
fi

BWRAP_CMD=(bwrap)
if [[ "$SUDO_BWRAP" == "true" ]]; then
    BWRAP_CMD=(sudo -n bwrap)
fi

BWRAP_EXIT=0
"${BWRAP_CMD[@]}" \
    "${BWRAP_ARGS[@]}" \
    -- sh -c "$INNER_SCRIPT" _ "${COMMAND_ARGS[@]}" || BWRAP_EXIT=$?

exit "$BWRAP_EXIT"
