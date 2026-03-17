# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build                  # Build the project
cargo test                   # Run all tests (unit + integration)
cargo test --lib             # Run unit tests only
cargo test --test proxy_basic_test  # Run a specific integration test file
cargo test pattern_matching  # Run tests matching a name pattern
cargo clippy                 # Lint
cargo fmt                    # Format code
scripts/test-report.sh       # Run tests + generate test-report.md / test-report.html

# Coverage (one-time setup: rustup component add llvm-tools-preview && cargo install cargo-llvm-cov)
cargo llvm-cov                                  # Text summary
cargo llvm-cov --html                           # HTML report in coverage/
cargo llvm-cov --lcov --output-path lcov.info   # LCOV format

# Fuzzing (one-time setup: cargo +nightly install cargo-fuzz)
cargo +nightly fuzz list                        # List fuzz targets
cargo +nightly fuzz run fuzz_pktline -- -max_total_time=60  # Time-limited run
cargo +nightly fuzz run fuzz_config fuzz/seeds/fuzz_config  # Run with seed corpus
```

## CLI Commands

```bash
cargo run -- run --config config.toml                    # Start proxy (--config is optional)
cargo run -- generate-ca --out ./certs/                  # Generate CA cert/key
cargo run -- validate-config --config config.toml        # Validate config
```

## Manual Testing

Use `scripts/pyloros-test-proxy.sh` to quickly test the proxy against real servers. It generates a temporary CA, starts the proxy, runs a command with all proxy env vars set, and cleans up on exit.

```bash
# Test curl through proxy
scripts/pyloros-test-proxy.sh --rule 'GET https://httpbin.org/*' -- curl -sS https://httpbin.org/get

# Test wget through proxy
scripts/pyloros-test-proxy.sh --rule 'GET https://www.google.com/*' -- wget -O /dev/null https://www.google.com/

# Multiple rules
scripts/pyloros-test-proxy.sh --rule 'GET https://api.github.com/*' --rule '* https://httpbin.org/*' \
  -- curl -sS https://api.github.com/zen

# Interactive shell with proxy configured
scripts/pyloros-test-proxy.sh --rule '* https://*.example.com/*' -- bash
```

Use this for ad-hoc verification when automated tests pass but you want to confirm behavior against real servers (different TLS stacks, h2 negotiation, etc.).

## Development process

`devdocs/SPEC.md` is a declarative specification of what we want this product to be: features, technical choices (libraries, protocols, testing strategy), and configuration format. Code should ultimately be maintained to match the requirements here. When we want to change something in the product, we first modify the SPEC.

After context compaction (when conversation history is summarized), reread `devdocs/SPEC.md` and any other relevant spec documents to stay on track with requirements and guidelines.

When facing design decisions, do the simpler thing and record the decision with rationale directly in `devdocs/INTERNALS.md`. Also document any tool/build-system problems encountered there.

`devdocs/INTERNALS.md` records implementation-level rationale and architecture details that supplement the high-level spec. Consult it when working on areas it covers (test infrastructure, TLS choices, etc.).

When you learn something non-obvious (a library gotcha, a debugging trick, a pattern that worked), write it to a new file in `devdocs/lessons/` — one lesson per file, named descriptively (e.g., `rcgen-ca-cert-chain.md`). Before starting work on a topic, scan existing lessons with `ls devdocs/lessons/` for relevant prior knowledge.

IMPORTANT: Commit immediately and automatically whenever a piece of work is done and verified. NEVER wait for the user to say "commit" — if it's done, commit it. This applies to every change: code, config, docs, anything. Don't accumulate changes. When following a multi-phase plan, commit after each phase passes its verification tests.

IMPORTANT: Every requirement in SPEC.md must be verified by tests. Prefer e2e tests by default; use unit tests only when e2e testing is not feasible for a particular requirement. Don't just wing it — if a feature isn't tested, it's not done.

IMPORTANT: If asked to implement something that's not in SPEC.md, insist on adding it to the spec first before writing any code.

You can keep refining the spec document as we work and discover new things, but confirm with human for major changes.

If you receive advice during development, you can add it to this section - will come handy during subsequent iterations.

When adding many tests, add them in groups with commit checkpoints — don't write 15 tests then commit once.

When debugging, isolate first: write a minimal reproducing test before iterating on the full system. Don't guess-and-check against the entire codebase — extract the failing component into a focused unit test that runs in seconds, then fix it there.

## Worktree Workflow

IMPORTANT: NEVER make changes directly in the main working directory (`/home/zyla.linux/pyloros`). ALL development work MUST happen in a worktree — this includes SPEC.md edits, doc changes, and early design iteration, not just code. When a new feature is proposed, create the worktree first, then write the spec update there. Do not edit files, run builds, or make commits in the main directory. If you catch yourself about to modify a file in the main directory, STOP and create a worktree first. This applies even for "small" or "trivial" changes. Multiple conversations may be running concurrently in separate worktrees, so uncommitted changes in the main directory risk being silently discarded during cleanup.

When making a plan, ALWAYS mention worktree setup in it, so that user can verify that you follow this.

**Setup (do this BEFORE any code changes):**

```bash
git branch claude/<feature-slug> main
mkdir -p ../pyloros-worktrees
git worktree add ../pyloros-worktrees/<feature-slug> claude/<feature-slug>
cd ../pyloros-worktrees/<feature-slug> && lefthook install
```

IMPORTANT: Always run `lefthook install` in new worktrees. Without this, the pre-commit hook (cargo fmt, clippy, rustc warnings) won't run and CI will fail on formatting.

**Branch naming**: `claude/<feature-slug>` (lowercase, hyphen-separated).

**Location**: worktrees live in `../pyloros-worktrees/<slug>/` (a sibling directory, not a subdirectory) so Grep/Glob don't find duplicate files.

**During development**: use absolute paths for all commands since shell state resets between Bash calls. Follow the same dev process (tests, commits).

**Finishing**: default to `gh pr create`. For trivial changes where a PR would be overkill, merge locally with `--no-ff` for clearer history. Ask the user if unclear.

**Cleanup** (after merge/PR):

```bash
git worktree remove ../pyloros-worktrees/<feature-slug>
git branch -d claude/<feature-slug>
```

## Architecture

See `devdocs/SPEC.md` for product spec (features, configuration format, technical decisions).

### Module layout (`src/`)

- **`proxy/`** - HTTP proxy server: `server.rs` (TCP listener, connection dispatch), `handler.rs` (CONNECT vs plain HTTP routing, filter integration), `tunnel.rs` (CONNECT tunnel with MITM TLS handshake, upstream forwarding)
- **`filter/`** - Request filtering: `rules.rs` (FilterEngine compiles config rules, evaluates RequestInfo, git rule expansion), `matcher.rs` (PatternMatcher for wildcard `*` matching on hosts/paths/queries, UrlPattern for full URL decomposition), `pktline.rs` (git pkt-line parser for branch restriction enforcement), `lfs.rs` (Git-LFS batch request JSON body inspection)
- **`tls/`** - Certificate management: `ca.rs` (CA generation/loading, per-host cert signing), `mitm.rs` (MitmCertificateGenerator wraps CA with caching, builds rustls ServerConfig), `cache.rs` (LRU cache with TTL for generated certs)
- **`audit.rs`** - Structured JSONL audit logging: `AuditLogger` (file writer), `AuditEntry` (serializable entry struct), enums for event/decision/reason types
- **`config.rs`** - TOML config parsing into `Config`/`ProxyConfig`/`LoggingConfig`/`Rule` structs
- **`error.rs`** - `thiserror`-based error types (`Error`)
- **`main.rs`** - clap CLI with `run`, `generate-ca`, `validate-config` subcommands

### Key patterns

- Async throughout using Tokio; one spawned task per connection
- `FilterEngine` and `MitmCertificateGenerator` are wrapped in `Arc` for cross-task sharing

## Parallel Development

Multiple features can be developed simultaneously in separate worktrees. To avoid
merge conflicts:

- **Tests**: Each feature gets its own `tests/<feature>_test.rs` file. Never append
  tests for a new feature into an existing test file.
- **Shared infra**: Add new helpers to `tests/common/mod.rs` only when needed by
  multiple test files. Feature-specific helpers stay in the test file.
- **SPEC.md**: Shared doc that will conflict. Keep edits minimal and well-scoped.
  Rebase before merging.

## Tests

Integration tests live in `tests/`, split by feature area to minimize merge conflicts
across parallel worktrees:
- `proxy_basic_test.rs` — core proxy flow (allowed/blocked, wildcards, multi-rule)
- `proxy_forwarding_test.rs` — header forwarding, error handling, large bodies
- `http2_test.rs` — HTTP/2 protocol negotiation and translation
- `logging_test.rs` — granular request logging configuration
- `websocket_test.rs` — WebSocket upgrade and echo
- `filter_test.rs` — FilterEngine unit tests
- `tls_test.rs` — certificate generation and caching
- `cli_test.rs` — CLI subcommand validation
- `git_smart_http_test.rs` — git clone/push through proxy (basic e2e)
- `git_rules_test.rs` — git rule filtering: operation type, repo URL, branch restrictions
- `git_lfs_test.rs` — Git-LFS batch endpoint filtering: operation checks, merged-scan, plain HTTP blocking
- `audit_log_test.rs` — Structured JSONL audit log: allowed/blocked/auth entries, credential info, HTTP vs HTTPS

Shared test infrastructure (TestCa, TestProxy, TestUpstream, handlers) lives in
`tests/common/mod.rs`.

**Adding tests for new features**: Create a new test file (`tests/<feature>_test.rs`)
rather than appending to an existing one. This prevents merge conflicts when
multiple features are developed in parallel across worktrees.

Unit tests are inline in their respective modules (`config.rs`, `matcher.rs`, `rules.rs`, `ca.rs`, `mitm.rs`, `cache.rs`, `tunnel.rs`). Tests use `tempfile` for temporary directories.

### Test Reporting

All tests use `TestReport` for structured reporting. Integration tests use `test_report!()` from `tests/common/mod.rs`; unit tests use `test_report!()` from `src/test_support.rs` (via `use crate::test_report;`). The report tool (`tools/test-report/`) runs `cargo test` with `TEST_REPORT_DIR` set, collects per-test report files, and generates `test-report.md` + `test-report.html`.

Run `scripts/test-report.sh` to generate reports locally. CI uploads them as artifacts.
