# External Integrations

**Analysis Date:** 2026-02-26

## APIs & External Services

**Not detected:** No external API integrations.

This is a standalone CLI tool. It processes local binary files and produces output to stdout/stderr without calling external services.

## Data Storage

**Databases:**
- Not applicable - No persistent data storage

**File Storage:**
- Local filesystem only
  - Reads PVM bytecode files from filesystem
  - Outputs decompiled pseudo-code to stdout
  - Optional example test outputs written to `examples/output/` during development

**Caching:**
- None - Each invocation processes independently

## Authentication & Identity

**Auth Provider:**
- Not applicable - No user authentication or authorization

## Monitoring & Observability

**Error Tracking:**
- None - No external error reporting service

**Logs:**
- stderr output via standard Rust `eprintln!()` and `eprint!()`
- Progress messages for long-running decompiles (sent to stderr per `src/main.rs`)
- Structured tracing via `tracing` crate is available (used by wasm-pvm) but not actively configured for application diagnostics

## CI/CD & Deployment

**Hosting:**
- GitHub repository: https://github.com/tomusdrw/pvm-decompiler
- Distributed as source code; binary artifacts not currently published

**CI Pipeline:**
- GitHub Actions (`.github/workflows/ci.yml`)
- Runs on: `ubuntu-latest`
- Jobs:
  - LLVM 18 installation
  - Rust toolchain setup (stable with clippy, rustfmt)
  - Code formatting check (`cargo fmt -- --check`)
  - Linting (`cargo clippy -- -D warnings`)
  - Unit and integration tests (`cargo test`)
  - Example output regeneration (`./run_examples.sh`)
  - Output quality threshold enforcement (`./scripts/check_output_quality.sh`)

**Dependency Updates:**
- Dependabot configured for:
  - Cargo dependencies (weekly updates, max 10 open PRs)
  - GitHub Actions (weekly updates, max 10 open PRs)

## Environment Configuration

**Required env vars:**
- `LLVM_SYS_181_PREFIX` - Path to LLVM 18 installation
  - Example: `/usr/lib/llvm-18`
  - Required only during build, not at runtime

**CLI arguments (not env vars):**
- Input file path: positional argument `<file.pvm>`
- Verbosity: `-v/--verbose`, `--debug` flags
- Version: `-V/--version` flag
- Help: `-h/--help` flag

**Secrets location:**
- No secrets required - No API keys, credentials, or sensitive configuration

## Webhooks & Callbacks

**Incoming:**
- None

**Outgoing:**
- None

---

*Integration audit: 2026-02-26*
