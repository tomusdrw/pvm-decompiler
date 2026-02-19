# PVM Reverse Assembler (pvm-diss)

A tool to reverse engineer PVM (Polkadot Virtual Machine) bytecode into readable high-level source code.

## Usage

```bash
cargo run -- path/to/file.pvm
```

## Development

### Prerequisites
- Rust (stable)
- `wasm-pvm` crate (expected in `../wasm-pvm`)

### Setup
The project uses a local Git hook to ensure code quality before pushing.
```bash
git config core.hooksPath .githooks
```

### Testing
Run the test suite:
```bash
cargo test
```

### Formatting & Linting
```bash
cargo fmt
cargo clippy
```

## CI/CD
GitHub Actions are configured in `.github/workflows/ci.yml`.
The workflow checks out the `wasm-pvm` dependency automatically.
