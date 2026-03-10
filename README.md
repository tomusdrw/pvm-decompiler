# PVM Decompiler (`pvm-decompiler`)

Decompiler for PVM (Polkadot Virtual Machine) bytecode that emits structured, readable pseudo-code.

## Disclaimer

This project is heavily vibe-coded. Here be dragons.

## Status

This project is under active development and output is best-effort. It is useful for reverse engineering and inspection, but generated pseudo-code is not guaranteed to be source-equivalent for every binary.

## Documentation

Canonical documentation lives in the mdBook:

- https://todr.me/pvm-decompiler/

Use the book for quick start, worked examples, and backend comparisons. This README is intentionally brief to avoid duplicating that content.

Build docs locally:

```bash
mdbook build
mdbook serve -p 3000
```

## Features

- Decodes SPI and raw ProgramBlob PVM binaries
- Builds CFGs and detects function boundaries
- Runs dataflow/liveness and expression lifting
- Recovers high-level structures (`if/else`, loops, `switch` where possible)
- Infers typed variable names (`u32`, `i64`, `ptr`, `bool`)
- Resolves many direct and indirect call patterns
- Emits progress to stderr for long-running decompiles

## Install

### From source

```bash
cargo build --release
./target/release/pvm-decompiler --help
```

### Local developer install

```bash
cargo install --path .
```

## Usage

```bash
# Default pseudo-code output
pvm-decompiler path/to/program.pvm

# Full LLVM pipeline: PVM -> LLVM IR -> C
pvm-decompiler --decompile path/to/program.pvm

# Optional LLM refinement (requires OPENROUTER_API_KEY)
pvm-decompiler --decompile --refine path/to/program.pvm
```

Run `pvm-decompiler --help` for full CLI options.

## Input Support

The decompiler accepts:

- SPI-wrapped PVM binaries
- raw ProgramBlob binaries
- binaries with a metadata prefix (auto-stripped before decode)

## Development

Prerequisite: stable Rust (edition 2024; MSRV in `Cargo.toml`).

```bash
# Format + lint + tests
cargo fmt -- --check
cargo clippy -- -D warnings
cargo test

# Refresh fixtures and quality checks
./run_examples.sh
./scripts/check_output_quality.sh
```

Optional local hook setup:

```bash
git config core.hooksPath .githooks
```

## Repository Docs

- `ROADMAP.md`: project roadmap and milestones
- `docs/output-baseline.md`: output quality baseline metrics
- `docs/release-checklist.md`: pre-release verification checklist
- `CONTRIBUTING.md`: contributor workflow and expectations
- `CHANGELOG.md`: release and change history

## Community

- Code of Conduct: `CODE_OF_CONDUCT.md`
- Contribution guide: `CONTRIBUTING.md`

## License

Licensed under the MIT license. See `LICENSE`.
