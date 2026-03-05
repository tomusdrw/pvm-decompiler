# PVM Decompiler (`pvm-decompiler`)

Decompiler for PVM (Polkadot Virtual Machine) bytecode that emits structured, readable pseudo-code.

## Status

This project is under active development and output is best-effort. It is useful for reverse engineering and inspection, but generated pseudo-code is not guaranteed to be source-equivalent for every binary.

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
# Default: pseudo-code only
pvm-decompiler path/to/program.pvm

# Verbose analysis summaries (CFG/dataflow/structuring)
pvm-decompiler -v path/to/program.pvm

# Full debug diagnostics (includes raw instruction dump)
pvm-decompiler --debug path/to/program.pvm

# Emit LLVM IR for the recovered functions
pvm-decompiler --llvm path/to/program.pvm

# Full LLVM pipeline: PVM -> LLVM IR -> C (auto-select backend)
pvm-decompiler --decompile path/to/program.pvm

# Force a specific backend
pvm-decompiler --decompile --backend=rellic path/to/program.pvm

# Optional LLM refinement (requires OPENROUTER_API_KEY)
pvm-decompiler --decompile --refine path/to/program.pvm
```

### CLI options

- `-v`, `--verbose`: show analysis summaries
- `--debug`: show raw instruction diagnostics
- `--llvm`: emit LLVM IR instead of pseudo-code
- `--decompile`: run full LLVM-to-C pipeline
- `--backend=X`: choose backend (`retdec`, `rellic`, `rellic-docker`, `llvm-cbe`, `builtin`)
- `--refine`: run LLM refinement on pseudo-code/C output (`OPENROUTER_API_KEY` required)
- `-V`, `--version`: print tool version
- `-h`, `--help`: print usage

## Decompilation Backends (`--decompile`)

When `--decompile` is enabled, the tool lifts PVM to LLVM IR and then emits C via one backend:

- `retdec`: RetDec CLI (`retdec-decompiler`)
- `rellic`: native Rellic CLI (`rellic-decomp`)
- `rellic-docker`: Rellic in Docker image `pvm-rellic-decomp`
- `llvm-cbe`: LLVM C backend emitter
- `builtin`: built-in best-effort fallback emitter (always available)

### Backend selection and fallback

- Default behavior: auto-detect and pick the first available backend in this order:
  `retdec` -> `rellic` -> `rellic-docker` -> `llvm-cbe` -> `builtin`
- If `--backend=X` is unavailable, the tool warns and falls back to the first available backend.
- Special case: if `--backend=rellic` is requested but native Rellic is missing, it automatically uses `rellic-docker` when available.
- During `--decompile`, stderr prints both `Available backends` and `Used backend`.

### Backend prerequisites

- `retdec`: requires `retdec-decompiler` and an `llvm-as` binary.
- `rellic`: requires native `rellic-decomp` and an `llvm-as` binary.
- `rellic-docker`: requires Docker; if image `pvm-rellic-decomp` is missing, the tool can build it from `docker/rellic/`.
- `llvm-cbe`: requires `llvm-cbe` on `PATH`.
- `builtin`: no external dependencies.

### Backend tradeoffs

- `retdec` / `rellic`: generally stronger C decompilation quality, but require local toolchain setup.
- `rellic-docker`: easier environment isolation than native setup, but has Docker/runtime overhead.
- `llvm-cbe`: fast path to C-like output, but less decompiler-oriented structuring.
- `builtin`: zero setup and always available, but intentionally naive and lower fidelity.

## Input Support

The decompiler accepts:

- SPI-wrapped PVM binaries
- raw ProgramBlob binaries
- binaries with a metadata prefix (auto-stripped before decode)

## Output

Generated pseudo-code includes function signatures, variable recovery, lifted expressions, and recovered control flow. For sample outputs, see `examples/output/`.

To regenerate all examples:

```bash
./run_examples.sh
```

## Architecture

Pipeline stages:

1. `src/decoder.rs`: binary parsing and instruction decoding
2. `src/cfg.rs`: control-flow graph construction
3. `src/functions.rs`: function and call-pattern detection
4. `src/dataflow.rs`: liveness and def-use analysis
5. `src/lifting.rs`: expression lifting and simplification
6. `src/structuring/*`: structural recovery and pseudo-code emission

## Limitations

- Decompiled output is pseudo-code, not recompilable source.
- Some complex or irreducible control flow may still emit goto-style labels.
- Unknown opcodes are reported and preserved conservatively.

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

## Documentation Index

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
