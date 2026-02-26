# Technology Stack

**Analysis Date:** 2026-02-26

## Languages

**Primary:**
- Rust 1.87+ (Edition 2024) - Primary implementation language for the decompiler

## Runtime

**Environment:**
- Rust stable toolchain
- LLVM 18 (required for bytecode compilation operations)

**Package Manager:**
- Cargo - Rust package manager and build tool
- Lockfile: `Cargo.lock` (present)

## Frameworks

**Core:**
- `wasm-pvm` 0.2.0 - PVM bytecode instruction definitions and execution models
  - Provides PVM instruction enum and bytecode parsing utilities
  - Includes WASM encoder/parser for binary format handling
- `inkwell` 0.8.0 - LLVM bindings for IR code generation and compilation
  - Wraps LLVM-sys for type-safe IR generation
  - Used by wasm-pvm for compilation operations

**Build/Dev:**
- `rustfmt` - Code formatting (integrated in cargo fmt)
- `clippy` - Linting with strict warning enforcement (-D warnings)
- `cargo-test` - Built-in test runner

## Key Dependencies

**Critical:**
- `wasm-pvm` 0.2.0 - Core PVM instruction support and WASM format handling
  - Used throughout: `src/decoder.rs`, `src/instruction.rs`, `src/functions.rs`, `src/cfg.rs`
- `inkwell` 0.8.0 - LLVM IR generation via wasm-pvm
  - Indirectly required for bytecode processing

**Infrastructure:**
- `thiserror` 2.0.18 - Structured error handling and derive macros
- `tracing` 0.1.44 - Distributed tracing framework (used by wasm-pvm, available for diagnostics)
- `atty` 0.2.14 - Terminal color and TTY detection for output formatting
  - Used in `src/main.rs` for colored output control
- `anyhow` 1.0.102 - Flexible error context handling
- `serde` 1.0.228 - Serialization framework (used by dependencies)

**Transitive (via wasm-pvm):**
- `wasmparser` 0.219.2 - WASM binary format parsing
- `wasm-encoder` 0.219.2 - WASM binary format generation
- `wat` 1.245.1 - WebAssembly Text format support
- `llvm-sys` 181.3.0 - Low-level LLVM C bindings (required for inkwell)

## Configuration

**Environment:**
- `LLVM_SYS_181_PREFIX` - Environment variable for LLVM 18 library location
  - CI sets to `/usr/lib/llvm-18` on Ubuntu
  - Must be set correctly for local builds using inkwell

**Build:**
- `Cargo.toml` - Main manifest with package metadata and dependencies
- `Cargo.lock` - Locked dependency versions for reproducible builds
- `.rustfmt.toml` - (Not detected) Uses default Rust formatting

## Platform Requirements

**Development:**
- Rust 1.87 or later (MSRV specified in `Cargo.toml` line 6)
- LLVM 18 development libraries and headers
  - On Ubuntu: `llvm-18-dev libpolly-18-dev`
  - Must have C++ compiler for LLVM compilation
- `cargo` toolchain with `rustfmt` and `clippy` components

**Production:**
- Standalone binary deployment
- Requires LLVM 18 runtime libraries (linked statically or dynamically)
- No database, network, or external service dependencies
- Runs on any platform supported by Rust (Linux, macOS, Windows)

---

*Stack analysis: 2026-02-26*
