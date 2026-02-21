# PVM Reverse Assembler & Decompiler Roadmap

## Project Goal
Create a tool to reverse engineer PVM (Polkadot Virtual Machine) bytecode into readable high-level source code (TypeScript/Python/Rust approximation).

## Feasibility Analysis
**Status: Highly Feasible**
- **Instruction Set**: Well-defined RISC-V 64-bit derivative (RV64EM-like). Defined in `wasm-pvm` crate (`opcode.rs`, `instruction.rs`).
- **Binary Format**: Custom `ProgramBlob` format. Includes a **mask section** that marks instruction boundaries, eliminating the primary difficulty of variable-length instruction disassembly.
- **Resources**: Full access to the reference implementation (`wasm-pvm`) and specification (`Graypaper`).

## Current State

### Phase 1: Disassembler — COMPLETE
- SPI and raw ProgramBlob format parsing
- Linear disassembly using mask section for instruction boundaries
- Jump table parsing (1-4 byte entry sizes)
- ~30 decoded opcode variants, unknown opcodes handled gracefully

### Phase 2: CFG & Data Flow — COMPLETE
- Basic block leader detection and edge creation
- Predecessor/successor tracking
- Function boundary detection (connected components + stack prologue heuristics)
- Per-function isolated sub-CFG construction
- Iterative liveness analysis (live_in/live_out)
- Def-use chain building

### Phase 3: Structural Analysis & Lifting — COMPLETE
- Dominator tree computation (Cooper-Harvey-Kennedy algorithm)
- Loop detection (natural loops via back-edges)
- If-then-else detection (diamond/triangle patterns)
- Switch/case detection (jump table dispatch)
- Variable assignment with type inference (integer/pointer/boolean)
- Expression building from instructions
- Constant propagation, copy propagation
- Intra-block and cross-block expression folding
- Store-load forwarding and dead store elimination
- Stack variable recovery
- Expression simplification (identity operations, constant folding)
- Inline `let` declarations at first assignment
- Condition lifting (variable names in while/if conditions)
- Comparison inlining (`x <u y` instead of `cond != 0`)
- `trap` → `return` rendering

### Phase 4: Output Quality — IN PROGRESS
Completed:
- For-loop pattern detection (#20) — detects init/cond/step and emits `for` syntax
- Named ecalli host functions (#17) — maps indices to JAM Graypaper names (gas_remaining, read, write, etc.)
- Deterministic variable naming (#25) — smallest-PC-wins policy for reaching definitions
- trap → return rendering (#14 partial) — function exits show `return` instead of `trap`
- Function parameter detection (#13) — live-in register analysis, typed fn signatures with indented body
- break/continue detection (#26) — loop exit paths emit `break`, header jumps emit `continue`

See open GitHub issues for planned improvements:
- SSA variable coalescing for loop variables (#24)
- Struct field access recovery (#19)
- Signedness tracking and type narrowing (#16)
- Call graph and inter-procedural analysis (#21)

### Phase 5: LLM Refinement (Future)
- Prompt engineering for function-level polishing
- Inlined function deduplication
- Docstring and comment generation

## Technical Architecture

See `README.md` for the 6-stage pipeline overview.

### Key Design Decisions
- **InstructionShape enum**: Central abstraction that classifies ~60 raw instruction variants into ~12 structural shapes, used by all analysis passes
- **Per-function analysis**: Functions are detected and analyzed independently, enabling parallel processing and cleaner scoping
- **Expression trees**: Lifted code uses `Expression` enum trees that support recursive simplification, folding, and formatting
- **Declared variable tracking**: `format_pc` emits `let` on first use via `declared_vars` set, producing clean inline declarations

## Proposed Stack
- **Implementation Language**: **Rust** (matches `wasm-pvm` reference implementation)
- **LLM Integration**: OpenAI API / Anthropic API (via standard HTTP client) — future work
