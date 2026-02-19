# PVM Reverse Assembler & Decompiler Roadmap

## Project Goal
Create a tool to reverse engineer PVM (Polkadot Virtual Machine) bytecode into readable high-level source code (TypeScript/Python/Rust approximation).

## feasibility Analysis
**Status: Highly Feasible**
- **Instruction Set**: Well-defined RISC-V 64-bit derivative (RV64EM-like). Defined in `wasm-pvm` crate (`opcode.rs`, `instruction.rs`).
- **Binary Format**: Custom `ProgramBlob` format. Crucially, it appears to include a **mask section** that marks instruction boundaries, eliminating the primary difficulty of variable-length instruction disassembly (distinguishing code from data/padding).
- **Resources**: Full access to the reference implementation (`wasm-pvm`) and specification (`Graypaper`).

## Technical Architecture

### Phase 1: Disassembler (The "Lifter")
**Goal**: Convert binary PVM bytecode -> Structured Internal Representation (IR).
- **Input**: Raw PVM Blob (or hex dump).
- **Step 1.1**: Parse Blob Header (Jump Table, Code Section, Mask Section).
- **Step 1.2**: Linear Disassembly. Use the `mask` to identify valid instruction start offsets. Decode each instruction using the spec from `instruction.rs`.
- **Step 1.3**: Resolve Jump Targets. Map immediate offsets and Jump Table indices to absolute PC addresses.
- **Output**: Assembly listing (e.g., `0x0010: add32 r1, r2, r3`).

### Phase 2: Control Flow Graph (CFG) Recovery
**Goal**: Reconstruct the logical flow of the program.
- **Step 2.1**: Basic Block Leader Detection. Identify start of blocks (jump targets, instruction after a jump/branch).
- **Step 2.2**: Edge Creation. Connect blocks based on branch/jump logic.
- **Step 2.3**: Data Flow Analysis (Def-Use Chains). Track register usage to identify variables.

### Phase 3: Structural Analysis (Decompilation)
**Goal**: Recover high-level control structures.
- **Step 3.1**: Pattern Matching. Detect loops (back-edges), if-then-else (diamond patterns), and switch cases (jump tables).
- **Step 3.2**: Stack/Register Lifting. Convert register allocation back to temporary variables.

### Phase 4: LLM Refinement (The "Polisher")
**Goal**: Make the output human-readable.
- **Step 4.1**: Prompt Engineering. Feed function-level CFG/Pseudo-code to LLM.
- **Step 4.2**: Deduplication. Identify inlined functions (repeated blocks of identical logic) and refactor them into helper functions.
- **Step 4.3**: Commentary. Generate docstrings and inline comments explaining the logic.

## Proposed Stack
- **Implementation Language**: **Rust**.
  - **Reason**: The reference implementation `wasm-pvm` is in Rust. We can potentially reuse `opcode` definitions or at least easily port the logic. Best performance for binary analysis.
- **LLM Integration**: OpenAI API / Anthropic API (via standard HTTP client).

## Immediate Next Steps
1.  Set up Rust project structure.
2.  Implement `Blob` parser and `Instruction` decoder.
3.  Verify against `wasm-pvm` test vectors (if available) or create simple test blobs.
