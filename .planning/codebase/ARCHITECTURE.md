# Architecture

**Analysis Date:** 2026-02-26

## Pattern Overview

**Overall:** Multi-stage decompiler pipeline

The PVM decompiler follows a classic reverse-engineering pipeline architecture:
1. **Decoding stage** - Parse binary to instruction stream
2. **Control flow stage** - Build CFG and detect function boundaries
3. **Analysis stage** - Run dataflow, liveness, and SSA analyses
4. **Lifting stage** - Recover high-level variables and expressions
5. **Structuring stage** - Detect loops, branches, switches
6. **Emission stage** - Output readable pseudo-code

**Key Characteristics:**
- Linear pipeline with minimal backtracking
- Each stage produces immutable data structures passed to the next
- Analysis results are threaded through rendering context (see `FormatContext` in `src/lifting.rs`)
- Deterministic output via sorted collections throughout
- Targets human readability over compilation/verification

## Layers

**Decoding Layer:**
- Purpose: Parse PVM bytecode from multiple input formats and produce a normalized instruction stream
- Location: `src/decoder.rs`, `src/varint.rs`
- Contains: Binary format parsing, metadata stripping, instruction array construction
- Depends on: `wasm_pvm` crate (external PVM instruction definitions)
- Used by: CFG construction layer
- Key structures: `DecodedProgram` (instruction stream + jump table + code length + memory_base)

**CFG & Function Detection Layer:**
- Purpose: Build control flow graph, identify function boundaries, and understand program structure
- Location: `src/cfg.rs`, `src/functions.rs`
- Contains: Basic block construction, edge connectivity, function detection via connected components and prologue heuristics
- Depends on: Decoding layer, `src/instruction.rs` (instruction classification)
- Used by: All analysis layers downstream
- Key structures: `ControlFlowGraph` (blocks + entry PC), `Function` (entry PC + block set + name)

**Instruction Classification Layer:**
- Purpose: Provide unified classification of 60+ raw PVM instructions into ~12 "shapes" (binary op, unary op, load, store, branch, etc.)
- Location: `src/instruction.rs`
- Contains: `InstructionShape` enum mapping instructions to operand structure, binary/unary ops, branch offsets, def-use info
- Depends on: `wasm_pvm` crate
- Used by: All downstream consumers (CFG, dataflow, lifting, structuring)
- Key abstraction: Single source of truth for instruction semantics

**Analysis Layer:**
- Purpose: Compute reachability, liveness, and value flow information for downstream optimization and lifting
- Location: `src/dataflow.rs`, `src/ir/ssa.rs`, `src/structuring/analysis.rs`
- Contains:
  - **Dataflow** (`src/dataflow.rs`): def-use chains, live-in/live-out sets per block
  - **SSA** (`src/ir/ssa.rs`): Lightweight SSA representation for dominance-safe optimizations
  - **Dominators** (`src/structuring/analysis.rs`): Dominator tree (iterative algorithm), RPO computation
- Depends on: CFG layer, instruction classification
- Used by: Lifting and structuring layers
- Key structures: `DataFlowAnalysis`, `SsaProgram`, `DominatorTree`

**Lifting Layer:**
- Purpose: Recover high-level variables, infer types, fold expressions, and simplify computations
- Location: `src/lifting.rs`
- Contains: Variable naming heuristics, expression tree construction, constant propagation, single-use inlining, type inference
- Depends on: Analysis layer (dataflow, SSA, dominators), instruction classification
- Used by: Structuring/emission layer
- Key structures: `Expression` (const/var/binop/unaryop/load/store/call), `Variable` (name + type), `VarType` (u64/i64/u32/i32/pointer/boolean), `LiftedProgram`
- Key insight: `FormatContext` threads memory_base through expression rendering to handle PVM's linear memory addressing

**Structuring & Emission Layer:**
- Purpose: Recover high-level control structures (loops, if-then-else, switches) and emit pseudo-code
- Location: `src/structuring/mod.rs`, `src/structuring/analysis.rs`, `src/structuring/emission.rs`
- Contains:
  - **Structure detection** (`analysis.rs`): Find natural loops, diamond patterns (if-then-else), switch tables
  - **Emission** (`emission.rs`): Format structures as pseudo-code with proper nesting and condition rendering
- Depends on: Lifting layer, CFG, dominators
- Used by: Main CLI output
- Key structures: `Structure` (Loop/IfThenElse/Switch), `Condition` (branch conditions with operands), `FunctionSignature`

**Entry Point & CLI Layer:**
- Purpose: Orchestrate the entire pipeline, handle I/O and verbosity levels
- Location: `src/main.rs`
- Triggers: User runs `pvm-decompiler <file.pvm> [OPTIONS]`
- Responsibilities:
  1. Parse CLI arguments (file, -v/--verbose, --debug flags)
  2. Read binary file
  3. Invoke decoder → CFG → function detection
  4. For each function: run analyses → lifting → structuring
  5. Emit output at appropriate verbosity level
  6. Handle errors and provide diagnostic messages

## Data Flow

**Main Pipeline:**

1. **File I/O & Decoding**
   - Input: PVM bytecode file (SPI-wrapped or raw ProgramBlob)
   - `decoder::try_strip_metadata()` removes optional metadata prefix
   - `decoder::decode_spi()` or `decoder::decode_blob()` parses instructions
   - Output: `DecodedProgram` with instruction stream and jump table

2. **CFG Construction & Function Detection**
   - Input: `DecodedProgram`
   - `ControlFlowGraph::build()` identifies leaders (block starts) from jumps/branches
   - Creates basic blocks between leaders
   - Connects blocks via edges (successors/predecessors)
   - `detect_functions()` groups blocks into functions via:
     - Connected component analysis (undirected edge traversal)
     - Prologue detection at block entries (`sp = sp - N`)
   - Output: `ControlFlowGraph` + `Vec<Function>`

3. **Per-Function Analysis Pipeline**
   - For each function, construct dedicated CFG and run:
     - **Dominance Analysis**: `DominatorTree::compute()` (iterative algorithm, RPO-ordered)
     - **Dataflow Analysis**: `DataFlowAnalysis::analyze()` computes liveness, def-use chains
     - **SSA Construction**: `SsaProgram::build()` creates lightweight SSA for optimization proofs
   - Output: Analysis results threaded to next stages

4. **Lifting**
   - Input: CFG, dataflow, SSA, dominators
   - `LiftedProgram::build()` assigns variables based on def sites
   - Constructs expression trees for each register definition
   - Inlines single-use expressions where safe (dominated)
   - Infers variable types from usage context
   - Output: `LiftedProgram` (per-block lifted code)

5. **Structuring & Emission**
   - Input: Lifted program, CFG, dominators
   - `detect_structures()` finds loops (back-edges), if-then-else (diamond patterns), switches (indirect jumps)
   - `emit_function()` formats recovered structures as pseudo-code
   - Condition extraction: `extract_condition()` decodes branch instructions to comparison expressions
   - Output: Formatted pseudo-code string

**State Management:**
- No global mutable state (exception: removed `thread_local MEMORY_BASE` in favor of explicit `FormatContext`)
- Analysis results are immutable values passed between pipeline stages
- Memory base address threaded through lifting context where needed for address simplification

## Key Abstractions

**InstructionShape:**
- Purpose: Provide unified view of 60+ raw instructions through ~12 shape variants
- Examples: `src/instruction.rs` defines BinOp, UnaryOp, Load, Store, Branch, Call, etc.
- Pattern: Static method `InstructionShape::classify()` decodes instruction to shape
- Used everywhere: CFG construction, dataflow, lifting, structuring need to understand operand structure

**Expression Tree (Lifting):**
- Purpose: Represent computations as nested expressions for human-readable output
- Examples: `Expression::BinOp { op: Add, lhs: Var("r1"), rhs: Const(4) }`
- Pattern: Recursive enum with boxing for nested expressions
- Key insight: Single-use expressions are inlined to produce readable expressions like `(r0 + 1) * 2` instead of `t1 = r0 + 1; r2 = t1 * 2`

**Control Structures:**
- Purpose: Recover high-level control flow patterns
- Types:
  - `Loop`: Header block dominates latch, latch back-edges to header
  - `IfThenElse`: Diamond (true/false paths rejoin) or triangle (true path only) patterns
  - `Switch`: Indirect jump dispatch with computed target
- Pattern: Detected via dominator relationships and edge analysis

**DataFlow Chains:**
- Purpose: Track where register values come from and go
- Examples: `DefUseChain { definition: (PC, reg), uses: [(PC, reg), ...] }`
- Pattern: HashMap of definitions keyed by (PC, reg) pairs
- Used for: Variable naming, expression tree construction, dead code detection

## Entry Points

**main():**
- Location: `src/main.rs`
- Triggers: User invokes `pvm-decompiler path/to/program.pvm [OPTIONS]`
- Responsibilities:
  1. Parse command-line arguments (filename, verbosity, version/help)
  2. Read file content into memory
  3. Invoke `decoder` to parse PVM bytecode
  4. Build `ControlFlowGraph` from decoded program
  5. Detect `Function` boundaries
  6. For each function:
     - Build per-function CFG
     - Run `DataFlowAnalysis`, `DominatorTree`, `SsaProgram`
     - Run `LiftedProgram` construction
     - Run `StructuralAnalysis` and emit pseudo-code
  7. Output formatted code at requested verbosity level
  8. Exit with appropriate code

## Error Handling

**Strategy:** Result types propagated up to main, user-facing errors printed to stderr

**Patterns:**
- `DecodeError` enum (`src/decoder.rs`): UnexpectedEof, InvalidOpcode, InvalidVarInt, etc.
- File I/O errors wrapped in `Box<dyn Error>`
- Unknown instructions logged but continue processing conservatively
- Parsing failures in varint decode return `Option` (fail-safe default behavior)

**Example:** Unknown opcode → error reported to stderr → instruction preserved conservatively in output

## Cross-Cutting Concerns

**Logging:**
- Strategy: Selective stderr output during long-running operations
- Used for: Progress indication on large programs
- Approach: `eprintln!()` macro for diagnostic messages during analysis

**Validation:**
- Strategy: Defensive programming with bounds checks during CFG construction
- Examples: Jump target validation, leader identification checks, block edge consistency
- Pattern: Early exit on inconsistency (e.g., empty CFG returns empty function list)

**Memory Management:**
- Strategy: Stack-allocated analysis results (no heap cycles)
- Pattern: Immutable data flows through pipeline
- Benefit: No borrow checker battles, clear ownership semantics

**Determinism:**
- Strategy: Sorted collections everywhere (Vec::sort_by_key, BTreeSet, etc.)
- Pattern: RPO ordering, sorted block/function lists
- Benefit: Reproducible output for testing and validation

---

*Architecture analysis: 2026-02-26*
