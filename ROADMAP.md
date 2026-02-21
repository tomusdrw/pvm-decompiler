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

### Phase 4: Output Quality — COMPLETE
Completed:
- For-loop pattern detection (#20) — detects init/cond/step and emits `for` syntax
- Named ecalli host functions (#17) — maps indices to JAM Graypaper names (gas_remaining, read, write, etc.)
- Deterministic variable naming (#25) — smallest-PC-wins policy for reaching definitions
- trap → return rendering (#14 partial) — function exits show `return` instead of `trap`
- Function parameter detection (#13) — live-in register analysis, typed fn signatures with indented body
- break/continue detection (#26) — loop exit paths emit `break`, header jumps emit `continue`
- SSA variable coalescing (#24) — loop induction variables use consistent names across init/step
- Signedness tracking (#16) — U32/I32/U64/I64 type inference from instruction width and signed ops
- Struct field access recovery (#19) — pointer loads/stores show as `ptr->field_N`

- Call graph construction (#21) — cross-function jumps detected and rendered as `func_name()` calls

- Emission method refactoring (#27) — Emitter struct groups mutable state, cleaner method signatures
- Reverse index for variable lookups (#23) — O(1) var_name → def_pc via HashMap
- Emitter method extraction (#28) — emit_loop, emit_switch, emit_switch_targets as separate methods
- Indirect call resolution (#30) — JumpInd with constant targets render as `func_name()`
- End-to-end integration tests (#29) — full pipeline tests on 6 real PVM binary fixtures
- Operator associativity fix — correct parenthesization for non-commutative right operands

### Phase 4b: Further Output Improvements — COMPLETE
- Counting-down for-loop detection (#31) — `detect_for_loop_pattern` scans all init/latch instructions, handles AddImm with negative values and Sub32 steps
- Array access pattern recovery (#32) — `format_array_access` detects `base + index * elem_size` and renders as `base[index]`
- Double negation elimination — `!!x → x` and `0 <u !(x) → x >=u y` simplification chain
- Redundant condition suppression (#34) — branch + condition variable definitions eliminated from while/for body when inlined into header
- Comparison inversion (#33) — `!(x <u y)` → `x >=u y`, `!(x <s y)` → `x >=s y` for cleaner conditions
- Deterministic function ordering — fix HashSet iteration non-determinism in `find_component_entry`

### Phase 4c: Polish — COMPLETE
- Suppress unreachable code after break/continue (#35) — pre-computed reachability in loop body, stops traversal at terminal blocks (break/continue/if where all branches terminate)
- Simplify `0 <u (a | b)` bitwise boolean patterns (#36) — renders as `(a | b) != 0` for non-boolean expressions, with correct parenthesization
- Suppress empty else blocks — `} else {}` omitted when else block produces no visible output

### Phase 4d: Advanced Output — COMPLETE
- Render `0 <s x` as `x >s 0` and similar comparisons (#38) — flip `const <u/s expr` to `expr >u/s const`, with `0 <u` kept for `!= 0` rendering
- Improve block emission order in loop bodies (#37) — reverse post-order DFS instead of PC-sorted, prevents `continue` appearing mid-body in nested loops
- Suppress redundant `continue` at end of loop body — implicit fall-through makes trailing `continue` unnecessary
- Eliminate redundant condition variable definitions in if headers — `let cond = x >=s y` suppressed when inlined into `if (x >=s y)`
- Add LeU/LeS operators and complete comparison inversion — `!(x >s y)` → `x <=s y`, `!(x >=u y)` → `x <u y`
- Suppress consecutive duplicate `return` statements
- Extract `eliminate_condition_def` helper to reduce code duplication
- Emit nested loops inside loop bodies with proper indentation (#39 partial) — `loop_map` passed to Emitter, `emit_loop` accepts indent parameter
- Conditional branch goto labels (#39) — unstructured branches render as `if (cond) goto block_XXXX;` instead of raw `if (...) jump <offset>`

### Phase 4e: Structural Improvements (Future)
- Improve top-level block label rendering (#40) — detect dispatch loops and structure as `loop { switch { ... } }`

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
