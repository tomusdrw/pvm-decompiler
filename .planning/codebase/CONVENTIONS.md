# Coding Conventions

**Analysis Date:** 2026-02-26

## Naming Patterns

**Files:**
- Snake case: `instruction.rs`, `varint.rs`, `cfg.rs` (control flow graph)
- Module directories: `structuring/`, `ir/` (intermediate representation)
- Submodules within: `mod.rs` for public API, specialized files for implementation (e.g., `structuring/analysis.rs`, `structuring/emission.rs`)

**Functions:**
- Snake case universally: `detect_functions()`, `build_call_graph()`, `decode_var_u32()`, `identify_leaders()`, `extract_condition()`
- Helper functions (not `pub`): Same snake case convention: `find_connected_components()`, `bfs_component()`, `split_at_prologues()`
- Test functions: Use `test_` prefix: `test_decode_known_values()`, `test_fibonacci_full_pipeline()`, `test_fibonacci_regression_elides_redundant_entry_goto_and_dead_stub_function()`

**Variables:**
- Snake case for locals and bindings: `mut components`, `entry_pc`, `block_pcs`, `program_buffer`
- Loop counters and temporaries: `i`, `idx`, `prev_non_empty`, `high`, `low`
- Register references use numeric suffixes: `ptr_0_80`, `ptr_0_56` (variable names derived from register assignments)

**Types (Structs, Enums):**
- PascalCase universally: `ControlFlowGraph`, `BasicBlock`, `DecodedProgram`, `InstructionShape`, `BinOp`, `UnaryOp`, `DataFlowAnalysis`, `StructuralAnalysis`, `LiftedProgram`, `Function`, `VarType`
- Enum variants: PascalCase: `Add`, `Sub`, `Mul`, `LtU`, `LtS`, `Load`, `Store`, `Branch`, `JumpInd`, `Phi`
- Option/Result variants: Standard Rust: `Some()`, `None()`, `Ok()`, `Err()`

## Code Style

**Formatting:**
- No custom rustfmt configuration found—uses Rust defaults
- Indentation: 4 spaces (Rust standard)
- Line width: Not restricted (no config present)
- Trailing commas in multiline: Observed across codebase

**Linting:**
- No custom clippy configuration
- Uses `#[allow(dead_code)]` where necessary (e.g., `DecodeError` variants, test-only fields like `phi_value_by_block_reg`)
- Uses `#[allow(dead_code)]` on functions like `decode_var_u32()` in `src/varint.rs` line 6 when used conditionally

## Import Organization

**Order:**
1. Standard library imports: `use std::{...}`
2. External crate imports: `use wasm_pvm::...`
3. Internal crate imports: `use crate::...`
4. Module-level imports from parent: `use super::...`
5. Local module declarations: `mod ...`

**Examples from codebase:**

In `src/main.rs`:
```rust
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Read;
use wasm_pvm::pvm::Instruction;

mod cfg;
mod dataflow;
mod decoder;
// ...

use cfg::ControlFlowGraph;
use dataflow::DataFlowAnalysis;
```

In `src/instruction.rs`:
```rust
use std::fmt;
use wasm_pvm::pvm::Instruction;
```

In `src/structuring/emission.rs`:
```rust
use super::{CondOp, Condition, Operand, StructuralAnalysis, Structure, extract_condition};
use crate::cfg::ControlFlowGraph;
use crate::instruction::InstructionShape;
use crate::lifting::LiftedProgram;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;
use wasm_pvm::pvm::Instruction;
```

**Path Aliases:**
- No path aliases configured in Cargo.toml
- Uses fully-qualified crate paths: `crate::cfg::ControlFlowGraph`, `crate::instruction::InstructionShape`

## Error Handling

**Patterns:**
- Primary strategy: `Result<T, Box<dyn std::error::Error>>` for propagating errors up the stack
  - `src/main.rs:46`: `fn main() -> Result<(), Box<dyn std::error::Error>>`
  - `src/main.rs:432`: `fn decompile_bytes(buffer: &[u8]) -> Result<String, Box<dyn std::error::Error>>`
  - `src/decoder.rs:44`: `pub fn try_strip_metadata(data: &[u8]) -> Result<&[u8], Box<dyn Error>>`

- Custom error enum for structured errors: `src/decoder.rs` defines `DecodeError` enum with Debug + Display implementation
  ```rust
  #[derive(Debug)]
  #[allow(dead_code)]
  pub enum DecodeError {
      UnexpectedEof,
      InvalidOpcode(u8),
      InvalidVarInt,
      InvalidMask,
      UnsupportedJumpTableEntrySize(u8),
      TrailingData,
  }

  impl fmt::Display for DecodeError {
      fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
          write!(f, "{:?}", self)
      }
  }

  impl Error for DecodeError {}
  ```

- Option-based returns: `decode_var_u32()` returns `Option<(u32, usize)>` for simple presence/absence checks

- `.expect()` used for test fixtures (acceptable in test code):
  ```rust
  let buffer = std::fs::read("examples/compiled/fibonacci.pvm")
      .expect("fibonacci.pvm fixture should exist");
  ```

- `.unwrap()` used minimally in test assertions: `src/main.rs:1286` uses `unwrap()` in test context

- `panic!()` reserved for invariant violations in test assertions:
  ```rust
  panic!("Expected Loop");     // src/structuring/analysis.rs:836
  panic!("Expected IfThenElse"); // src/structuring/analysis.rs:1148
  ```

## Logging

**Framework:** No external logging crate used
- Uses `eprintln!()` for diagnostics: `fn print_usage()` and error messages in main
- Uses `println!()` for output to stdout
- No structured logging or log levels

**Patterns:**
- Verbosity level enum: `src/main.rs:27`
  ```rust
  #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
  enum Verbosity {
      /// Default: only pseudo-code output
      Normal,
      /// -v/--verbose: include CFG, dataflow, and structural summaries
      Verbose,
      /// --debug: include raw instructions and all diagnostics
      Debug,
  }
  ```
- Conditional output based on verbosity level throughout main decompilation flow

## Comments

**When to Comment:**
- Module-level documentation: `//!` for every module explaining its purpose
  - `src/instruction.rs:1-10`: Module documentation explaining instruction classification as single source of truth
  - `src/decoder.rs:1-8`: Module documentation describing two decoding paths
  - `src/dataflow.rs:1-8`: Module documentation listing four uses of def-use analysis

- Public items: `///` documentation for public structs, enums, and functions
  - `src/instruction.rs:15`: `/// Binary operator for expression nodes.`
  - `src/decoder.rs:44-48`: Documentation for `try_strip_metadata()` with format explanation

- Inline comments: Used sparingly for non-obvious algorithmic steps
  - `src/instruction.rs`: Comments explain varint encoding rules ("0xxxxxxx -> 1 byte", "10xxxxxx -> 2 bytes")
  - `src/cfg.rs:70-80`: Algorithm comments before major steps: "Step 1: Identify leaders", "Step 2: Create blocks"
  - Algorithm descriptions in function headers: `src/cfg.rs:41-45` explains CFG build algorithm in comment block

**JSDoc/TSDoc:**
- Rust-style doc comments used throughout
- No code examples in doc comments observed
- Focus on "what" and "why", not "how"

## Function Design

**Size:**
- Most functions range from 20-60 lines
- Larger functions (200+ lines) are integration functions that orchestrate analysis passes (e.g., `StructuralAnalysis::detect()` in `src/structuring/analysis.rs`)
- Utility functions kept small: `byte_size()` is 1 line, `is_terminator()` is ~10 lines

**Parameters:**
- Limited to 2-4 parameters for most functions
- Use struct references for complex parameter bundles: `cfg: &ControlFlowGraph` passed throughout rather than unpacking fields
- Mutable borrows for builders: `&mut cfg`, `&mut analysis`
- Use of `&'a` lifetime when returning borrowed data: `src/structuring/emission.rs:1291` returns `Vec<&'a Structure>`

**Return Values:**
- Result types preferred for fallible operations: `Result<T, Box<dyn Error>>`
- Option types for optional values: `Option<usize>`, `Option<Condition>`
- Collections returned by value: `Vec<Function>`, `HashSet<usize>`, `HashMap<usize, BasicBlock>`
- Tuple returns for multi-value results: `decode_var_u32()` returns `(u32, usize)`

## Module Design

**Exports:**
- Public API clearly delineated with `pub` keyword
- Private structs/functions unmarked (implicit privacy)
- Example from `src/structuring/mod.rs:1-24`:
  ```rust
  mod analysis;  // Private submodule
  mod emission;  // Private submodule

  pub use analysis::DominatorTree;  // Re-export key type

  pub struct FunctionSignature { ... }  // Public struct
  pub enum Structure { ... }           // Public enum
  pub struct StructuralAnalysis { ... } // Public struct
  ```

**Barrel Files:**
- Used sparingly in `structuring/mod.rs`
- Re-exports `DominatorTree` from private `analysis` submodule
- No comprehensive barrel files for all exports (imports remain explicit)

**Test Organization:**
- Tests in same file as implementation: `#[cfg(test)] mod tests { ... }`
- Found in: `src/varint.rs:68`, `src/instruction.rs:1440`, `src/decoder.rs:855`, `src/cfg.rs:275`, `src/functions.rs:781`, `src/dataflow.rs:413`, `src/lifting.rs:2484`, `src/ir/ssa.rs:359`, `src/structuring/mod.rs:173`, `src/structuring/analysis.rs:648`, `src/structuring/emission.rs:3029`, `src/main.rs:833`

---

*Convention analysis: 2026-02-26*
