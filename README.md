# PVM Reverse Assembler (pvm-diss)

A tool to reverse engineer PVM (Polkadot Virtual Machine) bytecode into readable high-level pseudo-code.

## Usage

```bash
# Default: clean pseudo-code output only
cargo run -- path/to/file.pvm

# Verbose: include CFG, dataflow, and structural analysis summaries
cargo run -- -v path/to/file.pvm

# Debug: include raw instructions and all diagnostics
cargo run -- --debug path/to/file.pvm
```

### Output

The decompiler produces pseudo-code with:
- Function signatures with typed parameters (`fn func_0(var_0: u32, ptr_1: ptr) { ... }`)
- Named variables (`var_0`, `ptr_1`, `cond_2`) with width/signedness types (`u32`, `i64`, `bool`)
- Inline `let` declarations at first assignment (`let var_0: u32 = 42`)
- High-level control structures: `for`, `while`, `if/else`, `switch/case`
- `break`/`continue` in loop bodies, with unreachable code suppressed, redundant trailing `continue` elided, and condition variable definitions eliminated when inlined
- Comparison inlining in conditions (e.g. `x <u y` instead of `cond_0 != 0`)
- Full comparison inversion (`!(x <u y)` → `x >=u y`, `!(x >s y)` → `x <=s y`) and flipping (`0 <s x` → `x >s 0`)
- Struct field access recovery (`ptr_0->field_8` instead of `u64[ptr_0 + 8]`)
- Stack variable recovery (`local_0` instead of `u64[sp - 8]`)
- Named JAM host calls (`gas_remaining()`, `read()`, `write()` instead of `ecalli(0)`)
- `return` instead of `trap` at function exits
- SSA variable coalescing for loop induction variables
- Array access pattern recovery (`ptr[i]` instead of `u32[ptr + i * 4]`)
- Indirect call resolution (`func_name()` instead of `call_indirect(var)` when target is constant)
- Expression simplification: double negation elimination, constant folding, identity operations
- Bitwise boolean pattern simplification (`0 <u (a | b)` → `(a | b) != 0`)
- Empty else block suppression for cleaner output
- Goto labels for unstructured branches (`if (cond) goto block_XXXX;` instead of raw jump offsets)

## Architecture

The decompiler pipeline has 6 stages:

```
Binary Input (.pvm file)
       |
   [decoder.rs]        -- Binary parsing (SPI + ProgramBlob formats)
       |
   [cfg.rs]            -- Control flow graph construction
       |
   [functions.rs]      -- Function boundary detection
       |
   [dataflow.rs]       -- Def-use chains & liveness analysis
       |
   [lifting.rs]        -- Variable recovery, expression building,
       |                  constant/copy propagation, expression folding,
       |                  store-load forwarding, dead store elimination
       |
   [structuring.rs]    -- Structural analysis (loops, ifs, switches)
       |                  + pseudo-code emission
       |
   Pseudo-code output
```

Supporting modules:
- `instruction.rs` — Classifies ~60 PVM instructions into ~12 structural shapes
- `varint.rs` — Variable-length integer decoding

## Development

### Prerequisites
- Rust (stable, edition 2024)
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
