# PVM Decompiler (pvm-decompiler)

A tool to decompile PVM (Polkadot Virtual Machine) bytecode into readable high-level pseudo-code.

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
- Duplicate dispatch switch suppression (identical state machine dispatchers shown only once)
- Compound boolean condition inlining (`while (x <s 5 & x <=s 2)` instead of `while (cond != 0)`)
- Unreachable code suppression after `return` (dispatch infrastructure removed)

## Example Outputs

All examples are compiled from WASM to PVM bytecode. The decompiler recovers high-level structure from raw register-based instructions.

### Fibonacci (simple, compiled with polkatool)

Input: `examples/compiled/fibonacci.pvm` — a basic Fibonacci loop compiled from Rust via polkatool.

```
fn main(r1: u64, r7: u64, r8: u64) {
    let ptr_0_56 = u32[r7]
    let ptr_0_80 = 0
    let ptr_0_88 = 1
    let ptr_0_96 = 0

    while (ptr_0_80 >=u ptr_0_56) {
        ptr_0_80 = ptr_0_80 + 1
        ptr_0_88 = ptr_0_96 + ptr_0_88
        ptr_0_96 = ptr_0_88
    }

    mem[0] = ptr_0_96
    let ptr_0_64 = 17179869184

    let var_9 = pvm_addr(ptr_0_64) + (ptr_0_64 >>u 32)
    halt()
}

fn func_0() {
    return
}
```

### Fibonacci (AssemblyScript)

Input: `examples/compiled/as-fibonacci.pvm` — Fibonacci compiled from AssemblyScript via wasm-pvm. Shows cross-function calls, heap management (WASM memory grow via `sbrk`), and the actual Fibonacci loop.

```
fn main(r1: u64, r7: u64, r8: u64, r9: u64, r10: u64, r11: u64, r12: u64) {
    func_1()
}

fn func_1(r1: u64) {
    let var_1 = u64[r1 + 8]
    let ptr_0_40 = wasm_ptr(u64[r1])
    let ptr_0_56 = HEAP_PTR
    let var_9 = HEAP_PTR + 4
    let ptr_0_88 = var_9
    let ptr_0_112 = var_9 + 268
    let var_15 = HEAP_PAGES
    let ptr_0_120 = var_15
    let ptr_0_192 = (var_15 << 16) + 15 & -16

    if (((var_15 << 16) + 15 & -16) <u var_9 + 268) {
        ...  // heap grow logic
    }

    HEAP_PTR = ptr_0_112
    let ptr_0_520 = 0
    let ptr_0_528 = 1
    let ptr_0_536 = mem[ptr_0_40]

    while (ptr_0_536 >s 0) {
        let var_136 = ptr_0_528 + ptr_0_520
        ptr_0_520 = var_136 - ptr_0_520
        ptr_0_528 = var_136
        ptr_0_536 = ptr_0_536 - 1
    }

    RESULT_PTR = ptr_0_88
    RESULT_LEN = 4
    halt()
}
```

### Control Flow (AssemblyScript)

Input: `examples/compiled/as-tests-control-flow.pvm` — Tests `if/else`, counting loops, and nested `while` with compound boolean conditions.

```
fn func_1(r1: u64) {
    ...
    let var_100 = mem[ptr_0_40]
    let ptr_0_464 = var_100
    let ptr_0_512 = 2

    if (var_100 <=s 10) {
        let ptr_0_568 = 0
        let ptr_0_576 = ptr_0_512
    } else {
        ptr_0_512 = 1
    }

    while (ptr_0_568 <s ptr_0_464) {
        ptr_0_568 = ptr_0_568 + 1
        ptr_0_576 = ptr_0_576 + 1
    }

    let ptr_0_680 = 0
    let ptr_0_688 = ptr_0_576

    while (ptr_0_680 <s 5) {
        let ptr_0_760 = 0
        let ptr_0_768 = ptr_0_688

        while (ptr_0_760 <s 5 & ptr_0_760 <=s 2) {
            ptr_0_760 = ptr_0_760 + 1
            ptr_0_768 = ptr_0_768 + 1
        }

        ptr_0_680 = ptr_0_680 + 1
        ptr_0_688 = ptr_0_768
    }

    mem[RESULT_PTR] = ptr_0_688
    ...
}
```

Full outputs for all examples are in [`examples/output/`](examples/output/).

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
