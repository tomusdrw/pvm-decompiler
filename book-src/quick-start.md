# Quick Start

## Build

```bash
cargo build --release
```

The binary is at `./target/release/pvm-decompiler`.

## Basic Usage

Decompile a PVM binary to pseudo-code:

```bash
./target/release/pvm-decompiler examples/compiled/fibonacci.pvm
```

Output:

```text
fn main(r1: u64, r7: u64, r8: u64) {
    let ptr_0_80
    let ptr_0_88
    let ptr_0_96

    let ptr_0_56 = u32[r7]
    ptr_0_80 = 0
    ptr_0_88 = 1
    ptr_0_96 = 0

    while (ptr_0_80 <u ptr_0_56) {
        ptr_0_80 = ptr_0_80 + 1
        ptr_0_88 = ptr_0_96 + ptr_0_88
        ptr_0_96 = ptr_0_88
    }

    u32[0x20000] = ptr_0_96
    halt()
}
```

## Verbose Mode

Use `--verbose` to see the analysis details (CFG, dataflow, structural analysis) together with the pseudo-code:

```bash
./target/release/pvm-decompiler --verbose examples/compiled/fibonacci.pvm
```

This prints information about detected functions, def-use chains, lifted variables, detected loops, and the final pseudo-code.

## Debug Mode

Use `--debug` to see the raw decoded PVM instructions:

```bash
./target/release/pvm-decompiler --debug examples/compiled/fibonacci.pvm
```

This shows things like container format, jump tables, and each individual instruction with its program counter.

## LLM Refinement

If you set the `OPENROUTER_API_KEY` environment variable, you can ask an LLM to improve the variable names in the output:

```bash
export OPENROUTER_API_KEY="your-key-here"
./target/release/pvm-decompiler --refine examples/compiled/fibonacci.pvm
```

The LLM renames variables like `ptr_0_80` to more meaningful names like `loop_counter` based on how they are used.

## LLVM C Output

For a full decompilation to C code through the LLVM pipeline:

```bash
./target/release/pvm-decompiler --decompile --backend=builtin examples/compiled/fibonacci.pvm
```

See [Backend Comparison](./small-backend-compare.md) for details about available backends.
