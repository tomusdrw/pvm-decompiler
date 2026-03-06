# Backend Comparison

The `--decompile` flag runs the full LLVM pipeline: PVM bytecode is lifted to LLVM IR, then decompiled to C code. Several backends are available for the final decompilation step.

## Available Backends

| Backend | Flag | Status |
| --- | --- | --- |
| `builtin` | `--backend=builtin` | Works locally, no extra dependencies |
| `retdec` | `--backend=retdec` | Requires RetDec installation |
| `rellic` | `--backend=rellic` | Requires Rellic installation |
| `rellic-docker` | `--backend=rellic-docker` | Requires Docker with Rellic image |
| `llvm-cbe` | `--backend=llvm-cbe` | Requires LLVM C Backend Emitter |

For most users, `builtin` is the easiest option since it needs no external tools.

## Example: builtin Backend

Using `simple-add.pvm`, a minimal hand-crafted PVM binary (21 bytes, 6 instructions):

```bash
./target/release/pvm-decompiler --decompile --backend=builtin examples/compiled/simple-add.pvm
```

```c
int64_t main(void) {
    int64_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
    r0 = r1 = r2 = r3 = r4 = r5 = r6 = r7 = r8 = r9 = r10 = r11 = r12 = 0;
    goto bb_0000;
bb_0000:
    r0 = 42;
    r1 = 100;
    r2 = %t5;
    goto bb_000f;
bb_000f:
    return %t6;
}
```

The C output preserves the basic block structure from the LLVM IR. Variables like `%t5` are LLVM temporaries that the backend has not yet resolved into concrete expressions. This is expected for the builtin backend -- it prioritizes correctness over readability.

## Example: br-table Through builtin

A larger example showing how the builtin backend handles branching:

```bash
./target/release/pvm-decompiler --decompile --backend=builtin examples/compiled/br-table.pvm
```

The output is a C function with labeled basic blocks (`bb_0000`, `bb_000a`, etc.), `goto` statements for control flow, and `if/else` for conditional branches. The switch table from the source becomes a chain of conditional jumps.

## When to Use Which Output

| Goal | Recommended mode |
| --- | --- |
| Quick understanding of program logic | Default pseudo-code (no flags) |
| Better variable names for review | `--refine` |
| Integration with C toolchains | `--decompile --backend=builtin` |
| Deep analysis of the binary | `--verbose` or `--debug` |
| Generating LLVM IR for custom pipelines | `--llvm` |

The default pseudo-code mode is usually the most readable. Use `--decompile` when you need actual C code, for example to compile and test the decompiled output.
