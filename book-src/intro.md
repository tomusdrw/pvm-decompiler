# Introduction

`pvm-decompiler` is a decompiler for PVM (Polkadot Virtual Machine) bytecode. It takes compiled `.pvm` binary files and produces readable pseudo-code output.

## What It Does

The tool performs several analysis steps on PVM binaries:

1. **Decode** the binary (SPI or raw ProgramBlob format)
2. **Build** a control flow graph (CFG) and detect function boundaries
3. **Analyze** dataflow and variable liveness
4. **Lift** register operations into higher-level expressions
5. **Recover** control structures like `if/else`, `while` loops, and `switch/case`
6. **Emit** readable pseudo-code with inferred variable types

## Output Modes

The decompiler supports several output modes:

| Mode | Flag | Description |
| --- | --- | --- |
| Pseudo-code | *(default)* | Structured pseudo-code with type annotations |
| Verbose | `--verbose` | Pseudo-code plus CFG, dataflow, and structural analysis details |
| Debug | `--debug` | Raw decoded instructions and all diagnostics |
| LLVM IR | `--llvm` | Low-level LLVM intermediate representation |
| C code | `--decompile` | Full LLVM pipeline producing C output |
| LLM refined | `--refine` | Pseudo-code with variable names improved by an LLM |

## Supported Input Formats

- **SPI-wrapped** PVM binaries (most common)
- **Raw ProgramBlob** binaries
- Binaries with a **metadata prefix** (auto-stripped before decode)

## How to Read This Documentation

- Start with [Quick Start](./quick-start.md) to build and run the tool
- Look at [Examples](./examples.md) to see real decompilation results
- Check [Backend Comparison](./small-backend-compare.md) to understand the LLVM C output backend
- See [CLI Reference](./cli-reference.md) for all available flags
