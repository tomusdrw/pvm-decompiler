# CLI Reference

## Usage

```
pvm-decompiler [OPTIONS] <file.pvm>
```

The tool takes one PVM binary file as input and writes the result to stdout. Progress and diagnostic messages go to stderr.

## Options

| Flag | Description |
| --- | --- |
| *(no flags)* | Emit structured pseudo-code (default mode) |
| `-v`, `--verbose` | Show CFG, dataflow, and structural analysis alongside pseudo-code |
| `--debug` | Show raw decoded instructions and all diagnostics |
| `--llvm` | Emit LLVM IR instead of pseudo-code |
| `--decompile` | Full LLVM pipeline: lift to IR, then decompile to C code |
| `--refine` | Pass output through an LLM to improve variable names (requires `OPENROUTER_API_KEY`) |
| `--backend=X` | Choose decompilation backend (used with `--decompile`) |
| `-V`, `--version` | Show version |
| `-h`, `--help` | Show help |

## Backends

Used with `--decompile` to select the C code generation backend:

| Value | Description |
| --- | --- |
| `builtin` | Built-in backend, no dependencies needed |
| `retdec` | Uses RetDec decompiler |
| `rellic` | Uses Rellic (Trail of Bits) |
| `rellic-docker` | Uses Rellic via Docker container |
| `llvm-cbe` | Uses LLVM C Backend Emitter |

## Environment Variables

| Variable | Description |
| --- | --- |
| `OPENROUTER_API_KEY` | API key for LLM refinement (`--refine` flag) |

## Examples

```bash
# Basic decompilation
pvm-decompiler program.pvm

# See raw instructions
pvm-decompiler --debug program.pvm

# Verbose analysis + pseudo-code
pvm-decompiler --verbose program.pvm

# LLVM IR output
pvm-decompiler --llvm program.pvm

# C code via builtin backend
pvm-decompiler --decompile --backend=builtin program.pvm

# Pseudo-code with LLM-improved names
pvm-decompiler --refine program.pvm

# C code with LLM-improved names
pvm-decompiler --decompile --refine program.pvm
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Error (invalid input, decode failure, etc.) |
