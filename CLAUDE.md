# PVM Disassembler

## Design Principles

- **High-level intent over low-level detail**: The output should focus on understanding decompiled code intent, not on debugging memory layout or runtime internals. Prefer collapsing boilerplate (heap headers, pointer arithmetic) even at the cost of hiding implementation details.
