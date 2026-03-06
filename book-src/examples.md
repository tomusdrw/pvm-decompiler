# Examples

This section walks through several real PVM programs. For each example we show:

1. The **original source code** (WAT or AssemblyScript)
2. Basic **metadata** about the compiled binary
3. The **decompiled pseudo-code** output
4. Where available, the **LLM-refined** output with better variable names

The examples go from simple to more complex:

- [Branch Table](./example-br-table.md) -- a small WAT program with `switch/case` style branching
- [Fibonacci (WAT)](./example-fibonacci.md) -- classic fibonacci in WebAssembly text format
- [Fibonacci (AssemblyScript)](./example-as-fibonacci.md) -- same algorithm compiled from AssemblyScript, shows how a higher-level language compiles differently
- [Control Flow](./example-control-flow.md) -- a larger example with `if/else`, `while`, nested `for` loops, and `break`
- [JAM Fuzzy Service](./example-jam-fuzzy-service.md) -- a real-world Rust JAM service (~142 KB, 63 functions, no source available)
- [Ananas](./example-ananas.md) -- a real-world AssemblyScript JAM service (~442 KB, 189 functions, [source on GitHub](https://github.com/tomusdrw/anan-as))

The next examples show more complex patterns:

- [Functions (AssemblyScript)](./example-functions.md) -- multiple helper functions (add, factorial, square-in-loop), all inlined by the compiler
- [Linked List (AssemblyScript)](./example-linked-list.md) -- heap-allocated linked list with recursive traversal
- [Game of Life (AssemblyScript)](./example-life.md) -- Conway's Game of Life on a 16x16 grid, aggressive inlining
- [Host Call Log (WAT)](./example-host-call.md) -- minimal host call example using `ecalli` for logging
- [Fibonacci (as-lan)](./example-aslan-fib.md) -- fibonacci from a full AssemblyScript framework (~38 KB, 18 functions)

Each example can be reproduced by running the decompiler on files from the `examples/compiled/` directory.
