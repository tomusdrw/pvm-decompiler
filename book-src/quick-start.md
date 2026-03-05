# Quick Start

Build tool:

```bash
cargo build --release
```

Run default pseudo-code:

```bash
./target/release/pvm-decompiler examples/compiled/br-table.pvm
```

Run debug mode (good for metadata):

```bash
./target/release/pvm-decompiler --debug examples/compiled/br-table.pvm
```

Run refine mode (need `OPENROUTER_API_KEY`):

```bash
./target/release/pvm-decompiler --refine examples/compiled/br-table.pvm
```

Run LLVM decompile backend explicitly:

```bash
./target/release/pvm-decompiler --decompile --backend=builtin examples/compiled/br-table.pvm
```

