# Fibonacci (as-lan)

A Fibonacci implementation compiled through the [as-lan](https://github.com/aspect-build/aspect-lang) AssemblyScript framework. Unlike the hand-written WAT fibonacci, this version comes from a full framework with logging, string formatting, and runtime support -- producing a much larger binary.

## Source

The source is a full as-lan project. The core fibonacci logic (abbreviated):

```ts
function fibonacci(n: i32): i32 {
  if (n <= 1) return n;
  let a = 0, b = 1;
  for (let i = 2; i <= n; i++) {
    const tmp = a + b;
    a = b;
    b = tmp;
  }
  return b;
}
```

See `examples/sources/aslan-fib.jam.wat` for the full compiled WAT (the original TypeScript source is in the as-lan project).

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/aslan-fib.pvm` |
| Size | 39296 bytes (~38 KB) |
| Format | SPI |
| Functions | 18 |

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/aslan-fib.pvm
```

The output is 654 lines across 18 functions. The `main` function:

```text
fn main(r1: u64, r7: u64, r8: u64, r9: u64, r10: u64, r11: u64, r12: u64) {
    let var_0: u64

    // @0000
    // @000a
    var_0 = 2; jump 18414

    if (0xFEFD0000 >=u r1 - 16 - 256) {
        if (var_2481 == 0) {
            if (var_2487 == 0) {
                // ... nested initialization checks ...
                        u32[0x30000] = 5356
                        r9 = 4
                        r10 = 5
                        r0 = 190; jump -11326
            }
        }
    }
    // ...
}
```

**What to notice:**

- **Framework overhead**: 18 functions and 39 KB of binary for a fibonacci -- the as-lan framework includes runtime support for string handling, logging, memory management, and the ecalli dispatch table.
- **Nested guard checks**: The `main` function's deeply nested `if (var_XXXX == 0)` checks are the framework's initialization sequence, checking whether various runtime components need setup.
- **Scale comparison**: Compare with the [hand-written WAT fibonacci](./example-fibonacci.md) (335 bytes, 1 function, 7 lines of output) to see how framework overhead affects binary size and decompilation complexity.
- **Indirect calls**: The `call_indirect` and `jump` patterns show the framework's dispatch mechanism routing to different initialization and computation paths.
