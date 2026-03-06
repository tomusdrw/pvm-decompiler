# Fibonacci (WAT)

A fibonacci implementation in WebAssembly text format. It reads `n` from memory, computes `fib(n)`, and writes the result back.

## Source

File: `examples/sources/fibonacci.wat`

```wat
(module
  (memory 1)

  (func (export "main") (param $args_ptr i32) (param $args_len i32) (result i32 i32)
    (local $n i32)
    (local $i i32)

    ;; Read n from args
    (local.set $n (i32.load (local.get $args_ptr)))

    ;; Initialize: a=0, b=1, i=0
    (local.set $args_ptr (i32.const 0))  ;; reuse as $a
    (local.set $args_len (i32.const 1))  ;; reuse as $b
    (local.set $i (i32.const 0))

    (block $break
      (loop $continue
        (br_if $break (i32.ge_u (local.get $i) (local.get $n)))

        ;; a, b = b, a+b
        (local.get $args_len)
        (i32.add (local.get $args_ptr) (local.get $args_len))
        (local.set $args_len)
        (local.set $args_ptr)

        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $continue)
      )
    )

    (i32.store (i32.const 0) (local.get $args_ptr))
    (i32.const 0)
    (i32.const 4)
  )
)
```

The source reuses `$args_ptr` and `$args_len` as the fibonacci accumulators `a` and `b` after reading the input. This is a common trick in hand-written WAT to avoid extra locals.

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/fibonacci.pvm` |
| Size | 335 bytes (approx.) |
| Format | SPI |
| Functions | 1 |
| Instructions | ~70 |
| Jump table entries | 1 |

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/fibonacci.pvm
```

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

**What to notice:**

- The `loop`/`block` pair from WAT is recovered as a `while` loop.
- `ptr_0_56` holds the input `n`, read from memory at `r7`.
- `ptr_0_80` is the loop counter `i`.
- `ptr_0_88` and `ptr_0_96` correspond to the fibonacci accumulators `b` and `a`.
- The swap logic `a, b = b, a+b` is visible: first `ptr_0_88 = ptr_0_96 + ptr_0_88` (new b = a + b), then `ptr_0_96 = ptr_0_88` (new a = old b). The decompiler simplified the original stack-based swap into sequential assignments.

## Verbose Mode

Running with `--verbose` shows the analysis pipeline:

```bash
./target/release/pvm-decompiler --verbose examples/compiled/fibonacci.pvm
```

Key details from the verbose output:

- **1 function** detected (`main` at PC 0x0000 with 9 basic blocks)
- **46 variable definitions** tracked, **93 uses**
- **1 loop** detected (header at 0x006e)
- **1 switch** detected (the indirect jump dispatcher)

This gives a sense for how the analysis engine works internally.
