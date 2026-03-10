# Fibonacci (WAT)

A fibonacci implementation in WebAssembly text format. It reads `n` from memory, computes `fib(n)`, and writes the result back.

## Source

File: `examples/sources/fibonacci.wat`

```wat
(module
  (memory 1)

  (func (export "main") (param $args_ptr i32) (param $args_len i32) (result i64)
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
    (i64.const 17179869184)  ;; ptr=0, len=4
  )
)
```

The source reuses `$args_ptr` and `$args_len` as the fibonacci accumulators `a` and `b` after reading the input. This is a common trick in hand-written WAT to avoid extra locals. The return value is a packed i64: lower 32 bits = result pointer, upper 32 bits = result length.

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/fibonacci.pvm` |
| Size | 266 bytes |
| Format | SPI |
| Functions | 1 |

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/fibonacci.pvm
```

```text
fn main(r1: u64, r7: u64) {
    let ptr_0_72
    let ptr_0_80
    let ptr_0_88

    // @0000

    // @0006
    let ptr_0_56 = u32[r7]
    ptr_0_72 = 0
    ptr_0_80 = 1
    ptr_0_88 = 0

    while (ptr_0_72 <u ptr_0_56) {
        // @0075
        ptr_0_72 = ptr_0_72 + 1
        ptr_0_80 = ptr_0_88 + ptr_0_80 << 32 >>u 32
        ptr_0_88 = ptr_0_80
    }

    // @0033
    u32[0x3000] = ptr_0_88
    halt()
}
```

**What to notice:**

- The `loop`/`block` pair from WAT is recovered as a `while` loop.
- `ptr_0_56` holds the input `n`, read from memory at `r7`.
- `ptr_0_72` is the loop counter `i`.
- `ptr_0_80` and `ptr_0_88` correspond to the fibonacci accumulators `b` and `a`.
- The swap logic `a, b = b, a+b` is visible in the loop body.
