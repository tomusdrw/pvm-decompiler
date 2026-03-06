# Fibonacci (AssemblyScript)

The same fibonacci algorithm, but written in AssemblyScript. Comparing this with the [WAT version](./example-fibonacci.md) shows how a higher-level source language produces different binary structure.

## Source

File: `examples/sources/as-fibonacci.ts`

```ts
export let result_ptr: i32 = 0;
export let result_len: i32 = 0;

export function main(args_ptr: i32, args_len: i32): void {
  const RESULT_HEAP = heap.alloc(256);
  let n = load<i32>(args_ptr);
  let a: i32 = 0;
  let b: i32 = 1;

  while (n > 0) {
    b = a + b;
    a = b - a;
    n = n - 1;
  }

  store<i32>(RESULT_HEAP, a);

  result_ptr = RESULT_HEAP as i32;
  result_len = 4;
}
```

Compared to the WAT version, the AssemblyScript source uses `heap.alloc()` for the output buffer and exports `result_ptr`/`result_len` as globals. The compiler generates a two-function binary (entry wrapper + actual logic).

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/as-fibonacci.pvm` |
| Size | 1338 bytes |
| Format | SPI |
| Functions | 2 |
| Instructions | 334 |
| Jump table entries | 3 |
| Code size | 1118 bytes |

The binary is about 4x larger than the WAT version. The AssemblyScript compiler adds runtime support code, a heap allocator call, and a separate entry function.

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/as-fibonacci.pvm
```

```text
fn main(r1: u64, r7: u64, r8: u64, r9: u64, r10: u64, r11: u64, r12: u64) {
    func_1(r1 - 16)
}

fn func_1(r1: u64) {
    let ptr_0_40
    let ptr_0_520
    let ptr_0_528
    let ptr_0_536
    let ptr_0_88

    ptr_0_40 = u64[r1] - 0x50000
    ptr_0_88 = heap_alloc(272)
    ptr_0_520 = 0
    ptr_0_528 = 1
    ptr_0_536 = *ptr_0_40

    while (ptr_0_536 >s 0) {
        let var_136 = ptr_0_528 + ptr_0_520
        ptr_0_520 = var_136 - ptr_0_520
        ptr_0_528 = var_136
        ptr_0_536 = ptr_0_536 - 1
    }

    *ptr_0_88 = ptr_0_520
    RESULT_PTR = ptr_0_88
    RESULT_LEN = 4
    halt()
}
```

**What to notice:**

- The decompiler detects **two functions**: a thin `main` wrapper and the actual `func_1`.
- `heap_alloc(272)` corresponds to the source `heap.alloc(256)` -- the AssemblyScript runtime adds a small header to each allocation.
- The fibonacci loop is clean: `ptr_0_520` is `a`, `ptr_0_528` is `b`, and `ptr_0_536` is the countdown `n`.
- `RESULT_PTR` and `RESULT_LEN` are recognized as global exports.
- The `>s` operator means "signed greater than", matching the source `n > 0`.

## Refined Output (LLM)

```bash
./target/release/pvm-decompiler --refine examples/compiled/as-fibonacci.pvm
```

```text
fn main(r1: u64, r7: u64, r8: u64, r9: u64, r10: u64, r11: u64, r12: u64) {
    func_1(r1 - 16)
}

fn func_1(r1: u64) {
    let input_data_ptr
    let fib_next
    let fib_current
    let loop_counter
    let output_buffer

    input_data_ptr = u64[r1] - 0x50000
    output_buffer = heap_alloc(272)
    fib_current = 0
    fib_next = 1
    loop_counter = *input_data_ptr

    while (loop_counter >s 0) {
        let next_val = fib_next + fib_current
        fib_current = next_val - fib_current
        fib_next = next_val
        loop_counter = loop_counter - 1
    }

    *output_buffer = fib_current
    RESULT_PTR = output_buffer
    RESULT_LEN = 4
    halt()
}
```

The LLM correctly identifies the fibonacci pattern and gives meaningful names: `fib_current`, `fib_next`, `loop_counter`, and `output_buffer`.

## Comparison with WAT Version

| Aspect | WAT | AssemblyScript |
| --- | --- | --- |
| Binary size | ~335 bytes | 1338 bytes |
| Functions | 1 | 2 |
| Instructions | ~70 | 334 |
| Memory model | Direct store to address 0 | `heap_alloc` + globals |
| Loop style | `i < n` (unsigned) | `n > 0` (signed countdown) |

The WAT version is smaller because it is hand-written and avoids runtime overhead. The AssemblyScript version includes compiler-generated boilerplate but the core algorithm is still clearly visible in the decompiled output.
