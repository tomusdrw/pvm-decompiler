# Example 2: as-fibonacci

This one is from AssemblyScript. It is still small enough to read easy.

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

## Compiled Metadata

From `--debug` output and file size:

| Field | Value |
| --- | --- |
| Compiled file | `examples/compiled/as-fibonacci.pvm` |
| File size | `1338` bytes |
| Container format | `SPI` |
| Functions detected | `2` |
| Instruction count | `334` |
| Jump table | `[33, 10, 1045]` (3 entries) |
| Code size | `0x45E` (`1118`) bytes (max CFG block end PC) |

## Decompiled Output (default pseudo-code)

```text
fn main(r1: u64, r7: u64, r8: u64, r9: u64, r10: u64, r11: u64, r12: u64) {
    func_1(r1 - 16)
}

fn func_1(r1: u64) {
    let ptr_0_40
    let ptr_0_520
    let ptr_0_536
    let ptr_0_88

    ptr_0_40 = u64[r1] - 0x50000
    ptr_0_88 = heap_alloc(272)
    ptr_0_520 = 0
    let ptr_0_528 = 1
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

## Decompiled Output Refined With LLM

Command used:

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

