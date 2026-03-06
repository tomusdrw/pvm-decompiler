# Control Flow

A larger AssemblyScript example that exercises multiple control flow patterns: `if/else`, `while`, nested `for` loops, and `break`.

## Source

File: `examples/sources/as-tests-control-flow.ts`

```ts
let RESULT_HEAP: usize = 0;

export let result_ptr: i32 = 0;
export let result_len: i32 = 0;

function writeResult(val: i32): void {
  store<i32>(RESULT_HEAP, val);
  result_ptr = RESULT_HEAP as i32;
  result_len = 4;
}

export function main(args_ptr: i32, args_len: i32): void {
  RESULT_HEAP = heap.alloc(256);
  const input = load<i32>(args_ptr);
  let result = 0;

  // If/Else
  if (input > 10) {
    result = 1;
  } else {
    result = 2;
  }

  // While loop
  let i = 0;
  while (i < input) {
    result += 1;
    i++;
  }

  // Nested loop with break
  for (let j = 0; j < 5; j++) {
    for (let k = 0; k < 5; k++) {
      if (k > 2) break;
      result++;
    }
  }

  writeResult(result);
}
```

This program does three things in sequence:
1. Sets `result` to 1 or 2 depending on whether `input > 10`
2. Adds `input` to `result` via a while loop
3. Adds to `result` in a 5x5 nested loop, but the inner loop breaks when `k > 2` (so effectively 5x3 = 15 iterations)

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/as-tests-control-flow.pvm` |
| Format | SPI |
| Functions | 2 |

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/as-tests-control-flow.pvm
```

```text
fn main(r1: u64, r7: u64, r8: u64, r9: u64, r10: u64, r11: u64, r12: u64) {
    func_1(r1 - 16)
}

fn func_1(r1: u64) {
    let ptr_0_40
    let ptr_0_512
    let ptr_0_568
    let ptr_0_576
    let ptr_0_680
    let ptr_0_688
    let ptr_0_760
    let ptr_0_768
    let ptr_0_88

    ptr_0_40 = u64[r1] - 0x50000
    ptr_0_88 = heap_alloc(272)

    RESULT_PTR = ptr_0_88
    let ptr_0_464 = *ptr_0_40
    ptr_0_512 = 2

    if (*ptr_0_40 <=s 10) {
        ptr_0_568 = 0
        ptr_0_576 = ptr_0_512
        goto block_0376;
    } else {
    }

    ptr_0_512 = 1

    ptr_0_568 = 0
    ptr_0_576 = ptr_0_512

    block_0376:
    while (ptr_0_568 <s ptr_0_464) {
        ptr_0_568 = ptr_0_568 + 1
        ptr_0_576 = ptr_0_576 + 1
    }

    ptr_0_680 = 0
    ptr_0_688 = ptr_0_576

    while (ptr_0_680 <s 5) {
        ptr_0_760 = 0
        ptr_0_768 = ptr_0_688

        while (ptr_0_760 <s 5 & ptr_0_760 <=s 2) {
            ptr_0_760 = ptr_0_760 + 1
            ptr_0_768 = ptr_0_768 + 1
        }

        ptr_0_680 = ptr_0_680 + 1
        ptr_0_688 = ptr_0_768
    }

    u32[RESULT_PTR + 0x50000] = ptr_0_688
    RESULT_LEN = 4
    HEAP_PTR = 4
    halt()
}
```

**What to notice:**

- **If/else recovery**: The `if (*ptr_0_40 <=s 10)` branch corresponds to the source `if (input > 10)` (the condition is inverted because the compiler swapped the true/false branches). `ptr_0_512` starts as 2 (the else case) and gets overwritten to 1 if the condition falls through.

- **While loop**: The `while (ptr_0_568 <s ptr_0_464)` loop is a direct match to `while (i < input)`. The variable `ptr_0_576` accumulates the result.

- **Nested loops with break**: The outer `while (ptr_0_680 <s 5)` is the `for j` loop. The inner `while (ptr_0_760 <s 5 & ptr_0_760 <=s 2)` combines the loop condition `k < 5` with the break condition `k > 2` into a single compound condition. This is how the decompiler represents early exits from loops.

- **Inlined function**: The `writeResult` helper is inlined by the compiler, so it appears as direct assignments to `RESULT_PTR`, `RESULT_LEN`, and a memory store at the end.

## Reading Tips

When analyzing decompiled PVM output, keep these patterns in mind:

| Pattern in output | Meaning |
| --- | --- |
| `u32[addr]` or `u64[addr]` | Memory load/store at the given address |
| `*ptr` | Pointer dereference (load from computed address) |
| `>s`, `<s`, `<=s` | Signed comparison operators |
| `<u`, `>=u` | Unsigned comparison operators |
| `heap_alloc(n)` | Runtime heap allocation of `n` bytes |
| `RESULT_PTR`, `RESULT_LEN` | Recognized global exports |
| `halt()` | Program termination (ecalli) |
| `goto block_XXXX` | Jump to a labeled block (unstructured control flow) |
