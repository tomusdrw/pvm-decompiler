# Linked List (AssemblyScript)

An AssemblyScript program that creates a three-node linked list and sums its values recursively.

## Source

File: `examples/sources/as-tests-linked-list.ts`

```ts
// Memory addresses
let RESULT_HEAP: usize = 0;
let NODE_HEAP: usize = 0;

function writeResult(val: i32): i64 {
  store<i32>(RESULT_HEAP, val);
  return (RESULT_HEAP as i64) | ((4 as i64) << 32);
}

// Node structure: [value: i32, next: i32] (8 bytes)

function createNode(ptr: i32, val: i32, next: i32): void {
  store<i32>(ptr, val);
  store<i32>(ptr + 4, next);
}

function sumList(head: i32): i32 {
  if (head == 0) return 0;

  const val = load<i32>(head);
  const next = load<i32>(head + 4);

  // Recursive sum
  return val + sumList(next);
}

export function main(args_ptr: i32, args_len: i32): i64 {
  RESULT_HEAP = heap.alloc(256);
  NODE_HEAP = heap.alloc(32); // 3 nodes * 8 bytes each = 24 bytes
  // Create list: 10 -> 20 -> 30 -> null

  createNode(NODE_HEAP, 10, NODE_HEAP + 8);
  createNode(NODE_HEAP + 8, 20, NODE_HEAP + 16);
  createNode(NODE_HEAP + 16, 30, 0);

  const sum = sumList(NODE_HEAP); // 60

  return writeResult(sum);
}
```

The program builds a linked list `10 -> 20 -> 30 -> null`, then recursively sums the values to produce 60.

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/as-tests-linked-list.pvm` |
| Size | 1945 bytes |
| Format | SPI |
| Functions | 5 |

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/as-tests-linked-list.pvm
```

The output is large (501 lines) due to heap allocation boilerplate. Here are the most interesting fragments:

```text
fn func_2(r7: u64) {
    // @035f
    u32[RESULT_PTR + 0x33000] = r7
    halt()
}
```

`func_2` is the `writeResult` helper -- it writes the result to the heap and halts.

```text
fn func_4(r0: u64, r1: u64, r9: u64, r10: u64, r11: u64) {
    if (0xFEFD0000 >=u r1 - 72) {
        // @056e
        u32[r9 + 0x33000] = r10
        u32[r9 + 0x33004] = r11
        call_indirect(r0)
    }
}
```

`func_4` is the `createNode` helper -- it stores `value` and `next` at adjacent 4-byte offsets, matching the `[value: i32, next: i32]` node layout.

**What to notice:**

- **Pointer arithmetic**: The node structure is visible as two consecutive `u32` stores at offsets `+0x33000` and `+0x33004` (4 bytes apart).
- **Recursive traversal**: The `sumList` function compiles into `func_3`, which uses `call_indirect(r0)` to call back into itself -- the recursive `sumList(next)` call.
- **Two heap allocations**: `func_1` (the main logic) performs two `heap_alloc` calls, matching `heap.alloc(256)` and `heap.alloc(32)` from the source.
- **Heap boilerplate**: Much of the output is the `sbrk`-based heap allocator pattern. The design principle of this decompiler favors showing high-level intent, but the allocator code is not yet collapsed for this example.
