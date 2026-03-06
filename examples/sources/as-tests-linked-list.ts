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
