// Memory addresses
let RESULT_HEAP: usize = 0;

// Globals
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

  // Loop
  let i = 0;
  while (i < input) {
    result += 1;
    i++;
  }

  // Nested Loop with break
  for (let j = 0; j < 5; j++) {
    for (let k = 0; k < 5; k++) {
      if (k > 2) break;
      result++;
    }
  }

  writeResult(result);
}
