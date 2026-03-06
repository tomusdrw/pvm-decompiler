// Memory addresses
let RESULT_HEAP: usize = 0;

function writeResult(val: i32): i64 {
  store<i32>(RESULT_HEAP, val);
  return (RESULT_HEAP as i64) | ((4 as i64) << 32);
}

// Function with multiple args
function add3(a: i32, b: i32, c: i32): i32 {
  return a + b + c;
}

// Recursive function
function factorial(n: i32): i32 {
  if (n <= 1) return 1;
  return n * factorial(n - 1);
}

// Function calls in loop
function square(n: i32): i32 {
  return n * n;
}

export function main(args_ptr: i32, args_len: i32): i64 {
  RESULT_HEAP = heap.alloc(256);
  const n = load<i32>(args_ptr); // Input 5

  let res = add3(n, 2, 3); // 5 + 2 + 3 = 10

  res += factorial(n); // 10 + 120 = 130

  let sumSquares = 0;
  for (let i = 0; i < 3; i++) {
    sumSquares += square(i); // 0 + 1 + 4 = 5
  }

  res += sumSquares; // 130 + 5 = 135

  return writeResult(res);
}
