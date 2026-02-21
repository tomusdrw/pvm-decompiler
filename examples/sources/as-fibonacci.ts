
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
