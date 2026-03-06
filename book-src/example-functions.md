# Functions (AssemblyScript)

An AssemblyScript program with multiple helper functions: a three-argument add, a recursive factorial, and a square function called in a loop.

## Source

File: `examples/sources/as-tests-functions.ts`

```ts
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
```

The program computes `add3(5, 2, 3) + factorial(5) + (0^2 + 1^2 + 2^2) = 10 + 120 + 5 = 135`.

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/as-tests-functions.pvm` |
| Size | 986 bytes |
| Format | SPI |
| Functions | 3 |

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/as-tests-functions.pvm
```

```text
fn func_2(r1: u64, r7: u64) {
    // @0139
    u64[r1 + 224] = r7
    u64[r1 + 264] = 0
    u64[r1 + 272] = 0

    while (u64[r1 + 272] <s 3) {
        // @01b2
        let var_8 = u64[r1 + 264] + u64[r1 + 272] * u64[r1 + 272]
        u64[r1 + 296] = var_8
        u64[r1 + 264] = var_8
        u64[r1 + 272] = u64[r1 + 272] + 1
    }

    // @01e2
    let var_16 = u64[r1 + 224]
    u64[r1 + 328] = var_16
    let var_20 = u64[r1 + 216] + 5 + var_16
    u64[r1 + 336] = var_20
    let var_21 = RESULT_PTR
    u64[r1 + 344] = var_21
    let var_28 = var_20 + u64[r1 + 264] << 32 >>u 32
    u64[r1 + 360] = var_28
    u32[var_21 + 0x33000] = var_28
    halt()
}
```

(Showing `func_2` which contains the interesting computation; `main` and `func_1` handle entry and heap allocation boilerplate.)

**What to notice:**

- **Inlined helpers**: The `add3`, `factorial`, and `square` functions are inlined by the AssemblyScript compiler. The decompiler sees only the resulting combined computation.
- **Square-in-loop**: The `while (u64[r1 + 272] <s 3)` loop corresponds to the `for (let i = 0; i < 3; i++)` loop calling `square(i)`. The expression `u64[r1 + 272] * u64[r1 + 272]` is the inlined `i * i`.
- **Stack-frame layout**: Variables are stored at stack offsets (`r1 + 224`, `r1 + 264`, etc.) rather than in registers, reflecting the AssemblyScript compiler's frame-based calling convention.
- **Result encoding**: The final `u32[var_21 + 0x33000] = var_28` writes the result to the heap, followed by `halt()`.
