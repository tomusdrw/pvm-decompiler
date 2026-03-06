# Game of Life (AssemblyScript)

A Conway's Game of Life implementation on a 16x16 toroidal grid. It seeds glider, blinker, and toad patterns, then steps the simulation.

## Source

File: `examples/sources/as-life.ts`

```ts
const WIDTH: i32 = 16;
const HEIGHT: i32 = 16;
const CELL_COUNT: i32 = WIDTH * HEIGHT;

let BUF_A: u32 = 0;
let BUF_B: u32 = 0;
let OUTPUT_BASE: u32 = 0;

@inline
function idx(x: i32, y: i32): u32 {
  return (y * WIDTH + x) as u32;
}

@inline
function get(base: u32, x: i32, y: i32): u32 {
  return load<u8>(base + idx(x, y)) as u32;
}

@inline
function set(base: u32, x: i32, y: i32, v: u32): void {
  store<u8>(base + idx(x, y), v as u8);
}

function step_once(src: u32, dst: u32): void {
  for (let y = 0; y < HEIGHT; ++y) {
    for (let x = 0; x < WIDTH; ++x) {
      // count 8 neighbors with toroidal wrapping
      // apply B3/S23 rule
    }
  }
}

export function main(args_ptr: i32, args_len: i32): i64 {
  const base = heap.alloc(CELL_COUNT * 2 + 8 + CELL_COUNT) as u32;
  // ...seed, step, encode result...
}
```

(Source abbreviated for readability; see `examples/sources/as-life.ts` for the full listing.)

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/as-life.pvm` |
| Size | 2298 bytes |
| Format | SPI |
| Functions | 2 |

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/as-life.pvm
```

The output is 215 lines. Key fragments from `func_1`:

```text
    while (ptr_0_296 <s 256) {
        // @01d7
        u8[var_96 + 0x33000] = 0
        ptr_0_296 = ptr_0_296 + 1
    }
```

This is the `clear()` function inlined -- it zeroes out 256 bytes (the 16x16 grid).

```text
    u8[r2 + 0x33000] = 1
    u8[r2 + 0x33000] = 1
    // ... (14 stores total)
```

These are the `seed_world()` calls inlined -- each `set(base, x, y, 1)` becomes a direct byte store. The glider, blinker, and toad patterns total 14 alive cells.

```text
    while (ptr_0_688 <s 256) {
        u8[HEAP_PTR + 8 + ptr_0_688 << 32 >>u 32 + 0x33000] =
            u8[ptr_0_688 + ptr_0_608 << 32 >>u 32 + 0x33000]
        ptr_0_688 = ptr_0_688 + 1
    }
```

This is `encode_result()` -- copying the cell buffer into the output area (skipping the 8-byte width/height header).

**What to notice:**

- **Aggressive inlining**: All helper functions (`idx`, `get`, `set`, `clear`, `seed_world`, `encode_result`) are `@inline` or inlined by the compiler, producing a single large `func_1`.
- **Constant-folded seeds**: The seed pattern stores are fully unrolled -- no loops, just 14 direct `u8` stores.
- **Loop structure**: The `while (... <s 256)` loops correspond to iterating over `CELL_COUNT` (16 * 16 = 256) cells.
- **Double buffering**: The simulation swaps between `BUF_A` and `BUF_B` using `RESULT_LEN` and `RESULT_PTR` as buffer base pointers.
