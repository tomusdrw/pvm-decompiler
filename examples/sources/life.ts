// Input: u32 steps
// Output encoding: [u32 width][u32 height][u8 cells...], row-major, 1=alive, 0=dead

const WIDTH: i32 = 16;
const HEIGHT: i32 = 16;
const CELL_COUNT: i32 = WIDTH * HEIGHT;

// Two cell buffers + output area, all dynamically allocated
let BUF_A: u32 = 0;
let BUF_B: u32 = 0;
let OUTPUT_BASE: u32 = 0;

export let result_ptr: i32 = 0;
export let result_len: i32 = 0;

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

function clear(base: u32): void {
  for (let i: i32 = 0; i < CELL_COUNT; ++i) {
    store<u8>(base + i as u32, 0);
  }
}

function seed_world(base: u32): void {
  clear(base);

  // Glider at (1,1)
  set(base, 2, 1, 1);
  set(base, 3, 2, 1);
  set(base, 1, 3, 1);
  set(base, 2, 3, 1);
  set(base, 3, 3, 1);

  // Blinker at (10,2)
  set(base, 10, 2, 1);
  set(base, 11, 2, 1);
  set(base, 12, 2, 1);

  // Toad at (4,10)
  set(base, 5, 10, 1);
  set(base, 6, 10, 1);
  set(base, 7, 10, 1);
  set(base, 4, 11, 1);
  set(base, 5, 11, 1);
  set(base, 6, 11, 1);
}

function step_once(src: u32, dst: u32): void {
  const hm1 = HEIGHT - 1;
  const wm1 = WIDTH - 1;

  for (let y = 0; y < HEIGHT; ++y) {
    const ym1 = y == 0 ? hm1 : y - 1;
    const yp1 = y == hm1 ? 0 : y + 1;

    for (let x = 0; x < WIDTH; ++x) {
      const xm1 = x == 0 ? wm1 : x - 1;
      const xp1 = x == wm1 ? 0 : x + 1;

      const neighbors =
        get(src, xm1, ym1) +
        get(src, x, ym1) +
        get(src, xp1, ym1) +
        get(src, xm1, y) +
        get(src, xp1, y) +
        get(src, xm1, yp1) +
        get(src, x, yp1) +
        get(src, xp1, yp1);

      const self = get(src, x, y);
      let next = 0;
      if (self != 0) {
        if (neighbors == 2 || neighbors == 3) next = 1;
      } else {
        if (neighbors == 3) next = 1;
      }
      set(dst, x, y, next);
    }
  }
}

function encode_result(src: u32): void {
  store<u32>(OUTPUT_BASE, WIDTH as u32);
  store<u32>(OUTPUT_BASE + 4, HEIGHT as u32);

  for (let i: i32 = 0; i < CELL_COUNT; ++i) {
    const v = load<u8>(src + i as u32);
    store<u8>(OUTPUT_BASE + 8 + i as u32, v);
  }

  result_ptr = OUTPUT_BASE as i32;
  result_len = 8 + CELL_COUNT;
}

export function main(args_ptr: i32, args_len: i32): void {
  // Allocate working buffers: 2 cell buffers + output (width + height + cells)
  const alloc_size = CELL_COUNT * 2 + 8 + CELL_COUNT;
  const base = heap.alloc(alloc_size) as u32;
  BUF_A = base;
  BUF_B = base + CELL_COUNT as u32;
  OUTPUT_BASE = BUF_B + CELL_COUNT as u32;

  const steps = load<i32>(args_ptr);

  seed_world(BUF_A);

  let current = BUF_A;
  let next = BUF_B;

  for (let i: i32 = 0; i < steps; ++i) {
    step_once(current, next);
    const tmp = current;
    current = next;
    next = tmp;
  }

  encode_result(current);
}
