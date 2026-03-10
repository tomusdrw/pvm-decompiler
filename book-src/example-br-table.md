# Branch Table

A small WAT program that uses `br_table` for indexed branching. The decompiler recovers this as a `switch/case` statement.

## Source

File: `examples/sources/br-table.wat`

```wat
(module
  (memory 1)
  (func (export "main") (param $args_ptr i32) (param $args_len i32) (result i64)
    (local $index i32)
    (local $result i32)

    (local.set $index (i32.load (local.get $args_ptr)))

    (block $case3
      (block $case2
        (block $case1
          (block $case0
            (br_table $case0 $case1 $case2 $case3 (local.get $index))
          )
          (local.set $result (i32.const 100))
          (br $case3)
        )
        (local.set $result (i32.const 200))
        (br $case3)
      )
      (local.set $result (i32.const 300))
      (br $case3)
    )

    (if (i32.eq (local.get $result) (i32.const 0))
      (then
        (local.set $result (i32.const 999))
      )
    )

    (i32.store (i32.const 0) (local.get $result))
    (i64.const 17179869184)  ;; ptr=0, len=4
  )
)
```

The program reads an index from memory, branches to one of four cases (setting result to 100, 200, 300, or 0), then falls back to 999 if the result is still zero. Finally it writes the result to memory. The return value is a packed i64: lower 32 bits = result pointer, upper 32 bits = result length.

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/br-table.pvm` |
| Size | 206 bytes |
| Format | SPI |
| Functions | 1 |

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/br-table.pvm
```

```text
fn main(r1: u64, r7: u64) {
    let ptr_0_72

    // @0006
    let var_1 = u32[r7]

    switch (var_1) {
        case 0:
            // @007b
            ptr_0_72 = 100

        case 1:
            // @006f
            ptr_0_72 = 200

        case 2:
            // @0063
            ptr_0_72 = 300

        default:
            // @0032
            ptr_0_72 = 999

            break;
    }

    // @003a
    u32[0x3000] = ptr_0_72
    halt()
}
```

**What to notice:**

- The `br_table` is recovered as a clean `switch` statement with four cases.
- The variable `ptr_0_72` holds the intermediate result from each case.
- The fallback check (`if result == 0 then 999`) has been folded into the default case by the compiler.
- Memory write `u32[0x3000]` corresponds to the `i32.store` at offset 0 plus the PVM memory base address.
