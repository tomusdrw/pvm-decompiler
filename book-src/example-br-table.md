# Branch Table

A small WAT program that uses `br_table` for indexed branching. The decompiler recovers this as a `switch/case` statement.

## Source

File: `examples/sources/br-table.wat`

```wat
(module
  (memory 1)
  (func (export "main") (param $args_ptr i32) (param $args_len i32) (result i32 i32)
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
    (i32.const 0)
    (i32.const 4)
  )
)
```

The program reads an index from memory, branches to one of four cases (setting result to 100, 200, 300, or 0), then falls back to 999 if the result is still zero. Finally it writes the result to memory.

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/br-table.pvm` |
| Size | 335 bytes |
| Format | SPI |
| Functions | 1 |
| Instructions | 70 |
| Jump table entries | 1 |

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/br-table.pvm
```

```text
fn main(r1: u64, r7: u64, r8: u64) {
    let ptr_0_128
    let ptr_0_80

    let var_1 = u32[r7]

    switch (var_1) {
        case 0:
            ptr_0_80 = 100
        case 1:
            ptr_0_80 = 200
        case 2:
            ptr_0_80 = 300
        default:
            ptr_0_80 = 0
    }

    if (!(ptr_0_80)) {
        ptr_0_128 = 999
        goto block_00d5;
    } else {
        ptr_0_128 = 999
    }
    block_00d5:
    u32[0x20000] = ptr_0_128
    halt()
}
```

**What to notice:**

- The `br_table` is recovered as a clean `switch` statement with four cases.
- The variable `ptr_0_80` holds the intermediate result from each case.
- The fallback check (`if result == 0 then 999`) is visible in the `if` block.
- Memory write `u32[0x20000]` corresponds to the `i32.store` at offset 0 plus the PVM memory base address.

## Refined Output (LLM)

```bash
./target/release/pvm-decompiler --refine examples/compiled/br-table.pvm
```

```text
fn main(r1: u64, r7: u64, r8: u64) {
    let result_code
    let switch_value

    let switch_index = u32[r7]

    switch (switch_index) {
        case 0: switch_value = 100
        case 1: switch_value = 200
        case 2: switch_value = 300
        default: switch_value = 0
    }

    if (!(switch_value)) {
        result_code = 999
        goto block_00d5;
    } else {
        result_code = 999
    }
    block_00d5:
    u32[0x20000] = result_code
    halt()
}
```

The LLM renames `ptr_0_80` to `switch_value` and `ptr_0_128` to `result_code`, making the intent clearer.
