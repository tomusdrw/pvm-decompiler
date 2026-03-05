# Example 1: br-table (small)

This is good small case. Source is WAT and control flow has `br_table`.

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

## Compiled Metadata

From `--debug` output and file size:

| Field | Value |
| --- | --- |
| Compiled file | `examples/compiled/br-table.pvm` |
| File size | `335` bytes |
| Container format | `SPI` |
| Functions detected | `1` |
| Instruction count | `70` |
| Jump table | `[10]` (1 entry) |
| Code size | `0xF2` (`242`) bytes (max CFG block end PC) |

## Decompiled Output (default pseudo-code)

```text
fn main(r1: u64, r7: u64, r8: u64) {
    let ptr_0_128
    let ptr_0_80

    // @000a
    let var_1 = u32[r7]

    switch (var_1) {
        case 0:
            // @00b1
            ptr_0_80 = 100
        case 1:
            // @00a5
            ptr_0_80 = 200
        case 2:
            // @0099
            ptr_0_80 = 300
        default:
            // @0040
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

## Decompiled Output Refined With LLM

Command used:

```bash
./target/release/pvm-decompiler --refine examples/compiled/br-table.pvm
```

```text
fn main(r1: u64, r7: u64, r8: u64) {
    let result_code
    let switch_value

    // Read branch index from memory location in r7
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
    // Store final result to fixed output memory address 0x20000
    u32[0x20000] = result_code
    halt()
}
```

