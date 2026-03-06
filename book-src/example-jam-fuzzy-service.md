# JAM Fuzzy Service

This is a real-world JAM service binary compiled in Rust. No source code is available for this one -- it is included as a stress test for the decompiler on a production-size program.

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/jam-fuzzy-service.pvm` |
| Size | 145,725 bytes (~142 KB) |
| Format | SPI |
| Functions | 63 |
| Output lines | ~10,900 |
| Jump table entries | 962 |

This is significantly larger than the toy examples. The binary contains 63 detected functions and almost a thousand jump table entries, which means the original code uses heavy branching -- typical for a service that handles many message types.

## Decompiled Output (excerpt)

```bash
./target/release/pvm-decompiler examples/compiled/jam-fuzzy-service.pvm
```

The full output is about 10,900 lines. Here is the `main` function signature and a representative fragment showing nested conditionals with host calls:

```text
fn main(r0: u64, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64, r6: u64, r7: u64, r8: u64) {
    let cond_128: bool
    let ptr_0: ptr
    let ptr_1073: ptr
    let ptr_1073_0
    ...
```

A deeper fragment showing service logic:

```text
    if (0x4F87 >>u ptr_675_0 & 1 != 0) {
        if (fetch() >=u var_16944) {
            if (var_16944 != -1) {
                u64[ptr_1071 + 72] = 0
                u64[ptr_1071 + 48] = 1
                u64[ptr_1071 + 56] = 8
                u64[ptr_1071 + 64] = 0
                r8 = 0x17F10
                r7 = ptr_1071 + 40
                goto block_12850;
            } else {
                ptr_1071_32->field_0 = -0x8000000000000000
            }
        } else {
            if (var_16944 <s 0) {
                r7 = 0x17D28
                goto block_12480;
            } else {
                if (var_16944 == 0) {
                    let var_16960 = 0
                    u64[ptr_1071 + 0] = 1
                    goto block_155d7;
                } else {
                    ...
                }
            }
        }
    }
```

**What to notice:**

- The decompiler recovers deeply nested `if/else` trees from flat branch chains.
- `fetch()` is a recognized PVM host call (ecalli).
- Field access patterns like `ptr_1071_32->field_0` show the decompiler trying to infer struct-like memory layouts.
- Many `goto` targets remain because the control flow is too complex for full structuring. This is expected for large real-world binaries.
- The 63 detected functions give a rough sense of the original module structure.

## Detected Functions

The decompiler identifies 63 functions. The first few:

```text
fn main(r0: u64, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64, r6: u64, r7: u64, r8: u64)
fn func_0(r1: u64, r5: u64)
fn func_1(r0: u64, r1: u64, r5: u64, r6: u64, r7: u64, r8: u64)
fn func_2(r1: u64, r5: u64)
fn func_3(r1: u64, r5: u64, r6: u64)
fn func_4(r7: u64, r8: u64)
fn func_5(r7: u64, r8: u64)
fn func_6(r0: u64, r1: u64, r5: u64, r6: u64, r7: u64, r8: u64)
...
```

The varying function signatures (different register sets) reflect the Rust compiler's calling conventions at the PVM level.
