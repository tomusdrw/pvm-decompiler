# Ananas

Ananas is a JAM service written in AssemblyScript. The source code is available at [github.com/tomusdrw/anan-as](https://github.com/tomusdrw/anan-as). It is the largest example in this repository and is useful for testing the decompiler on a complex, real-world AssemblyScript binary.

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/ananas.pvm` |
| Size | 452,760 bytes (~442 KB) |
| Format | SPI |
| Functions | 189 |
| Output lines | ~11,300 |
| Jump table entries | 1,066 |

This is the largest binary in the examples directory -- about 3x the size of the JAM fuzzy service. The AssemblyScript compiler generates 189 functions, which includes runtime support (garbage collector, memory allocator, string handling) in addition to the actual service logic.

## Decompiled Output (excerpt)

```bash
./target/release/pvm-decompiler examples/compiled/ananas.pvm
```

The entry point and initialization:

```text
fn main(r1: u64, r7: u64, r8: u64, r9: u64, r10: u64, r11: u64, r12: u64) {
    let ptr_0: ptr
    let ptr_0_104
    let ptr_0_208
    let ptr_0_240
    let ptr_0_248
    let ptr_0_320
    let ptr_0_40
    ...

    if (0xFEFD0000 >=u r1 - 16 - 256) {
        ptr_1088 = ptr_992 - 256
    }

    if (0xFEFD0000 >=u ptr_1088 - 3760) {
        RESULT_PTR = 0x4DFC
        var_883 = 1856
        var_884 = 0
        var_885 = 0
        goto block_399c;
    }

    return
```

A fragment showing the memory allocator logic (typical AssemblyScript runtime):

```text
    var_167 = u32[52]
    var_168 = ptr_0_528 + var_167

    if (var_168 <u 1024) {
        r4 = -1
    } else {
        u32[52] = var_168
        let ptr_6 = sbrk(16 << var_167 - var_168)
        goto block_3897;
    }
```

A fragment showing bitwise operations for data processing:

```text
    let var_97 = 32 >>u (32 << (0xFFFFFFF0 & 32 >>u (32 << 15 + ...)))
    ptr_0_320 = var_97

    if (var_69 <u var_97 <u 0) {
        goto block_38ea;
    }
```

**What to notice:**

- The **stack guard check** `0xFEFD0000 >=u r1 - 16 - 256` at the top is inserted by the AssemblyScript compiler to detect stack overflow.
- `sbrk()` calls are recognized as the PVM memory growth host function. The allocator pattern (check available space, grow if needed) is clearly visible.
- `RESULT_PTR` is recognized as the standard JAM service output global.
- The 189 functions include many that are part of the AssemblyScript runtime, not user code. Functions like memory copy, string operations, and GC routines make up a significant portion of the output.

## Detected Functions

A selection of the 189 detected functions:

```text
fn main(r1: u64, r7: u64, r8: u64, r9: u64, r10: u64, r11: u64, r12: u64)
fn func_1(r0: u64, r1: u64, r9: u64, r10: u64, r11: u64, r12: u64)
fn func_2(r0: u64, r1: u64, r9: u64, r10: u64, r11: u64, r12: u64)
fn func_3(r0: u64, r1: u64, r9: u64, r10: u64, r11: u64, r12: u64)
fn func_4(r1: u64, r7: u64)
fn func_5(r0: u64, r1: u64, r9: u64, r10: u64, r11: u64, r12: u64)
...
fn func_21(r1: u64)
fn func_23(r1: u64, r7: u64)
...
```

Most functions share the signature `(r0, r1, r9, r10, r11, r12)` which reflects the AssemblyScript compiler's standard calling convention for PVM targets. Functions with fewer parameters (like `func_4(r1, r7)` and `func_21(r1)`) are likely utility or helper functions.

## Comparison with JAM Fuzzy Service

| Aspect | JAM Fuzzy Service | Ananas |
| --- | --- | --- |
| Source language | Rust | AssemblyScript |
| Binary size | 142 KB | 442 KB |
| Functions | 63 | 189 |
| Output lines | ~10,900 | ~11,300 |
| Jump table entries | 962 | 1,066 |
| Runtime overhead | Minimal | Large (AS runtime included) |

Despite being 3x larger in binary size, the ananas output is only slightly longer than the JAM fuzzy service. This is because much of the binary size comes from data sections and runtime code that decompiles into repetitive patterns. The Rust binary is more compact but its logic is denser.
