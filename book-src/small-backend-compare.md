# Small Backend Compare

Here I compare backend behavior on tiny fixture `simple-add.pvm`.

Source file for this one is not tracked in `examples/sources/`. It is hand-made tiny fixture.

## Tiny Program Metadata

| Field | Value |
| --- | --- |
| Compiled file | `examples/compiled/simple-add.pvm` |
| File size | `21` bytes |
| Container format | `raw ProgramBlob` (SPI decode fails, then raw decode works) |
| Functions detected | `1` |
| Instruction count | `6` |
| Jump table | `[]` |
| Code size | `0x10` (`16`) bytes (max CFG block end PC) |

## Backend 1: builtin (works now)

Command:

```bash
./target/release/pvm-decompiler --decompile --backend=builtin examples/compiled/simple-add.pvm
```

Short output:

```c
int64_t main(void) {
    int64_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
    r0 = r1 = r2 = r3 = r4 = r5 = r6 = r7 = r8 = r9 = r10 = r11 = r12 = 0;
    goto bb_0000;
bb_0000:
    r0 = 42;
    r1 = 100;
    r2 = %t5;
    goto bb_000f;
bb_000f:
    return %t6;
}
```

## Backend 2: rellic-docker (available but failing in this local env)

Command:

```bash
./target/release/pvm-decompiler --decompile --backend=rellic-docker examples/compiled/simple-add.pvm
```

Observed error:

```text
Error: "Rellic Docker produced no output. stderr: [rellic-docker] Assembling /work/input.ll -> /work/input.bc
/entrypoint.sh: 23: /opt/trailofbits/llvm/bin/llvm-as: not found
"
```

So for now, use `--backend=builtin` on this machine.

