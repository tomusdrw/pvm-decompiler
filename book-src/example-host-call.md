# Host Call Log (WAT)

A minimal WAT program that demonstrates PVM host calls. It invokes `ecalli 100` (the log host call) to print "Hello from PVM!" and returns 42.

## Source

File: `examples/sources/host-call-log.wat`

```wat
(module
  (import "env" "pvm_ptr" (func $pvm_ptr (param i64) (result i64)))
  (import "env" "host_call" (func $host_call (param i64 i64 i64 i64 i64 i64)))
  (memory (export "memory") 1)
  ;; "test-log" at offset 0 (8 bytes)
  (data (i32.const 0) "test-log")
  ;; "Hello from PVM!" at offset 8 (15 bytes)
  (data (i32.const 8) "Hello from PVM!")
  (func (export "main") (param $args_ptr i32) (param $args_len i32) (result i64)
    ;; ecalli 100 = log host call
    ;; r7 = level (3 = INFO)
    ;; r8 = target_ptr (PVM address of "test-log")
    ;; r9 = target_len (8)
    ;; r10 = msg_ptr (PVM address of "Hello from PVM!")
    ;; r11 = msg_len (15)
    (call $host_call
      (i64.const 100)
      (i64.const 3)
      (call $pvm_ptr (i64.const 0))
      (i64.const 8)
      (call $pvm_ptr (i64.const 8))
      (i64.const 15))
    ;; Return result: store 42 at offset 24, return (ptr=24, len=4)
    (i32.store (i32.const 24) (i32.const 42))
    (i64.const 17179869208)))
```

The program uses two imported helpers:
- `pvm_ptr` -- translates a Wasm linear-memory offset to a PVM address
- `host_call` -- dispatches to a numbered host function (here, `ecalli 100` for logging)

## Compiled Metadata

| Field | Value |
| --- | --- |
| File | `examples/compiled/host-call-log.pvm` |
| Size | 12490 bytes |
| Format | SPI |
| Functions | 1 |

## Decompiled Output

```bash
./target/release/pvm-decompiler examples/compiled/host-call-log.pvm
```

```text
fn main(r0: u64, r1: u64, r3: u64, r5: u64, r6: u64, r7: u64, r12: u64) {
    let var_28
    // @0006
    log()
    u32[var_28 + 0x33000] = 42
    halt()
}
```

**What to notice:**

- **Host call recognition**: The `ecalli 100` instruction is recognized and rendered as `log()`. The decompiler collapses the multi-register setup (level, target pointer/length, message pointer/length) into a single named call.
- **Compact output**: Despite the binary being 12 KB (due to the `pvm_ptr` helper and runtime support code being compiled in), the decompiler produces just 7 lines of pseudo-code for the main function.
- **Result encoding**: `u32[var_28 + 0x33000] = 42` stores the return value, followed by `halt()`.
- **Binary size vs. complexity**: The 12 KB binary size comes from the `pvm_ptr` address-translation helper and memory setup code compiled from the imports, not from the application logic itself.
