(module
  (import "env" "pvm_ptr" (func $pvm_ptr (param i64) (result i64)))
  (import "env" "host_call_2b" (func $host_call_2b (param i64 i64 i64) (result i64)))
  (import "env" "host_call_r8" (func $host_call_r8 (result i64)))
  (memory (export "memory") 1)
  ;; "data" at offset 0 (4 bytes)
  (data (i32.const 0) "data")
  (func (export "main") (param $args_ptr i32) (param $args_len i32) (result i64)
    ;; Call read (ecalli 3) with 2 args + r8 capture:
    ;; r7 = key_ptr, r8 = key_len
    ;; Returns: r7 = status, r8 = data_len (captured via host_call_2b)
    (drop (call $host_call_2b
      (i64.const 3)                  ;; ecalli index = read
      (call $pvm_ptr (i64.const 0))  ;; r7 = ptr to "data"
      (i64.const 4)))                ;; r8 = key length
    ;; Retrieve r8 (data_len) from the capture slot
    (i64.store (i32.const 16) (call $host_call_r8))
    ;; Return success
    (i64.const 0)))
