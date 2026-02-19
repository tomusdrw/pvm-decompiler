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

    (i32.const 0)  ;; result_ptr
    (i32.const 4)  ;; result_len
  )
)
