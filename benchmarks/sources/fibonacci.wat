(module
  (memory 1)
  
  
  ;; fib(n) - params reused as a,b after reading n
  ;; local 0 ($args_ptr) -> reused as $a
  ;; local 1 ($args_len) -> reused as $b  
  ;; local 2 ($n) -> holds n
  ;; local 3 ($i) -> loop counter
  (func (export "main") (param $args_ptr i32) (param $args_len i32) (result i32 i32)
    (local $n i32)
    (local $i i32)
    
    ;; Read n from args into $n
    (local.set $n (i32.load (local.get $args_ptr)))
    
    ;; Initialize: a=0 (in $args_ptr), b=1 (in $args_len), i=0
    (local.set $args_ptr (i32.const 0))
    (local.set $args_len (i32.const 1))
    (local.set $i (i32.const 0))
    
    (block $break
      (loop $continue
        (br_if $break (i32.ge_u (local.get $i) (local.get $n)))
        
        ;; Swap: a, b = b, a+b
        ;; Use stack to compute without extra local:
        ;; Push b, push a+b, set a=pop (old b), set b=pop (a+b)
        (local.get $args_len)         ;; push b (will become new a)
        (i32.add (local.get $args_ptr) (local.get $args_len))  ;; push a+b (will become new b)
        (local.set $args_len)          ;; b = a+b
        (local.set $args_ptr)          ;; a = old b
        
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $continue)
      )
    )
    
    ;; Result is in $args_ptr (which is $a)
    (i32.store (i32.const 0) (local.get $args_ptr))
    (i32.const 0)  ;; result_ptr
    (i32.const 4)  ;; result_len
  )
)
