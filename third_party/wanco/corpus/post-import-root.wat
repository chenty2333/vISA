(module
  (import "env" "checkpoint_window" (func $checkpoint_window))
  (import "env" "print_i32" (func $print_i32 (param i32)))

  (memory 1)

  (func (export "_start")
    (call $checkpoint_window)
    (call $print_i32 (i32.const 1004)))
)
