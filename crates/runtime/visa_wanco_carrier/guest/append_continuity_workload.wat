(module
  (import "env" "print_i32" (func $print_i32 (param i32)))
  (import "env" "sleep_msec" (func $sleep_msec (param i32)))
  (import "env" "visa_ha_append_step"
    (func $append_step (param i32 i32) (result i32)))

  (memory 1)
  (global $started (mut i32) (i32.const 0))
  (global $progress (mut i32) (i32.const 0))

  (func $observe_step (param $is_start i32)
    (local $result i32)
    (local.set $result
      (call $append_step (global.get $progress) (local.get $is_start)))
    (call $print_i32 (global.get $progress))
    (call $print_i32 (local.get $result)))

  (func (export "_start")
    (if (i32.eqz (global.get $started))
      (then
        (call $observe_step (i32.const 1))
        (global.set $started (i32.const 1))))

    (block $done
      (loop $steps
        (call $sleep_msec (i32.const 100))
        (global.set $progress
          (i32.add (global.get $progress) (i32.const 1)))
        (call $observe_step (i32.const 0))
        (br_if $steps
          (i32.lt_u (global.get $progress) (i32.const 12)))
        (br $done))))
)
