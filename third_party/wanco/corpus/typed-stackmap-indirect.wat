(module
  (type $unary-i32 (func (param i32) (result i32)))

  (import "env" "print_i32" (func $print_i32 (param i32)))
  (import "env" "sleep_msec" (func $sleep_msec (param i32)))

  (memory 1)
  (table 2 funcref)

  (func $wrong-target (type $unary-i32) (param $seed i32) (result i32)
    i32.const 999
    call $print_i32
    local.get $seed
    i32.const -999
    i32.add)

  (func $checkpoint-target (type $unary-i32) (param $seed i32) (result i32)
    (local $counter i32)
    (local $wide i64)
    (local $single f32)
    (local $double f64)
    i32.const 0
    local.set $counter
    i64.const 1234605616436508552
    local.set $wide
    f32.const 12.5
    local.set $single
    f64.const 33.75
    local.set $double
    block $done
      loop $spin
        local.get $counter
        i32.const 12
        i32.ge_u
        br_if $done
        local.get $counter
        i32.const 800
        i32.add
        call $print_i32
        i32.const 80
        call $sleep_msec
        local.get $wide
        i64.const 257
        i64.xor
        local.set $wide
        local.get $single
        f32.const 0.5
        f32.add
        local.set $single
        local.get $double
        f64.const 0.25
        f64.sub
        local.set $double
        local.get $counter
        i32.const 1
        i32.add
        local.set $counter
        br $spin
      end
    end
    local.get $wide
    i32.wrap_i64
    local.get $single
    i32.trunc_f32_s
    i32.xor
    local.get $double
    i32.trunc_f64_s
    i32.xor
    local.get $counter
    i32.xor
    local.get $seed
    i32.xor)

  (elem (i32.const 0) $wrong-target $checkpoint-target)

  (func $dispatch (param $seed i32) (result i32)
    (local $i32v i32)
    (local $i64v i64)
    (local $f32v f32)
    (local $f64v f64)
    local.get $seed
    local.set $i32v
    i64.const 72623859790382856
    local.set $i64v
    f32.const 7.25
    local.set $f32v
    f64.const 19.5
    local.set $f64v
    i64.const 1084818905618843912
    local.get $i32v
    i32.const 1
    call_indirect (type $unary-i32)
    i64.extend_i32_s
    i64.xor
    i32.wrap_i64
    local.get $i64v
    i32.wrap_i64
    i32.xor
    local.get $f32v
    i32.trunc_f32_s
    i32.xor
    local.get $f64v
    i32.trunc_f64_s
    i32.xor)

  (func (export "_start")
    i32.const 73
    call $dispatch
    call $print_i32))
