(module
  (type $unary-i32 (func (param i32) (result i32)))
  (type $unary-i64 (func (param i64) (result i64)))
  (type $unary-f32 (func (param f32) (result f32)))
  (type $unary-f64 (func (param f64) (result f64)))

  (import "env" "print_i32" (func $print_i32 (param i32)))
  (import "env" "sleep_msec" (func $sleep_msec (param i32)))

  (memory 1)

  (func $noise_i32 (type $unary-i32) (param $v i32) (result i32)
    local.get $v
    i32.const 17
    i32.add)

  (func $noise_i64 (type $unary-i64) (param $v i64) (result i64)
    local.get $v
    i64.const 1009
    i64.xor)

  (func $noise_f32 (type $unary-f32) (param $v f32) (result f32)
    local.get $v
    f32.const 1.25
    f32.add)

  (func $noise_f64 (type $unary-f64) (param $v f64) (result f64)
    local.get $v
    f64.const 2.5
    f64.sub)

  (func $depth4 (param $seed i32) (result i32)
    (local $i32v i32)
    (local $i64v i64)
    (local $f32v f32)
    (local $f64v f64)
    i32.const 0
    local.set $i32v
    i64.const 72623859790382856
    local.set $i64v
    f32.const 13.5
    local.set $f32v
    f64.const 29.25
    local.set $f64v
    block $done
      loop $spin
        local.get $i32v
        i32.const 20
        i32.ge_u
        br_if $done
        local.get $i32v
        i32.const 700
        i32.add
        call $print_i32
        i32.const 100
        call $sleep_msec
        local.get $i64v
        i64.const 257
        i64.add
        local.set $i64v
        local.get $f32v
        f32.const 0.5
        f32.add
        local.set $f32v
        local.get $f64v
        f64.const 0.25
        f64.sub
        local.set $f64v
        local.get $i32v
        i32.const 1
        i32.add
        local.set $i32v
        br $spin
      end
    end
    local.get $i64v
    i32.wrap_i64
    local.get $f32v
    i32.trunc_f32_s
    i32.xor
    local.get $f64v
    i32.trunc_f64_s
    i32.xor
    local.get $i32v
    i32.xor
    local.get $seed
    i32.xor)

  (func $depth3 (param $seed f64) (result f64)
    (local $i32v i32)
    (local $i64v i64)
    (local $f32v f32)
    (local $f64v f64)
    i32.const 31
    local.set $i32v
    i64.const 1234567890123
    local.set $i64v
    f32.const 7.75
    local.set $f32v
    local.get $seed
    local.set $f64v
    local.get $f32v
    call $noise_f32
    drop
    f64.const 4096.5
    local.get $i32v
    call $depth4
    f64.convert_i32_s
    f64.add
    local.get $f64v
    call $noise_f64
    f64.add)

  (func $depth2 (param $seed i64) (result i64)
    (local $i32v i32)
    (local $i64v i64)
    (local $f32v f32)
    (local $f64v f64)
    i32.const 47
    local.set $i32v
    local.get $seed
    local.set $i64v
    f32.const 3.125
    local.set $f32v
    f64.const 97.875
    local.set $f64v
    local.get $i32v
    call $noise_i32
    drop
    i64.const 8589934592
    local.get $f64v
    call $depth3
    i64.trunc_f64_s
    i64.xor
    local.get $i64v
    call $noise_i64
    i64.add)

  (func $depth1 (param $seed i32) (result i32)
    (local $i32v i32)
    (local $i64v i64)
    (local $f32v f32)
    (local $f64v f64)
    local.get $seed
    local.set $i32v
    i64.const 3405691582
    local.set $i64v
    f32.const 11.5
    local.set $f32v
    f64.const 19.25
    local.set $f64v
    local.get $f32v
    call $noise_f32
    drop
    i32.const 1437226410
    local.get $i64v
    call $depth2
    i32.wrap_i64
    i32.xor
    local.get $i32v
    call $noise_i32
    i32.add)

  (func $depth0 (param $seed f32) (result f32)
    (local $i32v i32)
    (local $i64v i64)
    (local $f32v f32)
    (local $f64v f64)
    i32.const 59
    local.set $i32v
    i64.const 78187493520
    local.set $i64v
    local.get $seed
    local.set $f32v
    f64.const 211.5
    local.set $f64v
    f32.const 64.25
    i32.const 91
    call $depth1
    f32.convert_i32_s
    f32.add
    local.get $f32v
    f32.add
    local.get $i32v
    f32.convert_i32_s
    f32.add
    local.get $i64v
    i32.wrap_i64
    f32.convert_i32_s
    f32.add
    local.get $f64v
    f32.demote_f64
    f32.add)

  (func (export "_start")
    f32.const 3.5
    call $depth0
    i32.trunc_f32_s
    call $print_i32))
