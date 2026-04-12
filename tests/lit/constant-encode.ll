; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode.yaml -passes=obf-constant-encode -S %s -o - | %opt -passes=instcombine -S -o - | %FileCheck %s --check-prefix=INST
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

define i32 @value() {
entry:
  ret i32 42
}

define i32 @main() {
entry:
  %value = call i32 @value()
  %ok = icmp eq i32 %value, 42
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; IR-LABEL: define i32 @value()
; IR: %obf.const.mba.seed.a = alloca i64
; IR: %obf.const.seed.slot = alloca i64
; IR: store volatile i64
; IR: %obf.const.seed = load volatile i64, ptr %obf.const.seed.slot
; IR: %obf.const.seed.cast = trunc i64 %obf.const.seed to i32
; IR: %obf.const.mask = {{(sub|or) i32}}
; IR: %obf.const = {{(sub|or) i32}}
; IR: ret i32 %obf.const
; IR-NOT: ret i32 42

; INST-LABEL: define i32 @value()
; INST: %obf.const.mba.seed.a = alloca i64
; INST: %obf.const.seed = load volatile i64, ptr %obf.const.seed.slot
; INST: %obf.const.seed.cast = trunc i64 %obf.const.seed to i32
; INST: %obf.const = {{(sub|or) i32}}
; INST: ret i32 %obf.const
; INST-NOT: ret i32 42
