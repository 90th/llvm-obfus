; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s
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

; CHECK-LABEL: define i32 @value()
; CHECK: %obf.const = xor i32
; CHECK: ret i32 %obf.const
; CHECK-NOT: ret i32 42
