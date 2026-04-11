; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/bogus-control-flow.yaml -passes=obf-bogus-cf -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/bogus-control-flow.yaml -passes=obf-bogus-cf -S %s -o %t
; RUN: %lli %t

define i32 @branchy(i32 %x) {
entry:
  %is_zero = icmp eq i32 %x, 0
  br i1 %is_zero, label %zero, label %nonzero

zero:
  ret i32 7

nonzero:
  br label %merge

merge:
  ret i32 %x
}

define i32 @main() {
entry:
  %value = call i32 @branchy(i32 5)
  %ok = icmp eq i32 %value, 5
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @branchy
; CHECK: %obf.opaque.true = icmp eq
; CHECK: br i1 %obf.opaque.true, label %merge, label %obf.bogus
; CHECK: obf.bogus:
; CHECK: %obf.bogus.xor = xor
