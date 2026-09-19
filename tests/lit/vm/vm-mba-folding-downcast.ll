; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-integer-safety.yaml -passes=obf-vm -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll

; Regression fixture for multiplication by zero and one under VM lowering with MBA:
; Constant multiplication by 0 or 1 may be folded by MBA or lower to non-BinaryOperator roots.
; The lowering must safely downcast with dyn_cast instead of crashing on cast<BinaryOperator>.

; CHECK-LABEL: define internal i32 @__obf_vm_i_
define i32 @vm_int_mul_fold(i32 %x) {
entry:
  %m0 = mul i32 %x, 0
  %m1 = mul i32 %x, 1
  %res = add i32 %m0, %m1
  ret i32 %res
}

define i32 @main() {
entry:
  %res = call i32 @vm_int_mul_fold(i32 42)
  %ok = icmp eq i32 %res, 42
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
