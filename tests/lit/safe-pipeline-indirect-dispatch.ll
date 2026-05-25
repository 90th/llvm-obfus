; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-indirect-dispatch.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-indirect-dispatch.yaml -passes=obf-safe-pipeline -S %s -o %t
; RUN: %lli %t

define i32 @flatten_header(i32 %x, i32 %y) {
entry:
  %positive = icmp sgt i32 %x, 0
  br i1 %positive, label %left, label %right

left:
  %l0 = add i32 %x, 7
  br label %merge

right:
  %r0 = sub i32 7, %x
  br label %merge

merge:
  %v = phi i32 [ %l0, %left ], [ %r0, %right ]
  %cmp = icmp slt i32 %v, %y
  br i1 %cmp, label %small, label %large

small:
  %s = add i32 %v, %y
  ret i32 %s

large:
  %g = sub i32 %v, %y
  ret i32 %g
}

define i32 @vm_switch_dispatch(i32 %a, i32 %b, i32 %c) {
entry:
  %seed = add i32 %a, 7
  %mix = xor i32 %seed, %b
  %cond = icmp sgt i32 %mix, %c
  br i1 %cond, label %left, label %right

left:
  %l0 = mul i32 %mix, 3
  %l1 = add i32 %l0, %c
  %l2 = xor i32 %l1, 17
  %l3 = shl i32 %l2, 1
  br label %merge

right:
  %r0 = sub i32 %c, %mix
  %r1 = or i32 %r0, %a
  %r2 = and i32 %r1, 255
  %r3 = lshr i32 %r2, 1
  br label %merge

merge:
  %v = phi i32 [ %l3, %left ], [ %r3, %right ]
  %m0 = add i32 %v, %b
  %m1 = xor i32 %m0, %c
  %m2 = mul i32 %m1, 5
  %m3 = sub i32 %m2, %a
  ret i32 %m3
}

define i32 @main() {
entry:
  %f0 = call i32 @flatten_header(i32 5, i32 20)
  %f1 = call i32 @flatten_header(i32 -2, i32 3)
  %v0 = call i32 @vm_switch_dispatch(i32 2, i32 5, i32 3)
  %v1 = call i32 @vm_switch_dispatch(i32 1, i32 2, i32 10)
  %sum0 = add i32 %f0, %f1
  %sum1 = add i32 %sum0, %v0
  %sum = add i32 %sum1, %v1
  %ok = icmp eq i32 %sum, 645
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @flatten_header(i32
; CHECK: freeze i1
; CHECK: blockaddress(@flatten_header, %{{[^)]+}})
; CHECK: inttoptr i64
; CHECK: indirectbr ptr
; CHECK-LABEL: define i32 @vm_switch_dispatch(i32
; CHECK: call i32 %{{[^ ]+}}(i32 %{{[^,]+}}, i32 %{{[^,]+}}, i32 %{{[^,]+}}, i64 %{{[^)]+}})
; CHECK: define internal i32 @{{_[0-9a-f]+}}(i32
; CHECK: freeze i1
; CHECK: blockaddress(@{{_[0-9a-f]+}}, %{{[^)]+}})
; CHECK: indirectbr ptr
