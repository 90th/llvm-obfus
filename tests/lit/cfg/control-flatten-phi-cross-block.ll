; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=1 -passes='obf-control-flatten,verify' -S %s -o %t.s1.ll
; RUN: %FileCheck %s < %t.s1.ll
; RUN: %opt -passes=verify -disable-output %t.s1.ll
; RUN: %lli %t.s1.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=42 -passes='obf-control-flatten,verify' -S %s -o %t.s42.ll
; RUN: %lli %t.s42.ll

; CHECK-LABEL: define i32 @flat_phi_cross_block
; CHECK: obf.flat.dispatch:

; Regression fixture for cross-block PHI input dominance hazard:
; %val is defined in block `a`, traversed through intermediate block `b` (b != a),
; and received by PHI %res in block `c` on edge b->c.
; The instruction must be marked as escaping and carried via dispatcher PHIs.
define i32 @flat_phi_cross_block(i32 %x, i1 %cond) {
entry:
  br i1 %cond, label %a, label %d

a:
  %val = add i32 %x, 42
  br label %b

b:
  br label %c

d:
  br label %c

c:
  %res = phi i32 [ %val, %b ], [ 0, %d ]
  ret i32 %res
}

define i32 @main() {
entry:
  %t1 = call i32 @flat_phi_cross_block(i32 8, i1 1)
  ; 8 + 42 = 50
  %cmp1 = icmp eq i32 %t1, 50
  br i1 %cmp1, label %check2, label %fail

check2:
  %t2 = call i32 @flat_phi_cross_block(i32 8, i1 0)
  ; 0
  %cmp2 = icmp eq i32 %t2, 0
  br i1 %cmp2, label %pass, label %fail

pass:
  ret i32 0

fail:
  ret i32 1
}
