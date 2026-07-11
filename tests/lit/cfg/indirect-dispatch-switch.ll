; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml --obf-seed=1 -passes=obf-indirect-dispatch -S %s -o %t.seed1.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml --obf-seed=1 -passes=obf-indirect-dispatch -S %s -o %t.seed1.second
; RUN: cmp %t.seed1.first %t.seed1.second
; RUN: %FileCheck %s < %t.seed1.first
; RUN: %opt -passes=verify -disable-output %t.seed1.first
; RUN: %lli %t.seed1.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml --obf-seed=3 -passes=obf-indirect-dispatch -S %s -o %t.seed3
; RUN: %python -c "import re,sys; p=re.compile(r'obf\.idis\.case\d+ = icmp eq i32 [^,]+, (\d+)'); a=p.findall(open(sys.argv[1]).read()); b=p.findall(open(sys.argv[2]).read()); sys.exit(0 if a and a!=b else 1)" %t.seed1.first %t.seed3
; RUN: %opt -passes=verify -disable-output %t.seed3
; RUN: %lli %t.seed3

define i32 @switch_dispatch(i32 %x) {
entry:
  switch i32 %x, label %default [
    i32 0, label %c0
    i32 1, label %c1
    i32 2, label %c2
    i32 3, label %c3
    i32 4, label %c4
    i32 5, label %c5
  ]
c0:
  ret i32 10
c1:
  ret i32 11
c2:
  ret i32 12
c3:
  ret i32 13
c4:
  ret i32 14
c5:
  ret i32 15
default:
  ret i32 99
}

define i32 @main() {
entry:
  %v0 = call i32 @switch_dispatch(i32 0)
  %v1 = call i32 @switch_dispatch(i32 1)
  %v2 = call i32 @switch_dispatch(i32 2)
  %v3 = call i32 @switch_dispatch(i32 3)
  %v4 = call i32 @switch_dispatch(i32 4)
  %v5 = call i32 @switch_dispatch(i32 5)
  %v6 = call i32 @switch_dispatch(i32 99)
  %e0 = icmp eq i32 %v0, 10
  %e1 = icmp eq i32 %v1, 11
  %e2 = icmp eq i32 %v2, 12
  %e3 = icmp eq i32 %v3, 13
  %e4 = icmp eq i32 %v4, 14
  %e5 = icmp eq i32 %v5, 15
  %e6 = icmp eq i32 %v6, 99
  %a0 = and i1 %e0, %e1
  %a1 = and i1 %e2, %e3
  %a2 = and i1 %e4, %e5
  %a3 = and i1 %a0, %a1
  %a4 = and i1 %a2, %e6
  %all = and i1 %a3, %a4
  %ret = select i1 %all, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @switch_dispatch(i32 %x)
; CHECK: entry:
; Token materialization: one aff.mul/aff.enc/xor triplet per unique target
; (default, c0..c5 in natural order -> tok0..tok6).
; CHECK: %obf.idis.site0.aff.mul0 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64), i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc0 = add i64 %obf.idis.site0.aff.mul0, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor0 = xor i64 %obf.idis.site0.aff.enc0, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.mul1 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@switch_dispatch, %c0) to i64), i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc1 = add i64 %obf.idis.site0.aff.mul1, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor1 = xor i64 %obf.idis.site0.aff.enc1, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.mul2 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@switch_dispatch, %c1) to i64), i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc2 = add i64 %obf.idis.site0.aff.mul2, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor2 = xor i64 %obf.idis.site0.aff.enc2, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.mul3 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@switch_dispatch, %c2) to i64), i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc3 = add i64 %obf.idis.site0.aff.mul3, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor3 = xor i64 %obf.idis.site0.aff.enc3, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.mul4 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@switch_dispatch, %c3) to i64), i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc4 = add i64 %obf.idis.site0.aff.mul4, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor4 = xor i64 %obf.idis.site0.aff.enc4, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.mul5 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@switch_dispatch, %c4) to i64), i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc5 = add i64 %obf.idis.site0.aff.mul5, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor5 = xor i64 %obf.idis.site0.aff.enc5, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.mul6 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@switch_dispatch, %c5) to i64), i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc6 = add i64 %obf.idis.site0.aff.mul6, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor6 = xor i64 %obf.idis.site0.aff.enc6, {{-?[0-9]+}}
; CHECK: %obf.idis.state = freeze i32 %x
; Six independent case comparisons feeding per-case candidate tokens, emitted in
; the seed-permuted order (case values are checked loosely; the committed %python
; RUN asserts the seed-1 vs seed-3 order actually differs).
; CHECK: %obf.idis.case0 = icmp eq i32 %obf.idis.state, {{[0-9]+}}
; CHECK: %obf.idis.cand0 = select i1 %obf.idis.case0, i64 %obf.idis.site0.tok{{[0-9]+}}, i64 0
; CHECK: %obf.idis.case1 = icmp eq i32 %obf.idis.state, {{[0-9]+}}
; CHECK: %obf.idis.cand1 = select i1 %obf.idis.case1, i64 %obf.idis.site0.tok{{[0-9]+}}, i64 0
; CHECK: %obf.idis.case2 = icmp eq i32 %obf.idis.state, {{[0-9]+}}
; CHECK: %obf.idis.cand2 = select i1 %obf.idis.case2, i64 %obf.idis.site0.tok{{[0-9]+}}, i64 0
; CHECK: %obf.idis.case3 = icmp eq i32 %obf.idis.state, {{[0-9]+}}
; CHECK: %obf.idis.cand3 = select i1 %obf.idis.case3, i64 %obf.idis.site0.tok{{[0-9]+}}, i64 0
; CHECK: %obf.idis.case4 = icmp eq i32 %obf.idis.state, {{[0-9]+}}
; CHECK: %obf.idis.cand4 = select i1 %obf.idis.case4, i64 %obf.idis.site0.tok{{[0-9]+}}, i64 0
; CHECK: %obf.idis.case5 = icmp eq i32 %obf.idis.state, {{[0-9]+}}
; CHECK: %obf.idis.cand5 = select i1 %obf.idis.case5, i64 %obf.idis.site0.tok{{[0-9]+}}, i64 0
; Balanced OR-reduction over candidate tokens (exact operand pairings prove the
; tree shape; a linear fold would read or(acc_prev, cand_next)).
; CHECK: %obf.idis.acc0_0 = or i64 %obf.idis.cand0, %obf.idis.cand1
; CHECK: %obf.idis.acc0_1 = or i64 %obf.idis.cand2, %obf.idis.cand3
; CHECK: %obf.idis.acc0_2 = or i64 %obf.idis.cand4, %obf.idis.cand5
; CHECK: %obf.idis.acc1_0 = or i64 %obf.idis.acc0_0, %obf.idis.acc0_1
; CHECK: %obf.idis.acc2_0 = or i64 %obf.idis.acc1_0, %obf.idis.acc0_2
; Matching balanced OR-reduction over the per-case hit bits.
; CHECK: %obf.idis.hit0_0 = or i1 %obf.idis.case0, %obf.idis.case1
; CHECK: %obf.idis.hit0_1 = or i1 %obf.idis.case2, %obf.idis.case3
; CHECK: %obf.idis.hit0_2 = or i1 %obf.idis.case4, %obf.idis.case5
; CHECK: %obf.idis.hit1_0 = or i1 %obf.idis.hit0_0, %obf.idis.hit0_1
; CHECK: %obf.idis.hit2_0 = or i1 %obf.idis.hit1_0, %obf.idis.hit0_2
; CHECK: %obf.idis.sel = select i1 %obf.idis.hit2_0, i64 %obf.idis.acc2_0, i64 %obf.idis.site0.tok{{[0-9]+}}
; CHECK: %obf.mba.sub
; CHECK: %obf.idis.unbias =
; CHECK: %obf.idis.rot.rot = or i64 %obf.idis.rot.lshr, %obf.idis.rot.shl
; CHECK: %obf.mba.xor
; CHECK: %obf.idis.delta =
; CHECK: %obf.idis.affine.sub =
; CHECK: %obf.idis.affine.dec =
; CHECK: %obf.mba.add
; CHECK: ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)
; CHECK: %obf.idis.dest = inttoptr i64 %obf.idis.addr to ptr
; CHECK: indirectbr ptr %obf.idis.dest, [label %default, label %c0, label %c1, label %c2, label %c3, label %c4, label %c5]
; CHECK-NOT: switch i32 %x
