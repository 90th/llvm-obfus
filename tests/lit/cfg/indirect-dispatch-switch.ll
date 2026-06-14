; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o %t
; RUN: %lli %t

define i32 @switch_dispatch(i32 %x) {
entry:
  switch i32 %x, label %default [
    i32 0, label %zero
    i32 7, label %seven
    i32 9, label %seven
  ]

zero:
  ret i32 11

seven:
  ret i32 22

default:
  ret i32 33
}

define i32 @main() {
entry:
  %v0 = call i32 @switch_dispatch(i32 0)
  %v1 = call i32 @switch_dispatch(i32 7)
  %v2 = call i32 @switch_dispatch(i32 9)
  %v3 = call i32 @switch_dispatch(i32 4)
  %ok0 = icmp eq i32 %v0, 11
  %ok1 = icmp eq i32 %v1, 22
  %ok2 = icmp eq i32 %v2, 22
  %ok3 = icmp eq i32 %v3, 33
  %all0 = and i1 %ok0, %ok1
  %all1 = and i1 %ok2, %ok3
  %all = and i1 %all0, %all1
  %ret = select i1 %all, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @switch_dispatch(i32 %x)
; CHECK: entry:
; CHECK: %obf.idis.site0.aff.mul0 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64), i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc0 = add i64 %obf.idis.site0.aff.mul0, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor0 = xor i64 %obf.idis.site0.aff.enc0, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.mul1 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@switch_dispatch, %zero) to i64), i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc1 = add i64 %obf.idis.site0.aff.mul1, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor1 = xor i64 %obf.idis.site0.aff.enc1, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.mul2 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@switch_dispatch, %seven) to i64), i64 ptrtoint (ptr blockaddress(@switch_dispatch, %default) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc2 = add i64 %obf.idis.site0.aff.mul2, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor2 = xor i64 %obf.idis.site0.aff.enc2, {{-?[0-9]+}}
; CHECK: %obf.idis.state = freeze i32 %x
; CHECK: %obf.idis.case0 = icmp eq i32 %obf.idis.state, 0
; CHECK: %obf.idis.sel0 = select i1 %obf.idis.case0, i64 %obf.idis.site0.tok1, i64 %obf.idis.site0.tok0
; CHECK: %obf.idis.case1 = icmp eq i32 %obf.idis.state, 7
; CHECK: %obf.idis.sel1 = select i1 %obf.idis.case1, i64 %obf.idis.site0.tok2, i64 %obf.idis.sel0
; CHECK: %obf.idis.case2 = icmp eq i32 %obf.idis.state, 9
; CHECK: %obf.idis.sel2 = select i1 %obf.idis.case2, i64 %obf.idis.site0.tok2, i64 %obf.idis.sel1
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
; CHECK: indirectbr ptr %obf.idis.dest, [label %default, label %zero, label %seven]
; CHECK-NOT: switch i32 %x
