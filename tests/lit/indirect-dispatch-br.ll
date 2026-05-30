; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o %t
; RUN: %lli %t

define i32 @branch_dispatch(i32 %x) {
entry:
  %cmp = icmp sgt i32 %x, 3
  br i1 %cmp, label %gt, label %le

gt:
  %inc = add i32 %x, 10
  ret i32 %inc

le:
  %dec = sub i32 3, %x
  ret i32 %dec
}

define i32 @main() {
entry:
  %lhs = call i32 @branch_dispatch(i32 5)
  %rhs = call i32 @branch_dispatch(i32 2)
  %ok0 = icmp eq i32 %lhs, 15
  %ok1 = icmp eq i32 %rhs, 1
  %both = and i1 %ok0, %ok1
  %ret = select i1 %both, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @branch_dispatch(i32 %x)
; CHECK: entry:
; CHECK: %obf.idis.site0.aff.mul0 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@branch_dispatch, %gt) to i64), i64 ptrtoint (ptr blockaddress(@branch_dispatch, %gt) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc0 = add i64 %obf.idis.site0.aff.mul0, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor0 = xor i64 %obf.idis.site0.aff.enc0, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.tok0 = add i64 %obf.idis.site0.rot0, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.mul1 = mul i64 sub (i64 ptrtoint (ptr blockaddress(@branch_dispatch, %le) to i64), i64 ptrtoint (ptr blockaddress(@branch_dispatch, %gt) to i64)), {{-?[0-9]+}}
; CHECK: %obf.idis.site0.aff.enc1 = add i64 %obf.idis.site0.aff.mul1, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.xor1 = xor i64 %obf.idis.site0.aff.enc1, {{-?[0-9]+}}
; CHECK: %obf.idis.site0.tok1 = add i64 %obf.idis.site0.rot1, {{-?[0-9]+}}
; CHECK: %obf.idis.cond = freeze i1 %cmp
; CHECK: %obf.idis.sel = select i1 %obf.idis.cond, i64 %obf.idis.site0.tok0, i64 %obf.idis.site0.tok1
; CHECK: %obf.mba.sub
; CHECK: %obf.idis.unbias =
; CHECK: %obf.idis.rot = or i64 %obf.idis.rot.lshr, %obf.idis.rot.shl
; CHECK: %obf.mba.xor
; CHECK: %obf.idis.delta =
; CHECK: %obf.idis.affine.sub =
; CHECK: %obf.idis.affine.dec =
; CHECK: %obf.mba.add
; CHECK: ptrtoint (ptr blockaddress(@branch_dispatch, %gt) to i64)
; CHECK: %obf.idis.dest = inttoptr i64 %obf.idis.addr to ptr
; CHECK: indirectbr ptr %obf.idis.dest, [label %gt, label %le]
; CHECK-NOT: br i1 %cmp
