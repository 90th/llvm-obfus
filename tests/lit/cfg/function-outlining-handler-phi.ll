; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/function-outlining.yaml -passes=obf-function-outline,verify -S %s -o %t
; RUN: %FileCheck %s < %t
; RUN: %lli %t

define i32 @legacy_no_metadata(i32 %x) {
obf.flat.dispatch:
  %cmp0 = icmp eq i32 %x, 0
  br i1 %cmp0, label %handler0, label %obf.flat.dispatch.split

obf.flat.dispatch.split:
  %twice = shl i32 %x, 1
  %cmp1 = icmp eq i32 %x, 1
  br i1 %cmp1, label %handler0, label %obf.flat.dispatch.left

obf.flat.dispatch.left:
  %cmp2 = icmp eq i32 %x, 2
  br i1 %cmp2, label %handler1, label %default

handler0:
  %p = phi i32 [ %x, %obf.flat.dispatch ], [ %twice, %obf.flat.dispatch.split ]
  %a = add i32 %p, 10
  br label %default

handler1:
  %b = add i32 %x, 20
  br label %default

default:
  %r = phi i32 [ %x, %obf.flat.dispatch.left ], [ %a, %handler0 ], [ %b, %handler1 ]
  ret i32 %r
}

define i32 @main() {
entry:
  %a = call i32 @legacy_no_metadata(i32 0)
  %b = call i32 @legacy_no_metadata(i32 1)
  %c = call i32 @legacy_no_metadata(i32 2)
  %d = call i32 @legacy_no_metadata(i32 3)
  %ok0 = icmp eq i32 %a, 10
  %ok1 = icmp eq i32 %b, 12
  %ok2 = icmp eq i32 %c, 22
  %ok3 = icmp eq i32 %d, 3
  %ab = and i1 %ok0, %ok1
  %cd = and i1 %ok2, %ok3
  %ok = and i1 %ab, %cd
  %result = select i1 %ok, i32 0, i32 1
  ret i32 %result
}

; CHECK-LABEL: define i32 @legacy_no_metadata(i32 %x)
; CHECK: %obf.shard.indirect = inttoptr
; CHECK: call {{.*}} %obf.shard.indirect
; CHECK-LABEL: define internal {{.*}} @__obf_shard_{{[0-9a-f]+}}
; CHECK: phi i32
