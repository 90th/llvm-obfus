; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/function-outlining.yaml -passes='obf-function-outline' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/function-outlining.yaml -passes='obf-function-outline' -S %s -o - | %opt -passes=verify -disable-output

define i32 @legacy_no_metadata(i32 %x) {
obf.flat.dispatch:
  %cmp0 = icmp eq i32 %x, 0
  br i1 %cmp0, label %handler0, label %obf.flat.dispatch.split

obf.flat.dispatch.split:
  %cmp1 = icmp ult i32 %x, 2
  br i1 %cmp1, label %obf.flat.dispatch.left, label %default

obf.flat.dispatch.left:
  %cmp2 = icmp eq i32 %x, 1
  br i1 %cmp2, label %handler1, label %default

handler0:
  %a = add i32 %x, 10
  br label %default

handler1:
  %b = add i32 %x, 20
  br label %default

default:
  %r = phi i32 [ %x, %obf.flat.dispatch.split ], [ %x, %obf.flat.dispatch.left ], [ %a, %handler0 ], [ %b, %handler1 ]
  ret i32 %r
}

define i32 @stale_block_metadata(i32 %x) !obf.flattened !0 {
obf.flat.dispatch:
  %cmp0 = icmp eq i32 %x, 0
  br i1 %cmp0, label %stale.handler0, label %obf.flat.dispatch.split

obf.flat.dispatch.split:
  %cmp1 = icmp ult i32 %x, 2
  br i1 %cmp1, label %obf.flat.dispatch.left, label %stale.default

obf.flat.dispatch.left:
  %cmp2 = icmp eq i32 %x, 1
  br i1 %cmp2, label %stale.handler1, label %stale.default

stale.handler0:
  %a = add i32 %x, 10
  br label %stale.default

stale.handler1:
  %b = add i32 %x, 20
  br label %stale.default

stale.default:
  %r = phi i32 [ %x, %obf.flat.dispatch.split ], [ %x, %obf.flat.dispatch.left ], [ %a, %stale.handler0 ], [ %b, %stale.handler1 ]
  ret i32 %r
}

; CHECK-LABEL: define i32 @legacy_no_metadata(i32 %x)
; CHECK: %obf.shard.addr.base = ptrtoint ptr @__obf_shard_{{[0-9a-f]+}} to i64
; CHECK: %obf.shard.indirect = inttoptr i64 %obf.shard.addr to ptr
; CHECK: call {{.*}} %obf.shard.indirect
; CHECK-LABEL: define i32 @stale_block_metadata(i32 %x)
; CHECK: %obf.shard.addr.base = ptrtoint ptr @__obf_shard_{{[0-9a-f]+}} to i64
; CHECK: %obf.shard.indirect = inttoptr i64 %obf.shard.addr to ptr
; CHECK: call {{.*}} %obf.shard.indirect
; CHECK-DAG: define internal {{.*}} @__obf_shard_{{[0-9a-f]+}}
; CHECK-DAG: define internal {{.*}} @__obf_shard_{{[0-9a-f]+}}

!0 = !{!"obf.flattened", !1}
!1 = !{!"obf.flattened.version", i32 1}
