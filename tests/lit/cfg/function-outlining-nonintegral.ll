; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/function-outlining.yaml -passes=obf-function-outline -disable-output %s 2>&1 | %FileCheck %s

target datalayout = "e-p:64:64-p200:128:128:128:64-ni:200"

define i32 @legacy_no_metadata(i32 %x) addrspace(200) {
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

; CHECK: LLVM ERROR: function outlining cannot encode shard pointers for non-integral address space 200 in legacy_no_metadata
