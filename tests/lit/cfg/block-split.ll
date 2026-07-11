; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/block-split.yaml --obf-seed=1 -passes=obf-block-split -S %s -o %t.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/block-split.yaml --obf-seed=1 -passes=obf-block-split -S %s -o %t.second
; RUN: cmp %t.first %t.second
; RUN: %FileCheck %s < %t.first
; RUN: %opt -passes=verify -disable-output %t.first
; RUN: %lli %t.first

define i32 @split_me(i32 %x) {
entry:
  %a = add i32 %x, 1
  %b = add i32 %a, 2
  %c = add i32 %b, 3
  ret i32 %c
}

define i32 @keep_me(i32 %x) {
entry:
  ret i32 %x
}

define i32 @main() {
entry:
  %s = call i32 @split_me(i32 10)
  %s.ok = icmp eq i32 %s, 16
  %k = call i32 @keep_me(i32 16)
  %k.ok = icmp eq i32 %k, 16
  %ok = and i1 %s.ok, %k.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; The split-off tail is separated from the retained prefix by an opaque-zero
; identity "bridge" block, so the split resists trivial re-merging.
; CHECK-LABEL: define i32 @split_me
; CHECK: entry:
; CHECK: %a = add i32 %x, 1
; CHECK: br label %entry.obf.bridge
; CHECK: entry.obf.bridge:
; CHECK: %obf.split.zero =
; CHECK: %obf.split.id =
; CHECK: br label %entry.obf.split
; CHECK: entry.obf.split:
; The exact split point is seed/module-path dependent; assert only that the
; tail consumes the bridged identity value.
; CHECK: %obf.split.id

; CHECK-LABEL: define i32 @keep_me
; CHECK: entry:
; CHECK-NEXT: ret i32 %x
