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

define i32 @tail_pair_value(i32 %x) {
entry:
  %value = musttail call i32 @keep_me(i32 %x)
  ret i32 %value
}

define void @tail_void_target() {
entry:
  ret void
}

define void @tail_pair_void() {
entry:
  musttail call void @tail_void_target()
  ret void
}

define i32 @tail_pair_prefix(i32 %x) {
entry:
  %next = add i32 %x, 1
  %value = musttail call i32 @keep_me(i32 %next)
  ret i32 %value
}

define i32 @main() {
entry:
  %s = call i32 @split_me(i32 10)
  %s.ok = icmp eq i32 %s, 16
  %k = call i32 @keep_me(i32 16)
  %k.ok = icmp eq i32 %k, 16
  %paired = call i32 @tail_pair_value(i32 16)
  %paired.ok = icmp eq i32 %paired, 16
  call void @tail_pair_void()
  %prefix = call i32 @tail_pair_prefix(i32 15)
  %prefix.ok = icmp eq i32 %prefix, 16
  %ok = and i1 %s.ok, %k.ok
  %pair.ok = and i1 %paired.ok, %prefix.ok
  %all.ok = and i1 %ok, %pair.ok
  %ret = select i1 %all.ok, i32 0, i32 1
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

; A musttail call and its return form one indivisible suffix. The minimal
; pairs have no legal split. A prefix can still split before the call.
; CHECK-LABEL: define i32 @tail_pair_value
; CHECK: %value = musttail call i32 @keep_me(i32 %x)
; CHECK-NEXT: ret i32 %value
; CHECK-LABEL: define void @tail_pair_void
; CHECK: musttail call void @tail_void_target()
; CHECK-NEXT: ret void
; CHECK-LABEL: define i32 @tail_pair_prefix
; CHECK: br label %entry.obf.bridge
; CHECK: entry.obf.split:
; CHECK: %value = musttail call i32 @keep_me(
; CHECK-NEXT: ret i32 %value
