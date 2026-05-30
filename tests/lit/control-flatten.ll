; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/control-flatten.yaml -passes=obf-control-flatten -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/control-flatten.yaml -passes=obf-control-flatten -S %s -o %t
; RUN: %lli %t

define i1 @verify_like(ptr %p, i64 %n) {
entry:
  %len_ok = icmp eq i64 %n, 4
  br i1 %len_ok, label %loop.prep, label %fail

loop.prep:
  br label %loop

loop:
  %i = phi i64 [ 0, %loop.prep ], [ %next, %body ]
  %acc = phi i32 [ 0, %loop.prep ], [ %sum, %body ]
  %ptr = getelementptr inbounds i8, ptr %p, i64 %i
  %ch = load i8, ptr %ptr
  %wide = zext i8 %ch to i32
  %sum = add i32 %acc, %wide
  %next = add i64 %i, 1
  %done = icmp eq i64 %next, %n
  br i1 %done, label %check, label %body

body:
  br label %loop

check:
  %ok = icmp eq i32 %sum, 266
  br i1 %ok, label %pass, label %fail

pass:
  ret i1 true

fail:
  ret i1 false
}

@.ok = private unnamed_addr constant [5 x i8] c"ABCD\00"

define i32 @main() {
entry:
  %result = call i1 @verify_like(ptr @.ok, i64 4)
  %ret = select i1 %result, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i1 @verify_like
; CHECK: obf.flat.setup:
; CHECK-NOT: %obf.state = alloca i32
; CHECK: obf.flat.dispatch:
; CHECK: %obf.state = phi i32
; CHECK-SAME: %obf.flat.state.next
; CHECK: %obf.flat.val = phi i64
; CHECK-NOT: switch i32 %obf.state
; CHECK-DAG: %obf.flat.dispatch.eq = icmp eq i32 %obf.state,
; CHECK-DAG: br i1 %obf.flat.dispatch.eq, label %{{[^,]+}}, label %obf.flat.dispatch.split0
; CHECK-DAG: %obf.flat.dispatch.ult = icmp ult i32 %obf.state,
; CHECK-DAG: br i1 %obf.flat.dispatch.ult, label %obf.flat.dispatch.left0, label %obf.flat.dispatch.right0
; CHECK-DAG: %ptr = getelementptr inbounds i8, ptr %p, i64 %obf.flat.val
; CHECK-DAG: %obf.opaque.pair = load
; CHECK-DAG: %obf.opaque.entropy.mix = xor i64
; CHECK-DAG: %obf.opaque.seed =
; CHECK-DAG: %obf.opaque.seed.freeze = freeze i64
; CHECK-DAG: %obf.opaque.expr.a =
; CHECK-DAG: %obf.opaque.expr.b =
; CHECK-DAG: %obf.flat.decoy.true = icmp eq i64 %obf.opaque.expr.a, %obf.opaque.expr.b
; CHECK-DAG: obf.flat.decoy{{[0-9]*}}:
; CHECK-DAG: obf.flat.decoy.loop{{[0-9]*}}:
; CHECK-DAG: obf.flat.decoy.trap{{[0-9]*}}:
; CHECK-DAG: call void @llvm.trap()
