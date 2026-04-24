; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-strong-vm-top-level-parent.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s

define internal i32 @verify_step(ptr %token, i64 %len) {
entry:
  %ok = icmp eq i64 %len, 7
  %ret = select i1 %ok, i32 1, i32 0
  ret i32 %ret
}

define internal i32 @score_step(ptr %token, i64 %len) {
entry:
  %trunc = trunc i64 %len to i32
  %score = add i32 %trunc, 9
  ret i32 %score
}

define i32 @main(i32 %argc, ptr %argv) {
entry:
  %gt = icmp sgt i32 %argc, 1
  br i1 %gt, label %have_arg, label %no_arg

have_arg:
  %argv.slot = getelementptr inbounds ptr, ptr %argv, i64 1
  %arg = load ptr, ptr %argv.slot, align 8
  br label %join

no_arg:
  br label %join

join:
  %token = phi ptr [ %arg, %have_arg ], [ null, %no_arg ]
  %isnull = icmp eq ptr %token, null
  %len = select i1 %isnull, i64 0, i64 7
  %verified = call i32 @verify_step(ptr %token, i64 %len)
  %score = call i32 @score_step(ptr %token, i64 %len)
  %ret = add i32 %verified, %score
  ret i32 %ret
}

; CHECK-LABEL: define i32 @main(i32
; CHECK: load i64, ptr @{{_[0-9a-f]+}}
; CHECK: load i64, ptr @{{_[0-9a-f]+}}
; CHECK: inttoptr i64
; CHECK: call i32 %{{[^ ]+}}(i32 %{{[^,]+}}, ptr %{{[^,]+}}, i64 %{{[^)]+}})
; CHECK: load i64, ptr @{{_[0-9a-f]+}}
; CHECK: define internal i32 @[[MAINVM:_[0-9a-f]+]](i32
; CHECK: indirectbr ptr
