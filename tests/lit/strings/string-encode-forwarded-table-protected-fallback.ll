; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-forwarded-table-protected.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-forwarded-table-protected.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [6 x i8] c"hello\00", align 1
@.forward_table = private unnamed_addr constant [1 x ptr] [ptr @.secret], align 8

define i32 @check_protected() {
entry:
  %slot = getelementptr inbounds [1 x ptr], ptr @.forward_table, i64 0, i64 0
  %p = load ptr, ptr %slot, align 8
  %c = load i8, ptr %p, align 1
  %is_h = icmp eq i8 %c, 104
  %res = select i1 %is_h, i32 0, i32 1
  ret i32 %res
}

define i32 @main() {
entry:
  %result = call i32 @check_protected()
  ret i32 %result
}

; CHECK-NOT: ephemeral_micro_slot
; CHECK: @llvm.global_ctors = appending global
