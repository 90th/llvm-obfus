; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-custom-section-preserve.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-custom-section-preserve.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t

@.custom = private unnamed_addr constant [6 x i8] c"hello\00", section ".custom", align 1

define i32 @check_custom() {
entry:
  %c = load i8, ptr @.custom, align 1
  %is_h = icmp eq i8 %c, 104
  %res = select i1 %is_h, i32 0, i32 1
  ret i32 %res
}

define i32 @main() {
entry:
  %result = call i32 @check_custom()
  ret i32 %result
}

; CHECK-NOT: c"hello\00"
; CHECK: @.custom = private unnamed_addr global [6 x i8] c"{{.*}}", section ".custom", align 1
; CHECK: @__obf_desc_table_
; CHECK-SAME: ptr @.custom
