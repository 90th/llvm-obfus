; REQUIRES: system-windows
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-coff-shared-custom-order.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %raw_clang -target x86_64-pc-windows-msvc -c %t.ll -o %t.obj
; RUN: %python %S/../Inputs/check_coff_writable_section.py %t.obj .protected_custom

 target triple = "x86_64-pc-windows-msvc"

@.constant_custom = internal unnamed_addr constant [4 x i8] c"abc\00", section ".custom", align 1
@.protected_custom = internal unnamed_addr constant [4 x i8] c"xyz\00", section ".custom", align 1

define i32 @check_protected() {
entry:
  %c = load i8, ptr @.protected_custom, align 1
  %ok = icmp eq i8 %c, 120
  %result = select i1 %ok, i32 0, i32 1
  ret i32 %result
}

define i32 @main() {
entry:
  ret i32 0
}

; CHECK: @.constant_custom = internal unnamed_addr constant [4 x i8] c"abc\00", section ".custom", align 1
; CHECK-NOT: c"xyz\00"
; CHECK: @.protected_custom = internal unnamed_addr global [4 x i8] c"{{[^"]*}}", align 1
; CHECK-NOT: @.protected_custom = internal unnamed_addr global [4 x i8] c"{{[^"]*}}", section ".custom"
