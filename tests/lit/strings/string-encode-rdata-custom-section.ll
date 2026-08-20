; REQUIRES: system-windows
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-rdata-custom-section.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %raw_clang -target x86_64-pc-windows-msvc -c %t.ll -o %t.obj
; RUN: %python %S/../Inputs/check_coff_writable_section.py %t.obj .rdata_custom

 target triple = "x86_64-pc-windows-msvc"

@.rdata_custom = internal unnamed_addr constant [6 x i8] c"hello\00", section ".rdata_custom", align 1

define i32 @check_rdata_custom() {
entry:
  %c = load i8, ptr @.rdata_custom, align 1
  %ok = icmp eq i8 %c, 104
  %result = select i1 %ok, i32 0, i32 1
  ret i32 %result
}

define i32 @main() {
entry:
  ret i32 0
}

; CHECK-NOT: c"hello\00"
; CHECK: @.rdata_custom = internal unnamed_addr global [6 x i8] c"{{[^"]*}}", align 1
; CHECK-NOT: section ".rdata_custom"
