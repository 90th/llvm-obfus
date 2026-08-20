; REQUIRES: system-windows
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-rdata-section-preserve.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %raw_clang -target x86_64-pc-windows-msvc -c %t.ll -o %t.obj
; RUN: %python %S/../Inputs/check_coff_writable_section.py %t.obj .rdata_str
; RUN: %lli %t.ll

target triple = "x86_64-pc-windows-msvc"

@.rdata_str = internal unnamed_addr constant [6 x i8] c"hello\00", section ".rdata", align 1

define i32 @check_rdata() {
entry:
  %c = load i8, ptr @.rdata_str, align 1
  %is_h = icmp eq i8 %c, 104
  %res = select i1 %is_h, i32 0, i32 1
  ret i32 %res
}

define i32 @main() {
entry:
  %result = call i32 @check_rdata()
  ret i32 %result
}

; CHECK-NOT: c"hello\00"
; CHECK: @.rdata_str = internal unnamed_addr global [6 x i8] c"{{.*}}"
; CHECK-NOT: section ".rdata"
