; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t

$"??_C@_0BC@SensitiveData12345?$AA@" = comdat any
@"??_C@_0BC@SensitiveData12345?$AA@" = linkonce_odr dso_local unnamed_addr constant [19 x i8] c"SensitiveData12345\00", comdat, align 1

define ptr @get_secret() {
entry:
  ret ptr @"??_C@_0BC@SensitiveData12345?$AA@"
}

define i32 @main() {
entry:
  %str = call ptr @get_secret()
  %first = load i8, ptr %str
  %is_s = icmp eq i8 %first, 83
  %res = select i1 %is_s, i32 0, i32 1
  ret i32 %res
}

; CHECK: @"??_C@_0BC@SensitiveData12345?$AA@" = internal unnamed_addr global [19 x i8]
; CHECK-NOT: comdat
; CHECK-NOT: c"SensitiveData12345\00"
