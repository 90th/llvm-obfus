; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @main() {
entry:
  %result = call i32 @first_char(ptr @.secret)
  ret i32 %result
}

; CHECK: @.secret = private unnamed_addr global [7 x i8]
; CHECK-NOT: @llvm.global_ctors = appending global
; CHECK-NOT: @__obf_get_cfg_state
; CHECK-NOT: @__obf_get_expected_cfg_state
; CHECK: %0 = call ptr @__obf_family_{{.*}}(ptr {{.*}}, i32 0, i32 0)
; CHECK: define internal ptr @__obf_family_{{.*}}(ptr %desc, i32 %cfg_state, i32 %expected_state)
