; RUN: %opt -load-pass-plugin %obf_plugin -passes=obf-entropy-init -S %s -o - | %FileCheck %s

@rt_core_ea = global i64 0, align 8

define i32 @main() {
entry:
  %value = load i64, ptr @rt_core_ea
  %ok = icmp ne i64 %value, 0
  %result = select i1 %ok, i32 0, i32 1
  ret i32 %result
}

; CHECK: @rt_core_ea = global i64 {{-?[1-9][0-9]*}}, align 8
