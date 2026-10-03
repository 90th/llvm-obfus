; RUN: env OBF_COVERAGE_REPORT=%t.coverage.json %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/policy-report.yaml -passes=obf-feature-report -disable-output %s > %t.predictions.json
; RUN: %python %S/../Inputs/report_contract.py selection %t.predictions.json --coverage %t.coverage.json

@.obf.strong = private unnamed_addr constant [11 x i8] c"obf:strong\00", section "llvm.metadata"
@.policy.file = private unnamed_addr constant [17 x i8] c"policy-report.ll\00", section "llvm.metadata"
@llvm.global.annotations = appending global [2 x { ptr, ptr, ptr, i32, ptr }] [
  { ptr, ptr, ptr, i32, ptr } { ptr @override_me, ptr @.obf.strong, ptr @.policy.file, i32 1, ptr null },
  { ptr, ptr, ptr, i32, ptr } { ptr @annotated, ptr @.obf.strong, ptr @.policy.file, i32 2, ptr null }
], section "llvm.metadata"

@.str = private unnamed_addr constant [6 x i8] c"hello\00"

declare i32 @puts(ptr)

define i32 @override_me(i32 %x) {
entry:
  %add = add i32 %x, 1
  ret i32 %add
}

define i32 @annotated(i32 %x) {
entry:
  %add = add i32 %x, 2
  ret i32 %add
}

define i32 @strong_vm_fn(i32 %x) {
entry:
  %add = add i32 %x, 3
  ret i32 %add
}

define i32 @stringy() {
entry:
  %call = call i32 @puts(ptr @.str)
  ret i32 %call
}

define i32 @default_fn(i32 %x) {
entry:
  ret i32 %x
}

