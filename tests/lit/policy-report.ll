; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/policy-report.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s

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

; CHECK-DAG: "detail":"override:override_me","level":"none","seed":"0x{{[0-9a-f]+}}","source":"explicit_override"
; CHECK-DAG: "detail":"annotation:obf:strong","level":"strong","seed":"0x{{[0-9a-f]+}}","source":"source_annotation"
; CHECK-DAG: "detail":"config match:strong_vm_fn","level":"strong_vm","seed":"0x{{[0-9a-f]+}}","source":"config_rule"
; CHECK-DAG: "allow_vm":true
; CHECK-DAG: "detail":"automatic:string-sensitive","level":"light","seed":"0x{{[0-9a-f]+}}","source":"automatic_analysis"
; CHECK-DAG: "name":"default_fn","policy":{{.*}}"detail":"default","level":"none","seed":"0x{{[0-9a-f]+}}","source":"default"
