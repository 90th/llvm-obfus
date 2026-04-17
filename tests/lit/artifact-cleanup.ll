; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/artifact-cleanup.yaml -passes=obf-artifact-cleanup -S %s -o - | %FileCheck %s

@.data = private global i32 7

define internal i32 @__obf_helper(i32 %arg) !dbg !6 {
entry:
  %sum = add i32 %arg, 1, !dbg !10
  ret i32 %sum, !dbg !11
}

define i32 @main() {
entry:
  %call = call i32 @__obf_helper(i32 4)
  ret i32 %call
}

; CHECK-DAG: @[[DATA:_[0-9a-f]+]] = private global i32 7
; CHECK-NOT: @.data
; CHECK-NOT: @__obf_helper
; CHECK-NOT: !dbg
; CHECK-NOT: entry:
; CHECK-NOT: %sum =
; CHECK: define internal i32 @[[HELPER:_[0-9a-f]+]](i32
; CHECK: add i32 %0, 1
; CHECK-LABEL: define i32 @main()
; CHECK: call i32 @[[HELPER]](i32 4)

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3, !4}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "test", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !2)
!1 = !DIFile(filename: "artifact.c", directory: "/tmp")
!2 = !{}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{i32 7, !"Dwarf Version", i32 4}
!5 = !{!7, !7}
!6 = distinct !DISubprogram(name: "__obf_helper", scope: !1, file: !1, line: 1, type: !8, scopeLine: 1, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!7 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!8 = !DISubroutineType(types: !5)
!10 = !DILocation(line: 1, column: 1, scope: !6)
!11 = !DILocation(line: 2, column: 1, scope: !6)
