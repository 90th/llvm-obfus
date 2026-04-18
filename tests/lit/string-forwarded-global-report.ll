; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-forwarded-global-report.yaml -passes=obf-feature-report -disable-output %s | jq -r '.schema, (.transforms[] | [.target_name, .pass, .status, (.count|tostring), .detail, (.strategy.kind // ""), (.strategy.helper_shape // ""), (.strategy.fallback_reason // "")] | join("|"))' | %FileCheck %s

@.msg = private unnamed_addr constant [15 x i8] c"ACCESS GRANTED\00"
@.table = private unnamed_addr constant [1 x ptr] [ptr @.msg]

declare i32 @puts(ptr)

define i32 @main() {
entry:
  %slot = getelementptr inbounds [1 x ptr], ptr @.table, i64 0, i64 0
  %msg = load ptr, ptr %slot, align 8
  %call = call i32 @puts(ptr %msg)
  ret i32 %call
}

; CHECK: obf.feature_report.v3
; CHECK-DAG: .msg|string_encoding|applied|1|global_ctor: ctor fallback due to forwarded pointer table use|helper_global_ctor|ctor_unrolled_v0|forwarded_pointer_table_use
