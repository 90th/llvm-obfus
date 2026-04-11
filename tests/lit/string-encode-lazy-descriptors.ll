; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-encode-lazy-descriptors.yaml -passes=obf-string-encode -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-encode-lazy-descriptors.yaml -passes=obf-string-encode -S %s -o %t
; RUN: %lli %t

@.alpha = private unnamed_addr constant [6 x i8] c"alpha\00"
@.bravo = private unnamed_addr constant [6 x i8] c"bravo\00"
@.charlie = private unnamed_addr constant [8 x i8] c"charlie\00"
@.delta = private unnamed_addr constant [6 x i8] c"delta\00"

define i32 @first_is(ptr %p, i8 %expected) {
entry:
  %first = load i8, ptr %p
  %match = icmp eq i8 %first, %expected
  %result = select i1 %match, i32 0, i32 1
  ret i32 %result
}

define i32 @main() {
entry:
  %a = call i32 @first_is(ptr @.alpha, i8 97)
  %b = call i32 @first_is(ptr @.bravo, i8 98)
  %c = call i32 @first_is(ptr @.charlie, i8 99)
  %d = call i32 @first_is(ptr @.delta, i8 100)
  %ab = add i32 %a, %b
  %cd = add i32 %c, %d
  %sum = add i32 %ab, %cd
  ret i32 %sum
}

; IR: @__obf_desc_table_0 = internal constant [4 x { ptr, i64, ptr, i64 }]
; IR-LABEL: define i32 @main() {
; IR: call ptr @__obf_family_flag_v0(ptr getelementptr ([4 x { ptr, i64, ptr, i64 }], ptr @__obf_desc_table_0, i64 0, i64 1))
; IR: call ptr @__obf_family_flag_v0(ptr @__obf_desc_table_0)
; IR: call ptr @__obf_family_flag_v0(ptr getelementptr ([4 x { ptr, i64, ptr, i64 }], ptr @__obf_desc_table_0, i64 0, i64 3))
; IR: call ptr @__obf_family_flag_v0(ptr getelementptr ([4 x { ptr, i64, ptr, i64 }], ptr @__obf_desc_table_0, i64 0, i64 2))
; IR-LABEL: define internal ptr @__obf_family_flag_v0(ptr %desc) {
; IR: getelementptr inbounds { ptr, i64, ptr, i64 }, ptr %desc, i64 0, i32 0
; IR: br i1
; IR: decode:
; IR: getelementptr inbounds { ptr, i64, ptr, i64 }, ptr %desc, i64 0, i32 2
