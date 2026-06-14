; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-strong-vm-literal-pointer.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-strong-vm-literal-pointer.yaml -passes=obf-feature-report -disable-output %s | jq -r '(.transforms[] | select(.pass == "string_encoding") | [.target_name, .status, (.count|tostring), .detail, (.strategy.kind // ""), (.strategy.helper_shape // ""), (.strategy.fallback_reason // ""), ((.strategy.use_kinds // []) | join(","))] | join("|"))' | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-strong-vm-literal-pointer.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t

@.expected = private unnamed_addr constant [8 x i8] c"delta-7\00"
@.expected.ptr = private unnamed_addr constant ptr @.expected

define i32 @literal_pointer(ptr %token, i64 %len) {
entry:
  %has_len = icmp eq i64 %len, 7
  br i1 %has_len, label %loop, label %fail

loop:
  %i = phi i64 [ 0, %entry ], [ %next, %body ]
  %acc = phi i32 [ 0, %entry ], [ %acc.next, %body ]
  %in_bounds = icmp ult i64 %i, 7
  br i1 %in_bounds, label %body, label %exit

body:
  %expected = load ptr, ptr @.expected.ptr, align 8
  %token.ptr = getelementptr inbounds i8, ptr %token, i64 %i
  %token.byte = load i8, ptr %token.ptr, align 1
  %expected.ptr = getelementptr inbounds i8, ptr %expected, i64 %i
  %expected.byte = load i8, ptr %expected.ptr, align 1
  %diff = xor i8 %token.byte, %expected.byte
  %diff.ext = zext i8 %diff to i32
  %acc.next = or i32 %acc, %diff.ext
  %next = add nuw nsw i64 %i, 1
  br label %loop

exit:
  %ok = icmp eq i32 %acc, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret

fail:
  ret i32 1
}

define i32 @main() {
entry:
  %buf = alloca [8 x i8], align 1
  %p0 = getelementptr inbounds [8 x i8], ptr %buf, i64 0, i64 0
  store i8 100, ptr %p0, align 1
  %p1 = getelementptr inbounds [8 x i8], ptr %buf, i64 0, i64 1
  store i8 101, ptr %p1, align 1
  %p2 = getelementptr inbounds [8 x i8], ptr %buf, i64 0, i64 2
  store i8 108, ptr %p2, align 1
  %p3 = getelementptr inbounds [8 x i8], ptr %buf, i64 0, i64 3
  store i8 116, ptr %p3, align 1
  %p4 = getelementptr inbounds [8 x i8], ptr %buf, i64 0, i64 4
  store i8 97, ptr %p4, align 1
  %p5 = getelementptr inbounds [8 x i8], ptr %buf, i64 0, i64 5
  store i8 45, ptr %p5, align 1
  %p6 = getelementptr inbounds [8 x i8], ptr %buf, i64 0, i64 6
  store i8 55, ptr %p6, align 1
  %p7 = getelementptr inbounds [8 x i8], ptr %buf, i64 0, i64 7
  store i8 0, ptr %p7, align 1
  %token = getelementptr inbounds [8 x i8], ptr %buf, i64 0, i64 0
  %result = call i32 @literal_pointer(ptr %token, i64 7)
  ret i32 %result
}

; IR-NOT: c"delta-7
; IR-NOT: c"\64\65\6C\74\61\2D\37
; IR-NOT: @llvm.global_ctors = appending global
; IR-NOT: @__obf_family_
; IR-NOT: @__obf_lazy_
; IR-NOT: @__obf_desc
; IR-NOT: lazy_decode
; IR: @.expected = private unnamed_addr global [8 x i8] c"
; IR: alloca [8 x i8]
; IR-NOT: load ptr, ptr @.expected.ptr

; REPORT-NOT: lazy_decode
; REPORT-NOT: global_ctor
; REPORT-DAG: .expected|applied|1|inline_stack_decode: 1 inline stack decode use(s)|inline_stack_decode|none||forwarded_pointer_load
