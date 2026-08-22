; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare.yaml -passes=obf-feature-report -disable-output %s | jq -r '(.transforms[] | select(.pass == "string_encoding") | [.target_name, .status, (.count|tostring), .detail, (.strategy.kind // "")] | join("|"))' | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t

target datalayout = "e-p:64:64"

@.mem64 = private unnamed_addr constant [65 x i8] c"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\00"
@other_mem64 = internal global [64 x i8] c"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
@.hello = private unnamed_addr constant [6 x i8] c"hello\00"
@other_hello = internal global [6 x i8] c"hello\00"
@.bee = private unnamed_addr constant [2 x i8] c"b\00"
@other_a = internal global [2 x i8] c"a\00"
@other_c = internal global [2 x i8] c"c\00"
@.ab = private unnamed_addr constant [3 x i8] c"ab\00"
@other_ab_tail = internal global [4 x i8] c"ab\00X"

; These are deliberately oversize for the 64-byte micro-slot bound.
@.mem65 = private unnamed_addr constant [66 x i8] c"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\00"
@other_mem65 = internal global [65 x i8] c"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
@.strcmp65 = private unnamed_addr constant [66 x i8] c"LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL\00"
@other_strcmp65 = internal global [66 x i8] c"LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL\00"

; Dynamic-length and two-encryptable-global compares must use a normal fallback.
@.dynamic = private unnamed_addr constant [8 x i8] c"dynamic\00"
@other_dynamic = internal global [8 x i8] c"dynamic\00"
@.pair_a = private unnamed_addr constant [7 x i8] c"pair-a\00"
@.pair_b = private unnamed_addr constant [7 x i8] c"pair-b\00"

declare i32 @memcmp(ptr, ptr, i64)
declare i32 @strcmp(ptr, ptr)
declare i32 @strncmp(ptr, ptr, i64)

define i32 @check_memcmp_lhs() {
entry:
  %cmp = call i32 @memcmp(ptr @.mem64, ptr @other_mem64, i64 64)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_memcmp_rhs() {
entry:
  %cmp = call i32 @memcmp(ptr @other_mem64, ptr @.mem64, i64 64)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_memcmp_zero() {
entry:
  %cmp = call i32 @memcmp(ptr @.hello, ptr @other_hello, i64 0)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_strcmp_lhs() {
entry:
  %cmp = call i32 @strcmp(ptr @.hello, ptr @other_hello)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_strcmp_rhs() {
entry:
  %cmp = call i32 @strcmp(ptr @other_hello, ptr @.hello)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_strcmp_positive() {
entry:
  %cmp = call i32 @strcmp(ptr @.bee, ptr @other_a)
  %ok = icmp sgt i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_strcmp_negative() {
entry:
  %cmp = call i32 @strcmp(ptr @.bee, ptr @other_c)
  %ok = icmp slt i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_strncmp_nul() {
entry:
  ; n exceeds the known object length, but the known NUL ends comparison at byte 2.
  %cmp = call i32 @strncmp(ptr @.ab, ptr @other_ab_tail, i64 64)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_memcmp_oversize() {
entry:
  %cmp = call i32 @memcmp(ptr @.mem65, ptr @other_mem65, i64 65)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_strcmp_oversize() {
entry:
  %cmp = call i32 @strcmp(ptr @.strcmp65, ptr @other_strcmp65)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_dynamic(i64 %n) {
entry:
  %cmp = call i32 @memcmp(ptr @.dynamic, ptr @other_dynamic, i64 %n)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @check_two_encrypted() {
entry:
  %cmp = call i32 @memcmp(ptr @.pair_a, ptr @.pair_b, i64 6)
  %ok = icmp ne i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @main() {
entry:
  %r0 = call i32 @check_memcmp_lhs()
  %r1 = call i32 @check_memcmp_rhs()
  %r2 = call i32 @check_memcmp_zero()
  %r3 = call i32 @check_strcmp_lhs()
  %r4 = call i32 @check_strcmp_rhs()
  %r5 = call i32 @check_strcmp_positive()
  %r6 = call i32 @check_strcmp_negative()
  %r7 = call i32 @check_strncmp_nul()
  %r8 = call i32 @check_memcmp_oversize()
  %r9 = call i32 @check_strcmp_oversize()
  %r10 = call i32 @check_dynamic(i64 7)
  %r11 = call i32 @check_two_encrypted()
  %a0 = or i32 %r0, %r1
  %a1 = or i32 %r2, %r3
  %a2 = or i32 %r4, %r5
  %a3 = or i32 %r6, %r7
  %a4 = or i32 %r8, %r9
  %a5 = or i32 %r10, %r11
  %b0 = or i32 %a0, %a1
  %b1 = or i32 %a2, %a3
  %b2 = or i32 %a4, %a5
  %c0 = or i32 %b0, %b1
  %ret = or i32 %c0, %b2
  ret i32 %ret
}

; Boundary and supported compare cases select the micro-slot strategy.
; REPORT-DAG: .mem64|applied|1|ephemeral_slot: 2 ephemeral micro-slot use(s)|ephemeral_micro_slot
; REPORT-DAG: .hello|applied|1|ephemeral_slot: 3 ephemeral micro-slot use(s)|ephemeral_micro_slot
; REPORT-DAG: .bee|applied|1|ephemeral_slot: 2 ephemeral micro-slot use(s)|ephemeral_micro_slot
; REPORT-DAG: .ab|applied|1|ephemeral_slot: 1 ephemeral micro-slot use(s)|ephemeral_micro_slot
; REPORT-DAG: .mem65|applied|1|lazy_decode: 1 lazy use(s)|helper_lazy_decode
; REPORT-DAG: .strcmp65|applied|1|lazy_decode: 1 lazy use(s)|helper_lazy_decode
; REPORT-DAG: .dynamic|applied|1|inline_stack_decode: 1 inline stack decode use(s)|inline_stack_decode
; REPORT-DAG: .pair_a|applied|1|inline_stack_decode: 1 inline stack decode use(s)|inline_stack_decode
; REPORT-DAG: .pair_b|applied|1|inline_stack_decode: 1 inline stack decode use(s)|inline_stack_decode

; CHECK-LABEL: define i32 @check_memcmp_lhs()
; CHECK-NOT: alloca
; CHECK-NOT: call i32 @memcmp
; CHECK: obf.str.cmp.0:
; CHECK: br i1
; CHECK-LABEL: define i32 @check_memcmp_rhs()
; CHECK-NOT: alloca
; CHECK-NOT: call i32 @memcmp
; CHECK: obf.str.cmp.0:
; CHECK-LABEL: define i32 @check_memcmp_zero()
; CHECK-NOT: call i32 @memcmp
; CHECK-LABEL: define i32 @check_strcmp_lhs()
; CHECK-NOT: alloca
; CHECK-NOT: call i32 @strcmp
; CHECK: obf.str.cmp.0:
; CHECK-LABEL: define i32 @check_strcmp_rhs()
; CHECK-NOT: call i32 @strcmp
; CHECK: obf.str.cmp.0:
; CHECK-LABEL: define i32 @check_strcmp_positive()
; CHECK-NOT: call i32 @strcmp
; CHECK-LABEL: define i32 @check_strcmp_negative()
; CHECK-NOT: call i32 @strcmp
; CHECK-LABEL: define i32 @check_strncmp_nul()
; CHECK-NOT: call i32 @strncmp
; CHECK: obf.str.cmp.0:
; CHECK-LABEL: define i32 @check_memcmp_oversize()
; CHECK: call i32 @memcmp
; CHECK-LABEL: define i32 @check_strcmp_oversize()
; CHECK: call i32 @strcmp
; CHECK-LABEL: define i32 @check_dynamic(i64 %n)
; CHECK: call i32 @memcmp
; CHECK-LABEL: define i32 @check_two_encrypted()
; CHECK: call i32 @memcmp
