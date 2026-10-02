; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-vm-owner-provenance.yaml -passes=obf-safe-pipeline -S %s -o %t
; RUN: %FileCheck %s --input-file=%t --implicit-check-not='c"cobalt-42' --implicit-check-not='c"amber-key19'
; RUN: %lli %t
;
; Real VM pointer cells feed ptrtoint/MBA/state forwarding in nested readers.
; Both private and MSVC linkonce_odr sources must be encoded, while an unrelated
; generated-looking function and pointer cell must not acquire their ownership.

target datalayout = "e-p:64:64"

@.private = private unnamed_addr constant [10 x i8] c"cobalt-42\00"
$"??_C@_0M@OwnedSecret?$AA@" = comdat any
@"??_C@_0M@OwnedSecret?$AA@" = linkonce_odr dso_local unnamed_addr constant [12 x i8] c"amber-key19\00", comdat, align 1
@.unowned = private unnamed_addr constant [13 x i8] c"unowned-note\00"
@__obf_vm_ptrconst_lookalike = private constant ptr @.unowned

define i32 @verify_owned_strings(ptr %token, i64 %len, i1 %private) {
entry:
  %expected = select i1 %private, ptr @.private, ptr @"??_C@_0M@OwnedSecret?$AA@"
  %expected.len = select i1 %private, i64 9, i64 11
  %wrong.len = icmp ne i64 %len, %expected.len
  %wrong.len.ext = zext i1 %wrong.len to i32
  %end = getelementptr i8, ptr %token, i64 %len
  %terminator = load i8, ptr %end, align 1
  %not.terminated = icmp ne i8 %terminator, 0
  %not.terminated.ext = zext i1 %not.terminated to i32
  %initial = or i32 %wrong.len.ext, %not.terminated.ext
  %short = icmp ult i64 %len, %expected.len
  %limit = select i1 %short, i64 %len, i64 %expected.len
  br label %loop

loop:
  %i = phi i64 [ 0, %entry ], [ %next, %body ]
  %mismatch = phi i32 [ %initial, %entry ], [ %mismatch.next, %body ]
  %in.bounds = icmp ult i64 %i, %limit
  br i1 %in.bounds, label %body, label %exit

body:
  %input.ptr = getelementptr i8, ptr %token, i64 %i
  %input = load i8, ptr %input.ptr, align 1
  %expected.ptr = getelementptr i8, ptr %expected, i64 %i
  %byte = load i8, ptr %expected.ptr, align 1
  %difference = xor i8 %input, %byte
  %difference.ext = zext i8 %difference to i32
  %mismatch.next = or i32 %mismatch, %difference.ext
  %next = add i64 %i, 1
  br label %loop

exit:
  ret i32 %mismatch
}

define internal i8 @__obf_vm_unowned_reader() {
entry:
  %pointer = load ptr, ptr @__obf_vm_ptrconst_lookalike
  %integer = ptrtoint ptr %pointer to i64
  %forwarded = inttoptr i64 %integer to ptr
  %byte = load i8, ptr %forwarded
  ret i8 %byte
}

define i32 @main() {
entry:
  %input = alloca [13 x i8], align 1
  store i8 99, ptr %input
  %p1 = getelementptr i8, ptr %input, i64 1
  store i8 111, ptr %p1
  %p2 = getelementptr i8, ptr %input, i64 2
  store i8 98, ptr %p2
  %p3 = getelementptr i8, ptr %input, i64 3
  store i8 97, ptr %p3
  %p4 = getelementptr i8, ptr %input, i64 4
  store i8 108, ptr %p4
  %p5 = getelementptr i8, ptr %input, i64 5
  store i8 116, ptr %p5
  %p6 = getelementptr i8, ptr %input, i64 6
  store i8 45, ptr %p6
  %p7 = getelementptr i8, ptr %input, i64 7
  store i8 52, ptr %p7
  %p8 = getelementptr i8, ptr %input, i64 8
  store i8 50, ptr %p8
  %p9 = getelementptr i8, ptr %input, i64 9
  store i8 0, ptr %p9
  %accepted.private = call i32 @verify_owned_strings(ptr %input, i64 9, i1 true)
  store i8 120, ptr %input
  %invalid = call i32 @verify_owned_strings(ptr %input, i64 9, i1 true)
  store i8 99, ptr %input
  store i8 0, ptr %p8
  %short = call i32 @verify_owned_strings(ptr %input, i64 8, i1 true)
  store i8 50, ptr %p8
  store i8 120, ptr %p9
  %p10 = getelementptr i8, ptr %input, i64 10
  store i8 0, ptr %p10
  %long = call i32 @verify_owned_strings(ptr %input, i64 10, i1 true)
  store i8 97, ptr %input
  store i8 109, ptr %p1
  store i8 98, ptr %p2
  store i8 101, ptr %p3
  store i8 114, ptr %p4
  store i8 45, ptr %p5
  store i8 107, ptr %p6
  store i8 101, ptr %p7
  store i8 121, ptr %p8
  store i8 49, ptr %p9
  store i8 57, ptr %p10
  %p11 = getelementptr i8, ptr %input, i64 11
  store i8 0, ptr %p11
  %accepted.comdat = call i32 @verify_owned_strings(ptr %input, i64 11, i1 false)
  %unowned = call i8 @__obf_vm_unowned_reader()
  %private.ok = icmp eq i32 %accepted.private, 0
  %invalid.ok = icmp ne i32 %invalid, 0
  %short.ok = icmp ne i32 %short, 0
  %long.ok = icmp ne i32 %long, 0
  %comdat.ok = icmp eq i32 %accepted.comdat, 0
  %unowned.ok = icmp eq i8 %unowned, 117
  %ok1 = and i1 %private.ok, %invalid.ok
  %ok2 = and i1 %short.ok, %long.ok
  %ok3 = and i1 %comdat.ok, %unowned.ok
  %ok4 = and i1 %ok1, %ok2
  %ok = and i1 %ok4, %ok3
  %status = select i1 %ok, i32 0, i32 1
  ret i32 %status
}

; CHECK: c"unowned-note\00"
; CHECK: "vm.island.subhelper"
