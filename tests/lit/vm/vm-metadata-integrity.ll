; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-metadata-integrity.yaml -passes=obf-vm -S %s -o %t.ll
; RUN: %python %S/../Inputs/vm-metadata-integrity.py discover %t.ll %t.discovery.ll %t.layout.json
; RUN: %python %S/../Inputs/vm-metadata-integrity.py check %t.ll %t.discovery.ll %t.layout.json %t -- %lli
;
; Runtime layout gathering changes only a separate discovery copy. Every control
; and mutation executes the complete original protected body, through its public
; wrapper and registered-token admission, retaining encoded target/return ABI.
; Coherent mutations reproduce rolling decode exactly, not just random damage.
; All successors of an executed branch must be checked, including its unselected
; edge. An unexecuted future instruction is not an upfront whole-program check.
; Padding is semantically inert, but must be checked just as exactly as metadata.
; Unbuffered markers distinguish rejection before the first call from late traps.
; A POSIX trap observer also exposes stores that occur before rejection.
; Payload matching accepts LLVM hexadecimal escapes and escaped backslashes.
; Affine placement and masked physical copies reconstruct one canonical payload.
; Every logical mutation reencodes all copies, including state-island anchors.
; Encoding metadata and canonical/physical roundtrips are mandatory for active pools.
; Discovery follows pointer constant cells and split call/store handler blocks.
; Complete decode records use unbuffered stderr; effect markers use stdout.
; Discovery formats bounded unsigned decimals in IR, without libc formatter symbols.
; Padding classification reproduces every seeded field-order key, including ties.
; Each scenario retains complete reachable bodies, tables, and startup constructors.

@fixture_effect = global i32 0
@fixture_value = global i32 -1
@fixture_trap_expect = global i32 -1
@fixture_first = private constant [3 x i8] c"E1\0A"
@fixture_left = private constant [3 x i8] c"E2\0A"
@fixture_right = private constant [3 x i8] c"E3\0A"
@fixture_last = private constant [3 x i8] c"E4\0A"
@fixture_accept = private constant [7 x i8] c"ACCEPT\0A"
@fixture_dirty = private constant [6 x i8] c"DIRTY\0A"

declare i64 @fixture_write(i32, ptr, i64)

define void @fixture_emit(i32 %stage) {
entry:
  %old = load i32, ptr @fixture_effect
  %scaled = mul i32 %old, 5
  %next = add i32 %scaled, %stage
  store i32 %next, ptr @fixture_effect
  %first = icmp eq i32 %stage, 1
  %left = icmp eq i32 %stage, 2
  %right = icmp eq i32 %stage, 3
  %p1 = select i1 %first, ptr @fixture_first, ptr @fixture_last
  %p2 = select i1 %left, ptr @fixture_left, ptr %p1
  %p3 = select i1 %right, ptr @fixture_right, ptr %p2
  call i64 @fixture_write(i32 1, ptr %p3, i64 3)
  ret void
}

define i32 @ordinary_integrity(i32 %fixture_ordinary_integrity_input) {
entry:
  call void @fixture_emit(i32 1)
  %mixed = xor i32 %fixture_ordinary_integrity_input, 23130
  %base = add i32 %mixed, 17
  %bit = and i32 %fixture_ordinary_integrity_input, 1
  %choose = icmp ne i32 %bit, 0
  br i1 %choose, label %left, label %right
left:
  store i32 200, ptr @fixture_value
  call void @fixture_emit(i32 2)
  %left.value = mul i32 %base, 3
  br label %join
right:
  store i32 300, ptr @fixture_value
  call void @fixture_emit(i32 3)
  %right.value = add i32 %base, 19
  br label %join
join:
  %value = phi i32 [ %left.value, %left ], [ %right.value, %right ]
  call void @fixture_emit(i32 4)
  ret i32 %value
}

define i32 @strong_integrity(i32 %fixture_strong_integrity_input) {
entry:
  call void @fixture_emit(i32 1)
  %mixed = xor i32 %fixture_strong_integrity_input, 23130
  %base = add i32 %mixed, 17
  %bit = and i32 %fixture_strong_integrity_input, 1
  %choose = icmp ne i32 %bit, 0
  br i1 %choose, label %left, label %right
left:
  store i32 200, ptr @fixture_value
  call void @fixture_emit(i32 2)
  %left.value = mul i32 %base, 3
  br label %join
right:
  store i32 300, ptr @fixture_value
  call void @fixture_emit(i32 3)
  %right.value = add i32 %base, 19
  br label %join
join:
  %value = phi i32 [ %left.value, %left ], [ %right.value, %right ]
  call void @fixture_emit(i32 4)
  %s1 = add i32 %value, 1
  %s2 = add i32 %s1, 2
  %s3 = add i32 %s2, 3
  %s4 = add i32 %s3, 4
  %s5 = add i32 %s4, 5
  %s6 = add i32 %s5, 6
  %s7 = add i32 %s6, 7
  %s8 = add i32 %s7, 8
  %s9 = add i32 %s8, 9
  %s10 = add i32 %s9, 10
  %s11 = add i32 %s10, 11
  %s12 = add i32 %s11, 12
  %s13 = add i32 %s12, 13
  %s14 = add i32 %s13, 14
  %s15 = add i32 %s14, 15
  %s16 = add i32 %s15, 16
  %s17 = add i32 %s16, 17
  %s18 = add i32 %s17, 18
  %s19 = add i32 %s18, 19
  %s20 = add i32 %s19, 20
  %s21 = add i32 %s20, 21
  %s22 = add i32 %s21, 22
  %s23 = add i32 %s22, 23
  %s24 = add i32 %s23, 24
  ret i32 %s24
}

define i32 @main() {
entry:
  %ordinary = call i32 @ordinary_integrity(i32 0)
  %strong = call i32 @strong_integrity(i32 1)
  %sum = add i32 %ordinary, %strong
  ret i32 0
}
