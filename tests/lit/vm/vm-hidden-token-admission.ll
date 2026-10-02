; RUN: %python %S/../Inputs/vm-hidden-token-admission.py config %t.yaml
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%t.yaml -passes=obf-vm -S %s -o %t.ll
; RUN: %python %S/../Inputs/vm-hidden-token-admission.py discover %t.ll %t.discover.ll
; RUN: %lli %t.discover.ll > %t.tokens
; RUN: %python %S/../Inputs/vm-hidden-token-admission.py check %t.ll %t.tokens %t -- %lli
;
; Discover opaque values only in a separate instrumented copy. Each admission
; scenario executes the complete original reachable body in a fresh lli process.
; Keep its resolver and startup dependencies. Remove only unrelated definitions,
; unused retention-list operands, and independent constructor stores to unused seeds.
; Unique temporary scenario paths prevent reuse of files held by interrupted runs.
; Each lli has the same 30-second deadline and is killed/reaped on timeout.
; Small ordinary targets exercise the inline root; large strong targets
; exercise the state-island root, including integer and void return paths.
; The configuration retains strong_vm's required public-symbol isolation gate.
; Invalid tokens must terminate via a native trap, not an LLVM parse/load error,
; with neither protected side effects nor a normal return.
; Input targets are not address-taken, which would make policy disallow VM.
; Public-wrapper pointer calls are added only to the discovery copy after opt.

@fixture_effect = global i32 -1
@fixture_state = global i32 -1
@fixture_side_marker = private constant [5 x i8] c"SIDE\0A"
@fixture_accept = private constant [7 x i8] c"ACCEPT\0A"

declare i32 @printf(ptr, ...)
declare i64 @fixture_write(i32, ptr, i64)

define void @fixture_observe(i32 %value) {
entry:
  store i32 %value, ptr @fixture_effect
  call i64 @fixture_write(i32 1, ptr @fixture_side_marker, i64 5)
  ret void
}

define i32 @ordinary_value(i32 %fixture_ordinary_value_input) {
entry:
  call void @fixture_observe(i32 %fixture_ordinary_value_input)
  %mul = mul i32 %fixture_ordinary_value_input, 3
  %sum = add i32 %mul, 4
  ret i32 %sum
}

define void @ordinary_void(i32 %fixture_ordinary_void_input) {
entry:
  call void @fixture_observe(i32 %fixture_ordinary_void_input)
  ret void
}

define i32 @strong_value(i32 %fixture_strong_value_input) {
entry:
  call void @fixture_observe(i32 %fixture_strong_value_input)
  %s1 = add i32 %fixture_strong_value_input, 1
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

define void @strong_void(i32 %fixture_strong_void_input) {
entry:
  call void @fixture_observe(i32 %fixture_strong_void_input)
  %s1 = add i32 %fixture_strong_void_input, 1
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
  store i32 %s24, ptr @fixture_state
  ret void
}

define i32 @fixture_direct_sites(i32 %x) {
entry:
  %ordinary = call i32 @ordinary_value(i32 %x)
  call void @ordinary_void(i32 %x)
  %strong = call i32 @strong_value(i32 %x)
  call void @strong_void(i32 %x)
  %sum = add i32 %ordinary, %strong
  ret i32 %sum
}

define i32 @main() {
entry:
  %ordinary = call i32 @ordinary_value(i32 37)
  call void @ordinary_void(i32 37)
  %strong = call i32 @strong_value(i32 37)
  call void @strong_void(i32 37)
  %direct = call i32 @fixture_direct_sites(i32 37)
  %ordinary.ok = icmp eq i32 %ordinary, 115
  %strong.ok = icmp eq i32 %strong, 337
  %direct.ok = icmp eq i32 %direct, 452
  %effect = load i32, ptr @fixture_effect
  %effect.ok = icmp eq i32 %effect, 37
  %state = load i32, ptr @fixture_state
  %state.ok = icmp eq i32 %state, 337
  %ok1 = and i1 %ordinary.ok, %strong.ok
  %ok2 = and i1 %ok1, %direct.ok
  %ok3 = and i1 %ok2, %effect.ok
  %ok4 = and i1 %ok3, %state.ok
  %exit = select i1 %ok4, i32 0, i32 1
  ret i32 %exit
}
