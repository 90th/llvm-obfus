; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute.yaml --obf-seed=1 -passes=obf-instruction-substitute -S %s -o %t.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute.yaml --obf-seed=1 -passes=obf-instruction-substitute -S %s -o %t.second
; RUN: cmp %t.first %t.second
; RUN: %FileCheck %s < %t.first
; RUN: %opt -passes=verify -disable-output %t.first
; RUN: %lli %t.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute.yaml --obf-seed=2 -passes=obf-instruction-substitute -S %s -o %t.seed2
; RUN: %python -c "import re,pathlib,sys; pat=re.compile(r'obf\.(?:and|or|xor)\.[a-z0-9.]*'); a=pat.findall(pathlib.Path(sys.argv[1]).read_text()); b=pat.findall(pathlib.Path(sys.argv[2]).read_text()); sys.exit(0 if a and a != b else 1)" %t.first %t.seed2

define i32 @value(i32 %x, i32 %y) {
entry:
  %lhs = and i32 %x, %y
  %rhs = or i32 %lhs, 123
  %z = xor i32 %rhs, 5
  ret i32 %z
}

define i32 @main() {
entry:
  %value = call i32 @value(i32 10, i32 20)
  %ok = icmp eq i32 %value, 126
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; @value is level strong (max_substitutions_per_function = 6), so and/or/xor are
; all substituted. The exact identity family per op is seed/path dependent, so
; assert only that each operator's substitution chain is present (both families
; share the %obf.<op>. name prefix). %lli proves the identities are correct and
; the seed=2 python guard proves seed diversity; the cmp proves determinism.
; CHECK-LABEL: define i32 @value
; CHECK-DAG: %obf.and.
; CHECK-DAG: %obf.or.
; CHECK-DAG: %obf.xor.
