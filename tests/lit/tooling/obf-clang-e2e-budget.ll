; RUN: timeout 120 %obf_clang -O2 --obf-config=%S/../Inputs/obf-clang-e2e.yaml %S/../Inputs/obf-clang-e2e.c -o %t.exe
; RUN: %t.exe | %FileCheck %s
;
; CHECK: consistent=1 len=13

define void @dummy() {
entry:
  ret void
}
