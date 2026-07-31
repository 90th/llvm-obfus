; RUN: timeout 120 %obf_clang -O0 --obf-config=%S/../Inputs/progress-warnings.yaml %S/../Inputs/obf-clang-opt-levels.c -o %t.o0.exe 2>&1 | %FileCheck %s --check-prefix=ACTIVE
; RUN: %t.o0.exe | %FileCheck %s --check-prefix=RESULT
; RUN: timeout 120 %obf_clang -O1 --obf-config=%S/../Inputs/progress-warnings.yaml %S/../Inputs/obf-clang-opt-levels.c -o %t.o1.exe 2>&1 | %FileCheck %s --check-prefix=ACTIVE
; RUN: %t.o1.exe | %FileCheck %s --check-prefix=RESULT
; RUN: timeout 120 %obf_clang -O2 --obf-config=%S/../Inputs/progress-warnings.yaml %S/../Inputs/obf-clang-opt-levels.c -o %t.o2.exe 2>&1 | %FileCheck %s --check-prefix=ACTIVE
; RUN: %t.o2.exe | %FileCheck %s --check-prefix=RESULT
; RUN: timeout 120 %obf_clang -O3 --obf-config=%S/../Inputs/progress-warnings.yaml %S/../Inputs/obf-clang-opt-levels.c -o %t.o3.exe 2>&1 | %FileCheck %s --check-prefix=ACTIVE
; RUN: %t.o3.exe | %FileCheck %s --check-prefix=RESULT
;
; The source intentionally uses ordinary C locals so -O0 exercises the
; alloca-based path for the strong_vm target selected by progress-warnings.yaml.
;
; ACTIVE: llvm-obfus: warning: starting strong_vm lowering for 1 function(s); this can take a while
; ACTIVE: llvm-obfus: warning: starting strong_vm hardening for 1 function(s); this can take a while
; RESULT: result=9

define void @dummy() {
entry:
  ret void
}
