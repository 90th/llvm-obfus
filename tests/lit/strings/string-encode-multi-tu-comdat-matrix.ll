; RUN: %python %S/../Inputs/multi_tu_comdat_matrix.py %obf_clangxx %obf_plugin %obf_runtime %t
; RUN: %FileCheck %s --input-file=%t.log

; CHECK: RESOLVED_DRIVER: {{.*}}obf-clang++
; CHECK: CASE_A_ORDER1: exit=0 stdout=CASE_A: S=SensitiveData12345 | L=SensitiveData12345
; CHECK: CASE_A_ORDER2: exit=0 stdout=CASE_A: S=SensitiveData12345 | L=SensitiveData12345
; CHECK: CASE_B_ORDER1: exit=0 stdout=CASE_B: TU1=SensitiveData12345 | TU2=SensitiveData12345
; CHECK: CASE_B_ORDER2: exit=0 stdout=CASE_B: TU1=SensitiveData12345 | TU2=SensitiveData12345
