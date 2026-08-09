; RUN: %raw_clang -O1 -fno-inline -fno-inline-functions -emit-llvm -c %S/../Inputs/obf-bc-e2e.c -o %t.input.bc
; RUN: printf 'obf-bc sentinel\n' > %t.sentinel.bc
; RUN: cp %t.sentinel.bc %t.sentinel.expected.bc
; RUN: %python %S/../Inputs/obf-tinygo-assert.py obf-bc-signal %obf_bc %t.signal-transaction
; RUN: not %obf_bc --obf-config %S/../Inputs/obf-bc-e2e.yaml -passes=verify %t.input.bc -o %t.sentinel.bc 2>&1 | %FileCheck %s --check-prefix=NO-PASS
; RUN: cmp %t.sentinel.expected.bc %t.sentinel.bc
; RUN: not %obf_bc --obf-config %S/../Inputs/obf-bc-e2e.yaml -c %t.input.bc -o %t.sentinel.bc 2>&1 | %FileCheck %s --check-prefix=OBJECT
; RUN: cmp %t.sentinel.expected.bc %t.sentinel.bc
; RUN: not %obf_bc --obf-config %S/../Inputs/obf-bc-e2e.yaml --obf-seed=0 %t.input.bc -o %t.sentinel.bc 2>&1 | %FileCheck %s --check-prefix=SEED
; RUN: cmp %t.sentinel.expected.bc %t.sentinel.bc
; RUN: not %obf_bc %t.input.bc -o %t.sentinel.bc 2>&1 | %FileCheck %s --check-prefix=MISSING-CONFIG
; RUN: cmp %t.sentinel.expected.bc %t.sentinel.bc
; RUN: not %obf_bc --obf-config=%S/../Inputs/obf-bc-e2e.yaml %t.input.bc 2>&1 | %FileCheck %s --check-prefix=MISSING-OUTPUT
; RUN: not %obf_bc --obf-config=%S/../Inputs/obf-bc-e2e.yaml %t.input.bc %t.input.bc -o%t.sentinel.bc 2>&1 | %FileCheck %s --check-prefix=MULTIPLE-INPUTS
; RUN: cmp %t.sentinel.expected.bc %t.sentinel.bc
; RUN: not %obf_bc --obf-config=%t.missing.yaml %t.input.bc -o%t.sentinel.bc 2>&1 | %FileCheck %s --check-prefix=MISSING-CONFIG-FILE
; RUN: cmp %t.sentinel.expected.bc %t.sentinel.bc
; RUN: cp %t.input.bc %t.alias.bc
; RUN: cp %t.alias.bc %t.alias.expected.bc
; RUN: not %obf_bc --obf-config=%S/../Inputs/obf-bc-e2e.yaml %t.alias.bc -o%t.alias.bc 2>&1 | %FileCheck %s --check-prefix=ALIAS
; RUN: cmp %t.alias.expected.bc %t.alias.bc
; RUN: not --crash %obf_bc --obf-config=%S/../Inputs/obf-bc-plugin-failure.yaml --obf-seed=424242 %t.input.bc -o%t.sentinel.bc 2>&1 | %FileCheck %s --check-prefix=PLUGIN-CONFIG --implicit-check-not='obf-bc:'
; RUN: cmp %t.sentinel.expected.bc %t.sentinel.bc
;
; Every rejected invocation starts with a preseeded output. Parser and preflight
; failures must retain it unchanged. The final case reaches the real pass plugin;
; its fatal config error is re-raised as the child signal after cleanup.
;
; NO-PASS: obf-bc: unsupported option: -passes=verify
; OBJECT: obf-bc: unsupported option: -c
; SEED: obf-bc: --obf-seed must be a non-zero decimal integer
; MISSING-CONFIG: obf-bc: --obf-config is required
; MISSING-OUTPUT: obf-bc: -o is required
; MULTIPLE-INPUTS: obf-bc: expected exactly one .bc input
; MISSING-CONFIG-FILE: obf-bc: missing config:
; ALIAS: obf-bc: input and output must be distinct
; PLUGIN-CONFIG: configured function 'missing_target' is not a defined function

define void @dummy() {
entry:
  ret void
}
