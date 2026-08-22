; Keep the dynamic fallback compare in the inline-stack path, then run the
; exact finalized IR through a second LLVM O2 pipeline. The post-IR executable
; is code-generated at O0 so this test isolates reoptimization from codegen.
;
; RUN: timeout 120 %raw_clang -O2 -S -emit-llvm %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.pre.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml -passes=obf-feature-report -disable-output %t.pre.ll | %python -c "import json,sys; d=json.load(sys.stdin); print(*('|'.join((x['target_name'],x['status'],(x.get('strategy') or {}).get('kind',''))) for x in d['transforms'] if x.get('pass') == 'string_encoding' and x.get('target_name') == 'g_fallback_strncmp_dynamic'), sep=chr(10))" | %FileCheck %s --check-prefix=STRATEGY
; RUN: timeout 120 %obf_clang -O2 -S -emit-llvm --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.post.ll
; RUN: %opt -passes=verify -disable-output %t.post.ll
; RUN: timeout 120 %raw_clang -O0 %t.post.ll %obf_runtime -o %t.direct
; RUN: %t.direct | %FileCheck %s --check-prefix=DIRECT
; RUN: %opt -passes='default<O2>' %t.post.ll -o %t.reopt.bc
; RUN: %opt -passes=verify -disable-output %t.reopt.bc
; RUN: timeout 120 %raw_clang -O0 %t.reopt.bc %obf_runtime -o %t.reopt
; RUN: %t.reopt | %FileCheck %s --check-prefix=REOPT
;
; STRATEGY: g_fallback_strncmp_dynamic|applied|inline_stack_decode
; DIRECT: [ALL E2E PASS] 43 assertions passed
; REOPT: [ALL E2E PASS] 43 assertions passed
