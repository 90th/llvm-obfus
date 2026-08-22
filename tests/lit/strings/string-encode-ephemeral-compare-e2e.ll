; Raw Clang must leave each sentinel libc call alive immediately before the
; plugin would run at OptimizerLast. The matching obf-clang build must keep the
; externally visible probe function but remove that libc call. This paired
; pre/post proof survives artifact_cleanup, which intentionally strips local
; basic-block and local-linkage symbol names from final wrapper output.
; Runtime semantics are checked against the exact post-cleanup IR and through
; a separate direct wrapper build. The post-IR binary is compiled from each
; %t.post.o*.ll artifact with raw Clang at -O0, so it performs code generation
; without a second optimization pipeline.
;
; RUN: timeout 120 %raw_clang -O0 -S -emit-llvm %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.pre.o0.ll
; RUN: %FileCheck %s --check-prefix=PRE < %t.pre.o0.ll
; RUN: timeout 120 %obf_clang -O0 -S -emit-llvm --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.post.o0.ll
; RUN: %FileCheck %s --check-prefixes=POST,ORACLE < %t.post.o0.ll
; RUN: timeout 120 %raw_clang -O0 %t.post.o0.ll %obf_runtime -o %t.post-ir.o0.exe
; RUN: %t.post-ir.o0.exe | %FileCheck %s --check-prefix=POST-RESULT
; RUN: timeout 120 %obf_clang -O0 --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.o0.exe
; RUN: %t.o0.exe | %FileCheck %s --check-prefix=RESULT
;
; RUN: timeout 120 %raw_clang -O1 -S -emit-llvm %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.pre.o1.ll
; RUN: %FileCheck %s --check-prefix=PRE < %t.pre.o1.ll
; RUN: timeout 120 %obf_clang -O1 -S -emit-llvm --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.post.o1.ll
; RUN: %FileCheck %s --check-prefixes=POST,ORACLE < %t.post.o1.ll
; RUN: timeout 120 %raw_clang -O0 %t.post.o1.ll %obf_runtime -o %t.post-ir.o1.exe
; RUN: %t.post-ir.o1.exe | %FileCheck %s --check-prefix=POST-RESULT
; RUN: timeout 120 %obf_clang -O1 --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.o1.exe
; RUN: %t.o1.exe | %FileCheck %s --check-prefix=RESULT
;
; RUN: timeout 120 %raw_clang -O2 -S -emit-llvm %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.pre.o2.ll
; RUN: %FileCheck %s --check-prefix=PRE < %t.pre.o2.ll
; RUN: timeout 120 %obf_clang -O2 -S -emit-llvm --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.post.o2.ll
; RUN: %FileCheck %s --check-prefixes=POST,ORACLE < %t.post.o2.ll
; RUN: timeout 120 %raw_clang -O0 %t.post.o2.ll %obf_runtime -o %t.post-ir.o2.exe
; RUN: %t.post-ir.o2.exe | %FileCheck %s --check-prefix=POST-RESULT
; RUN: timeout 120 %obf_clang -O2 --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.o2.exe
; RUN: %t.o2.exe | %FileCheck %s --check-prefix=RESULT
;
; RUN: timeout 120 %raw_clang -O3 -S -emit-llvm %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.pre.o3.ll
; RUN: %FileCheck %s --check-prefix=PRE < %t.pre.o3.ll
; RUN: timeout 120 %obf_clang -O3 -S -emit-llvm --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.post.o3.ll
; RUN: %FileCheck %s --check-prefixes=POST,ORACLE < %t.post.o3.ll
; RUN: timeout 120 %raw_clang -O0 %t.post.o3.ll %obf_runtime -o %t.post-ir.o3.exe
; RUN: %t.post-ir.o3.exe | %FileCheck %s --check-prefix=POST-RESULT
; RUN: timeout 120 %obf_clang -O3 --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml %S/../Inputs/string-encode-ephemeral-compare-e2e.c -o %t.o3.exe
; RUN: %t.o3.exe | %FileCheck %s --check-prefix=RESULT
;
; The standalone string pass intentionally stops before artifact cleanup, so it
; is the right layer for asserting the generated short-circuit CFG names. The
; feature report independently proves that all three sentinel globals select
; the ephemeral micro-slot strategy on every optimized input.
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml -passes=obf-feature-report -disable-output %t.pre.o0.ll | %python -c "import json,sys; d=json.load(sys.stdin); print(*('|'.join((x['target_name'],x['status'],(x.get('strategy') or {}).get('kind',''))) for x in d['transforms'] if x.get('pass') == 'string_encoding' and x.get('target_name','').startswith('g_probe_')), sep=chr(10))" | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %t.pre.o0.ll -o %t.direct.o0.ll
; RUN: %FileCheck %s --check-prefix=DIRECT < %t.direct.o0.ll
; RUN: %opt -passes=verify -disable-output %t.direct.o0.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml -passes=obf-feature-report -disable-output %t.pre.o1.ll | %python -c "import json,sys; d=json.load(sys.stdin); print(*('|'.join((x['target_name'],x['status'],(x.get('strategy') or {}).get('kind',''))) for x in d['transforms'] if x.get('pass') == 'string_encoding' and x.get('target_name','').startswith('g_probe_')), sep=chr(10))" | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %t.pre.o1.ll -o %t.direct.o1.ll
; RUN: %FileCheck %s --check-prefix=DIRECT < %t.direct.o1.ll
; RUN: %opt -passes=verify -disable-output %t.direct.o1.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml -passes=obf-feature-report -disable-output %t.pre.o2.ll | %python -c "import json,sys; d=json.load(sys.stdin); print(*('|'.join((x['target_name'],x['status'],(x.get('strategy') or {}).get('kind',''))) for x in d['transforms'] if x.get('pass') == 'string_encoding' and x.get('target_name','').startswith('g_probe_')), sep=chr(10))" | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %t.pre.o2.ll -o %t.direct.o2.ll
; RUN: %FileCheck %s --check-prefix=DIRECT < %t.direct.o2.ll
; RUN: %opt -passes=verify -disable-output %t.direct.o2.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml -passes=obf-feature-report -disable-output %t.pre.o3.ll | %python -c "import json,sys; d=json.load(sys.stdin); print(*('|'.join((x['target_name'],x['status'],(x.get('strategy') or {}).get('kind',''))) for x in d['transforms'] if x.get('pass') == 'string_encoding' and x.get('target_name','').startswith('g_probe_')), sep=chr(10))" | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %t.pre.o3.ll -o %t.direct.o3.ll
; RUN: %FileCheck %s --check-prefix=DIRECT < %t.direct.o3.ll
; RUN: %opt -passes=verify -disable-output %t.direct.o3.ll

; PRE-LABEL: define{{.*}} @test_probe_memcmp(
; PRE: call i32 @memcmp
; PRE-LABEL: define{{.*}} @test_probe_strcmp(
; PRE: call i32 @strcmp
; PRE-LABEL: define{{.*}} @test_probe_strncmp(
; PRE: call i32 @strncmp

; POST-LABEL: define{{.*}} @test_probe_memcmp(
; POST-NOT: call{{.*}}@memcmp
; POST-LABEL: define{{.*}} @test_probe_strcmp(
; POST-NOT: call{{.*}}@strcmp
; POST-LABEL: define{{.*}} @test_probe_strncmp(
; POST-NOT: call{{.*}}@strncmp

; ORACLE-LABEL: define{{.*}} @oracle_memcmp(
; ORACLE: call i32 @memcmp
; ORACLE-LABEL: define{{.*}} @oracle_strcmp(
; ORACLE: call i32 @strcmp
; ORACLE-LABEL: define{{.*}} @oracle_strncmp(
; ORACLE: call i32 @strncmp

; REPORT-DAG: g_probe_memcmp|applied|ephemeral_micro_slot
; REPORT-DAG: g_probe_strcmp|applied|ephemeral_micro_slot
; REPORT-DAG: g_probe_strncmp|applied|ephemeral_micro_slot

; DIRECT-LABEL: define{{.*}} @test_probe_memcmp(
; DIRECT: obf.str.cmp.0:
; DIRECT-LABEL: define{{.*}} @test_probe_strcmp(
; DIRECT: obf.str.cmp.0:
; DIRECT-LABEL: define{{.*}} @test_probe_strncmp(
; DIRECT: obf.str.cmp.0:

; POST-RESULT: [ALL E2E PASS] 43 assertions passed
; RESULT: [ALL E2E PASS] 43 assertions passed

define void @dummy() {
entry:
  ret void
}
