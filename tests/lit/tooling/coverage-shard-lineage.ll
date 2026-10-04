; Exercise outlining on a retained generated-parent input, without VM admission claims.
; RUN: %python %S/../Inputs/report_contract.py prepare-shards %s --ir %t.input.ll
; RUN: env OBF_COVERAGE_REPORT=%t.json %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/coverage-shard-lineage.yaml -passes='obf-control-flatten,obf-function-outline,obf-cfg-state-cleanup,obf-artifact-cleanup,obf-coverage-report' -S %t.input.ll -o %t.ll
; RUN: %python %S/../Inputs/report_contract.py shards %t.json
; RUN: %lli %t.ll
; RUN: env -u OBF_COVERAGE_REPORT %opt -load-pass-plugin %obf_plugin -passes=obf-coverage-report -disable-output %t.ll > %t.retained.json
; RUN: %python %S/../Inputs/report_contract.py shards %t.retained.json
; RUN: env -u OBF_COVERAGE_REPORT %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/coverage-shard-lineage.yaml -passes='obf-control-flatten,obf-function-outline,obf-cfg-state-cleanup,obf-artifact-cleanup' -S %s -o %t.uncaptured.ll
; RUN: %lli %t.uncaptured.ll

define i32 @strong_vm_fold(i32 %a, i32 %b, i32 %c) {
entry:
  %seed = add i32 %a, 7
  %mix = xor i32 %seed, %b
  %cond = icmp sgt i32 %mix, %c
  br i1 %cond, label %left, label %right

left:
  %l0 = mul i32 %mix, 3
  %l1 = add i32 %l0, %c
  %l2 = xor i32 %l1, 17
  %l3 = shl i32 %l2, 1
  br label %merge

right:
  %r0 = sub i32 %c, %mix
  %r1 = or i32 %r0, %a
  %r2 = and i32 %r1, 255
  %r3 = lshr i32 %r2, 1
  br label %merge

merge:
  %v = phi i32 [ %l3, %left ], [ %r3, %right ]
  %m0 = add i32 %v, %b
  %m1 = xor i32 %m0, %c
  %m2 = mul i32 %m1, 5
  %m3 = sub i32 %m2, %a
  ret i32 %m3
}

define i32 @native_fold(i32 %a, i32 %b, i32 %c) {
entry:
  %seed = add i32 %a, 7
  %mix = xor i32 %seed, %b
  %cond = icmp sgt i32 %mix, %c
  br i1 %cond, label %left, label %right

left:
  %l0 = mul i32 %mix, 3
  %l1 = add i32 %l0, %c
  %l2 = xor i32 %l1, 17
  %l3 = shl i32 %l2, 1
  br label %merge

right:
  %r0 = sub i32 %c, %mix
  %r1 = or i32 %r0, %a
  %r2 = and i32 %r1, 255
  %r3 = lshr i32 %r2, 1
  br label %merge

merge:
  %v = phi i32 [ %l3, %left ], [ %r3, %right ]
  %m0 = add i32 %v, %b
  %m1 = xor i32 %m0, %c
  %m2 = mul i32 %m1, 5
  %m3 = sub i32 %m2, %a
  ret i32 %m3
}

define i32 @main() {
entry:
  %a = call i32 @strong_vm_fold(i32 2, i32 5, i32 3)
  %b = call i32 @strong_vm_fold(i32 1, i32 2, i32 10)
  %sum = add i32 %a, %b
  %c = call i32 @native_fold(i32 2, i32 5, i32 3)
  %d = call i32 @native_fold(i32 1, i32 2, i32 10)
  %native_sum = add i32 %c, %d
  %vm_ok = icmp eq i32 %sum, 607
  %native_ok = icmp eq i32 %native_sum, 607
  %ok = and i1 %vm_ok, %native_ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

