; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/frontend-policy-safe.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s --check-prefix=POLICY
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/frontend-policy-safe.yaml -passes=obf-safe-pipeline -S %s -o %t.safe
; RUN: %FileCheck %s --check-prefix=SAFE < %t.safe
; RUN: %opt -passes=verify -disable-output %t.safe
; RUN: %lli %t.safe
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/frontend-policy-missing.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=MISSING
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/frontend-policy-unsafe.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=UNSAFE
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/frontend-policy-wildcard-vm.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=WILDCARD
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/frontend-policy-duplicate-overlap.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=DUPLICATE
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/frontend-policy-vm.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=VM
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/frontend-policy-overlap.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=OVERLAP

; The safe frontend config must select only the exact configured function. Its
; transformed output and runnable result prove the pipeline still runs; the
; unchanged helper proves unmatched functions cannot be promoted implicitly.

define i32 @selected(i32 %x) {
entry:
  %slot = alloca i32, align 4
  store i32 %x, ptr %slot, align 4
  %loaded = load i32, ptr %slot, align 4
  %sum = add nsw i32 %loaded, 129
  ret i32 %sum
}

define i32 @helper(i32 %x) {
entry:
  %slot = alloca i32, align 4
  store i32 %x, ptr %slot, align 4
  %loaded = load i32, ptr %slot, align 4
  %sum = add nsw i32 %loaded, 7
  ret i32 %sum
}

define i32 @duplicate_target(i32 %x) {
entry:
  ret i32 %x
}

define i32 @overlap_target(i32 %x) {
entry:
  ret i32 %x
}

define i32 @main() {
entry:
  %selected = call i32 @selected(i32 5)
  %helper = call i32 @helper(i32 8)
  %sum = add i32 %selected, %helper
  %ok = icmp eq i32 %sum, 149
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; POLICY-DAG: "detail":"config match:selected","level":"strong"
; POLICY-DAG: "name":"helper","policy":{{.*}}"detail":"default","level":"none"

; SAFE-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; SAFE-LABEL: define i32 @selected(i32
; SAFE: alloca i32, align 4
; SAFE: alloca { i64, i64 }, align 8
; SAFE: call {{.*}} @{{_[0-9a-f]+}}
; SAFE: store i32 %0, ptr %{{[^,]+}}, align 4
; SAFE: load i32, ptr %{{[^,]+}}, align 4
; SAFE: freeze i32
; SAFE-NOT: add nsw i32 %{{[^,]+}}, 129
; SAFE: ret i32 %{{[^ ]+}}
; SAFE-LABEL: define i32 @helper(i32
; SAFE: alloca i32, align 4
; SAFE: store i32 %0, ptr %{{[^,]+}}, align 4
; SAFE: load i32, ptr %{{[^,]+}}, align 4
; SAFE: add nsw i32 %{{[^,]+}}, 7
; SAFE: ret i32 %{{[^ ]+}}
; SAFE-NOT: alloca { i64, i64 }, align 8
; SAFE-LABEL: define i32 @main()
; SAFE: call i32 @selected(i32 5)
; SAFE: call i32 @helper(i32 8)
; SAFE: icmp eq i32 %{{[^,]+}}, 149

; MISSING: LLVM ERROR: config error: non-generic frontend configured function 'missing_exact' is not a defined function
; UNSAFE: LLVM ERROR: config error: non-generic frontend forbids security.allow_unsafe_config
; WILDCARD: LLVM ERROR: config error: non-generic frontend target 'selected_*' must use an exact function name
; DUPLICATE: LLVM ERROR: config error: non-generic frontend has duplicate configured function 'duplicate_target'
; VM: LLVM ERROR: config error: non-generic frontend entries must use light or strong
; OVERLAP: LLVM ERROR: config error: non-generic frontend target/override overlap 'overlap_target'
