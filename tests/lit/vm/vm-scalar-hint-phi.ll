; RUN: env OBF_COVERAGE_REPORT=%t.json %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-scalar-intrinsics.yaml -passes='obf-vm,obf-coverage-report,verify' -S %s -o %t.ll
; RUN: %python %S/../Inputs/report_contract.py whole-vm %t.json --owner vm_scalar_hint_phi
; RUN: %lli %s
; RUN: %lli %t.ll
; RUN: %opt -O2 -S %t.ll -o %t.o2.ll
; RUN: %lli %t.o2.ll
;
; Both hints feed PHI edges. Chained hints must forward the selected SSA value.
declare i8 @llvm.expect.i8(i8, i8)
declare i8 @llvm.expect.with.probability.i8(i8, i8, double immarg)

define i8 @vm_scalar_hint_phi(i1 %condition, i8 %left, i8 %right) {
entry:
  %hint = call i8 @llvm.expect.i8(i8 %left, i8 %right)
  br i1 %condition, label %yes, label %no
yes:
  %chain = call i8 @llvm.expect.with.probability.i8(i8 %hint, i8 %right, double 5.000000e-01)
  br label %merge
no:
  %other = call i8 @llvm.expect.i8(i8 %right, i8 %left)
  br label %merge
merge:
  %result = phi i8 [ %chain, %yes ], [ %other, %no ]
  ret i8 %result
}

define i32 @main() {
entry:
  %left = call i8 @vm_scalar_hint_phi(i1 true, i8 37, i8 91)
  %right = call i8 @vm_scalar_hint_phi(i1 false, i8 37, i8 91)
  %bad.left = icmp ne i8 %left, 37
  %bad.right = icmp ne i8 %right, 91
  %bad = or i1 %bad.left, %bad.right
  %exit = zext i1 %bad to i32
  ret i32 %exit
}
