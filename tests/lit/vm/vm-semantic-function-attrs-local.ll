; RUN: %python %S/../Inputs/prepare_vm_semantic_attrs_runtime.py %s %t.host-input.ll %llvm_host_triple
; RUN: %opt -mtriple=%llvm_host_triple -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-semantic-function-attrs-local.yaml -passes='obf-vm,verify' -S %t.host-input.ll -o %t
; RUN: %lli %t
; RUN: %opt -passes='default<O2>,verify' -S %t -o %t.optimized
; RUN: %lli %t.optimized


declare float @llvm.experimental.constrained.fmul.f32(float, float, metadata, metadata)

define i32 @local_attr_target(i32 %bits, i32 %salt) #0 {
entry:
  %value = bitcast i32 %bits to float
  %half = fmul float %value, 5.000000e-01
  %half.bits = bitcast float %half to i32
  %masked = xor i32 %half.bits, %salt
  %restored = xor i32 %masked, %salt
  ret i32 %restored
}

define i32 @local_attr_caller() {
entry:
  %r = call i32 @local_attr_target(i32 1082130432, i32 21845)
  ret i32 %r
}

define i32 @constrained_target(i32 %bits) #1 {
entry:
  %x = bitcast i32 %bits to float
  %m = call float @llvm.experimental.constrained.fmul.f32(float %x, float 5.000000e-01, metadata !"round.dynamic", metadata !"fpexcept.strict")
  %m.bits = bitcast float %m to i32
  ret i32 %m.bits
}

define i32 @main() {
entry:
  %direct = call i32 @local_attr_target(i32 1082130432, i32 4660)
  %caller = call i32 @local_attr_caller()
  %constrained = call i32 @constrained_target(i32 1082130432)
  %direct.zero = call i32 @local_attr_target(i32 -2147483648, i32 4660)
  %constrained.zero = call i32 @constrained_target(i32 -2147483648)
  %direct.ok = icmp eq i32 %direct, 1073741824
  %caller.ok = icmp eq i32 %caller, 1073741824
  %constrained.ok = icmp eq i32 %constrained, 1073741824
  %direct.zero.ok = icmp eq i32 %direct.zero, -2147483648
  %constrained.zero.ok = icmp eq i32 %constrained.zero, -2147483648
  %ok.direct.caller = and i1 %direct.ok, %caller.ok
  %normal.ok = and i1 %ok.direct.caller, %constrained.ok
  %zero.ok = and i1 %direct.zero.ok, %constrained.zero.ok
  %ok = and i1 %normal.ok, %zero.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

attributes #0 = { mustprogress nofree nosync willreturn memory(none) null_pointer_is_valid strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign" "probe-stack"="inline-asm" "stack-probe-size"="4096" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic" }
attributes #1 = { strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic" }
