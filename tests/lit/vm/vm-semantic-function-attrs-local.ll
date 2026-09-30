; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-semantic-function-attrs-local.yaml -passes='obf-vm,verify' -S %s -o - | %FileCheck %s --check-prefix=LOCAL
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-semantic-function-attrs-local.yaml -passes='obf-vm,verify' -S %s -o %t
; RUN: %lli %t

; LOCAL-LABEL: define i32 @local_attr_target(
; LOCAL-SAME: #[[WRAP:[0-9]+]] {
; LOCAL: call i32 %local_attr_target.obf.wrapper.indirect({{.*}}) #[[STRICTCALL:[0-9]+]]
; LOCAL-LABEL: define i32 @local_attr_caller() {
; LOCAL: call i32 %local_attr_target.obf.indirect({{.*}}) #[[STRICTCALL]]
; LOCAL-LABEL: define i32 @constrained_target(
; LOCAL-SAME: #[[CONSTRAINED:[0-9]+]] {
; LOCAL: call float @llvm.experimental.constrained.fmul.f32
; LOCAL-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(
; LOCAL-SAME: #[[IMPL:[0-9]+]] {
; LOCAL-LABEL: define internal i32 @__obf_vm_e_{{[A-Za-z0-9_]+}}(
; LOCAL-SAME: #[[THUNK:[0-9]+]] {
; LOCAL: call i32 {{(@__obf_vm_i_[A-Za-z0-9_]+|%obf\.vm\.entry\.thunk\.[A-Za-z0-9_.]+)}}({{.*}}) #[[STRICTCALL]]
; LOCAL-DAG: attributes #[[WRAP]] = { null_pointer_is_valid strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign" "probe-stack"="inline-asm" "stack-probe-size"="4096" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic" }
; LOCAL-DAG: attributes #[[CONSTRAINED]] = { strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic" }
; LOCAL-DAG: attributes #[[IMPL]] = { noinline null_pointer_is_valid optnone strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign"{{.*}}"probe-stack"="inline-asm" "stack-probe-size"="4096" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic"{{.*}} }
; LOCAL-DAG: attributes #[[THUNK]] = { noinline null_pointer_is_valid strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign"{{.*}}"probe-stack"="inline-asm" "stack-probe-size"="4096" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic"{{.*}} }
; LOCAL-DAG: attributes #[[STRICTCALL]] = { strictfp }

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
  %direct.ok = icmp eq i32 %direct, 1073741824
  %caller.ok = icmp eq i32 %caller, 1073741824
  %constrained.ok = icmp eq i32 %constrained, 1073741824
  %ok.direct.caller = and i1 %direct.ok, %caller.ok
  %ok = and i1 %ok.direct.caller, %constrained.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

attributes #0 = { mustprogress nofree nosync willreturn memory(none) null_pointer_is_valid strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign" "probe-stack"="inline-asm" "stack-probe-size"="4096" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic" }
attributes #1 = { strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic" }
