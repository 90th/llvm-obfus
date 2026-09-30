; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-semantic-function-attrs-islands.yaml -passes='obf-vm,verify' -S %s -o - | %FileCheck %s --check-prefix=ISLAND
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-semantic-function-attrs-islands.yaml -passes='obf-vm,verify' -S %s -o %t
; RUN: %lli %t

; ISLAND-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(
; ISLAND-SAME: #[[IMPL:[0-9]+]] {
; ISLAND-LABEL: define internal i32 @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr %vm.island.state)
; ISLAND-SAME: #[[HELPER:[0-9]+]] {
; ISLAND-LABEL: define internal i32 @__obf_vm_hd_{{[A-Za-z0-9_]+}}(ptr %vm.island.state)
; ISLAND-SAME: #[[DECOY:[0-9]+]] {
; ISLAND-DAG: attributes #[[IMPL]] = { noinline null_pointer_is_valid optnone strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign"{{.*}}"target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic"{{.*}}"vm.island.topology.helper_shards"{{.*}} }
; ISLAND-DAG: attributes #[[HELPER]] = { noinline null_pointer_is_valid optnone strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign"{{.*}}"target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic"{{.*}}"vm.island.helper"{{.*}} }
; ISLAND-DAG: attributes #[[DECOY]] = { noinline null_pointer_is_valid optnone strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign"{{.*}}"target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic"{{.*}}"vm.island.helper.decoy"{{.*}} }

define i32 @island_attr_target(i32 %bits, i32 %salt) #0 {
entry:
  %value = bitcast i32 %bits to float
  %half = fmul float %value, 5.000000e-01
  %half.bits = bitcast float %half to i32
  %k0 = xor i32 %salt, 85
  %k1 = add i32 %k0, 17
  %k2 = sub i32 %k1, 17
  %k3 = xor i32 %k2, 85
  %r0 = xor i32 %half.bits, %k3
  %r1 = add i32 %r0, 29
  %r2 = sub i32 %r1, 29
  %r3 = xor i32 %r2, 4660
  %r4 = xor i32 %r3, 4660
  %k4 = or i32 %salt, 0
  %k5 = and i32 %k4, -1
  %r5 = xor i32 %r4, %k5
  %k6 = add i32 %k5, 101
  %k7 = sub i32 %k6, 101
  %r6 = xor i32 %r5, %k7
  %m0 = add i32 %r6, 7
  %m1 = sub i32 %m0, 7
  %m2 = xor i32 %m1, 255
  %m3 = xor i32 %m2, 255
  %m4 = or i32 %m3, 0
  %m5 = and i32 %m4, -1
  %m6 = add i32 %m5, %salt
  %m7 = sub i32 %m6, %salt
  ret i32 %m7
}

define i32 @main() {
entry:
  %r = call i32 @island_attr_target(i32 1082130432, i32 21845)
  %ok = icmp eq i32 %r, 1073763669
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

attributes #0 = { mustprogress nofree nosync willreturn memory(none) null_pointer_is_valid strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic" }
