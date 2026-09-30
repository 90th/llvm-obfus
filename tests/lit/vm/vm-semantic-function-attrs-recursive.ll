; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-semantic-function-attrs-recursive.yaml -passes='obf-vm,verify' -S %s -o - | %FileCheck %s --check-prefix=RECURSIVE
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-semantic-function-attrs-recursive.yaml -passes='obf-vm,verify' -S %s -o %t
; RUN: %lli %t

; RECURSIVE-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(
; RECURSIVE-SAME: #[[IMPL:[0-9]+]] {
; RECURSIVE-LABEL: define internal i32 @__obf_vm_hs_{{[A-Za-z0-9_]+}}(ptr %vm.island.subhelper.state)
; RECURSIVE-SAME: #[[SUB:[0-9]+]] {
; RECURSIVE-DAG: attributes #[[IMPL]] = { noinline null_pointer_is_valid optnone strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign"{{.*}}"probe-stack"="inline-asm" "stack-probe-size"="4096" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic"{{.*}}"vm.island.topology.helper_shards"{{.*}} }
; RECURSIVE-DAG: attributes #[[SUB]] = { noinline null_pointer_is_valid optnone strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign"{{.*}}"probe-stack"="inline-asm" "stack-probe-size"="4096" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic"{{.*}}"vm.island.subhelper"{{.*}} }

define i32 @recursive_attr_target(i32 %bits, i32 %salt) #0 {
entry:
 %value = bitcast i32 %bits to float
 %half = fmul float %value, 5.000000e-01
 %base = bitcast float %half to i32
 %v00 = xor i32 %base, %salt
 %v01 = add i32 %v00, 11
 %v02 = sub i32 %v01, 11
 %v03 = xor i32 %v02, 2827
 %v04 = xor i32 %v03, 2827
 %v05 = or i32 %v04, 0
 %v06 = and i32 %v05, -1
 %v07 = add i32 %v06, 17
 %v08 = sub i32 %v07, 17
 %v09 = xor i32 %v08, 4369
 %v10 = xor i32 %v09, 4369
 %v11 = or i32 %v10, 0
 %v12 = and i32 %v11, -1
 %v13 = add i32 %v12, 23
 %v14 = sub i32 %v13, 23
 %v15 = xor i32 %v14, 5911
 %v16 = xor i32 %v15, 5911
 %v17 = or i32 %v16, 0
 %v18 = and i32 %v17, -1
 %v19 = add i32 %v18, 31
 %v20 = sub i32 %v19, 31
 %v21 = xor i32 %v20, 7967
 %v22 = xor i32 %v21, 7967
 %v23 = or i32 %v22, 0
 %v24 = and i32 %v23, -1
 %v25 = add i32 %v24, 37
 %v26 = sub i32 %v25, 37
 %v27 = xor i32 %v26, 9509
 %v28 = xor i32 %v27, 9509
 %v29 = or i32 %v28, 0
 %v30 = and i32 %v29, -1
 %v31 = add i32 %v30, 43
 %v32 = sub i32 %v31, 43
 %v33 = xor i32 %v32, 11051
 %v34 = xor i32 %v33, 11051
 %v35 = or i32 %v34, 0
 %v36 = and i32 %v35, -1
 %v37 = add i32 %v36, 59
 %v38 = sub i32 %v37, 59
 %v39 = xor i32 %v38, 15163
 %v40 = xor i32 %v39, 15163
 %v41 = or i32 %v40, 0
 %v42 = and i32 %v41, -1
 %v43 = add i32 %v42, 71
 %v44 = sub i32 %v43, 71
 %v45 = xor i32 %v44, 18247
 %v46 = xor i32 %v45, 18247
 %v47 = or i32 %v46, 0
 %v48 = and i32 %v47, -1
 %v49 = add i32 %v48, 83
 %v50 = sub i32 %v49, 83
 %v51 = xor i32 %v50, 21331
 %v52 = xor i32 %v51, 21331
 %v53 = or i32 %v52, 0
 %v54 = and i32 %v53, -1
 %v55 = add i32 %v54, 97
 %v56 = sub i32 %v55, 97
 %v57 = xor i32 %v56, 24929
 %v58 = xor i32 %v57, 24929
 %v59 = or i32 %v58, 0
 %v60 = and i32 %v59, -1
 %v61 = add i32 %v60, 109
 %v62 = sub i32 %v61, 109
 %v63 = xor i32 %v62, 28013
 %v64 = xor i32 %v63, 28013
 %v65 = or i32 %v64, 0
 %v66 = and i32 %v65, -1
 %v67 = add i32 %v66, 131
 %v68 = sub i32 %v67, 131
 %v69 = xor i32 %v68, 33667
 %v70 = xor i32 %v69, 33667
 %v71 = or i32 %v70, 0
 %v72 = and i32 %v71, -1
 %v73 = add i32 %v72, 149
 %v74 = sub i32 %v73, 149
 %v75 = xor i32 %v74, 38293
 %v76 = xor i32 %v75, 38293
 %v77 = or i32 %v76, 0
 %v78 = and i32 %v77, -1
 %v79 = add i32 %v78, 173
 %v80 = sub i32 %v79, 173
 %v81 = xor i32 %v80, 44461
 %v82 = xor i32 %v81, 44461
 %v83 = or i32 %v82, 0
 %v84 = and i32 %v83, -1
 %v85 = add i32 %v84, 197
 %v86 = sub i32 %v85, 197
 %v87 = xor i32 %v86, 50629
 %v88 = xor i32 %v87, 50629
 %v89 = or i32 %v88, 0
 %v90 = and i32 %v89, -1
 %v91 = add i32 %v90, 211
 %v92 = sub i32 %v91, 211
 %v93 = xor i32 %v92, 54227
 %v94 = xor i32 %v93, 54227
 %v95 = or i32 %v94, 0
 %v96 = and i32 %v95, -1
 %out = xor i32 %v96, %salt
 ret i32 %out
}

define i32 @main() {
entry:
  %r = call i32 @recursive_attr_target(i32 1082130432, i32 21845)
  %ok = icmp eq i32 %r, 1073741824
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

attributes #0 = { mustprogress nofree nosync willreturn memory(none) null_pointer_is_valid strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign" "probe-stack"="inline-asm" "stack-probe-size"="4096" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic" }
