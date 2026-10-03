; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-select-semantics.yaml -passes=obf-feature-report -disable-output %s | jq -r '.predictions[] | select(.pass == "vm") | [.target_name, .status] | join("|")' | %FileCheck %s --check-prefix=ADMIT
; RUN: %lli %s
; RUN: for seed in 1 2 111 222; do \
; RUN:   %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-select-semantics.yaml --obf-seed=$seed -passes='obf-vm,verify' -S %s -o %t.$seed.ll && \
; RUN:   %FileCheck %s --check-prefix=VM --implicit-check-not='br i1 poison' --implicit-check-not='br i1 undef' < %t.$seed.ll && \
; RUN:   %lli %t.$seed.ll && \
; RUN:   %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t.$seed.ll -o %t.$seed.instcombine.ll && \
; RUN:   %lli %t.$seed.instcombine.ll && \
; RUN:   %opt -O2 -S %t.$seed.ll -o %t.$seed.o2.ll && \
; RUN:   %lli %t.$seed.o2.ll || exit 1; \
; RUN: done
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-select-semantics.yaml -passes='obf-safe-pipeline,verify' -S %s -o %t.safe.ll
; RUN: %lli %t.safe.ll

; A discarded poison result must not introduce immediate UB. Scalar integer
; and pointer selects use store branches. Float and vector results also exercise
; seed-selected select/PHI handlers with a scalar condition.
@selected.true = global i32 7
@selected.false = global i32 13
@observed.integer = global i32 0
@observed.float = global float 0.0
@observed.pointer = global ptr null
@observed.vector = global <2 x i32> zeroinitializer

define i32 @vm_select_discard() {
entry:
  %integer = select i1 poison, i32 7, i32 13
  %pointer = select i1 poison, ptr @selected.true, ptr @selected.false
  %float = select i1 poison, float 7.0, float 13.0
  %vector = select i1 poison, <2 x i32> <i32 7, i32 11>, <2 x i32> <i32 13, i32 17>
  ret i32 0
}

; Freeze must preserve defined results and keep poison conditions from causing
; immediate UB. Poison results have no prescribed value after freeze.
define i32 @vm_select_freeze(i1 %condition) {
entry:
  %integer = select i1 %condition, i32 poison, i32 7
  %integer.safe = freeze i32 %integer
  store i32 %integer.safe, ptr @observed.integer
  %float = select i1 %condition, float poison, float 13.0
  %float.safe = freeze float %float
  store float %float.safe, ptr @observed.float
  %pointer = select i1 %condition, ptr poison, ptr @selected.true
  %pointer.safe = freeze ptr %pointer
  store ptr %pointer.safe, ptr @observed.pointer
  %vector = select i1 %condition, <2 x i32> poison, <2 x i32> <i32 7, i32 11>
  %vector.safe = freeze <2 x i32> %vector
  store <2 x i32> %vector.safe, ptr @observed.vector
  ret i32 %integer.safe
}

define i32 @vm_select_undef() {
entry:
  %result = select i1 undef, i32 7, i32 13
  ret i32 %result
}

; Both polarities discard poison in the unselected arm, including when that
; poison arrives through another select's VM slot.
define i32 @vm_select_integer(i1 %condition) {
entry:
  %true = select i1 %condition, i32 7, i32 poison
  %false = select i1 %condition, i32 poison, i32 13
  %result = select i1 %condition, i32 %true, i32 %false
  ret i32 %result
}

define float @vm_select_float(i1 %condition) {
entry:
  %true = select i1 %condition, float 7.0, float poison
  %false = select i1 %condition, float poison, float 13.0
  %result = select i1 %condition, float %true, float %false
  ret float %result
}

define ptr @vm_select_pointer(i1 %condition) {
entry:
  %true = select i1 %condition, ptr @selected.true, ptr poison
  %false = select i1 %condition, ptr poison, ptr @selected.false
  %result = select i1 %condition, ptr %true, ptr %false
  ret ptr %result
}

define <2 x i32> @vm_select_scalar_vector(i1 %condition) {
entry:
  %true = select i1 %condition, <2 x i32> <i32 7, i32 11>, <2 x i32> poison
  %false = select i1 %condition, <2 x i32> poison, <2 x i32> <i32 13, i32 17>
  %result = select i1 %condition, <2 x i32> %true, <2 x i32> %false
  ret <2 x i32> %result
}

define <2 x i32> @vm_select_lanes(<2 x i1> %condition) {
entry:
  %result = select <2 x i1> %condition, <2 x i32> <i32 7, i32 11>, <2 x i32> <i32 13, i32 17>
  ret <2 x i32> %result
}

define <2 x float> @vm_select_float_lanes(<2 x float> %lhs, <2 x float> %rhs) {
entry:
  %condition = fcmp olt <2 x float> %lhs, %rhs
  %result = select <2 x i1> %condition, <2 x float> %lhs, <2 x float> %rhs
  ret <2 x float> %result
}

define <2 x i32> @vm_select_lane_poison() {
entry:
  %result = select <2 x i1> <i1 true, i1 false>, <2 x i32> <i32 7, i32 poison>, <2 x i32> <i32 poison, i32 17>
  ret <2 x i32> %result
}

define <2 x i32> @vm_select_lane_undef() {
entry:
  %result = select <2 x i1> <i1 undef, i1 true>, <2 x i32> <i32 7, i32 11>, <2 x i32> <i32 13, i32 17>
  ret <2 x i32> %result
}

define <2 x i32> @vm_select_lane_freeze() {
entry:
  %result = select <2 x i1> <i1 poison, i1 false>, <2 x i32> <i32 7, i32 11>, <2 x i32> <i32 13, i32 17>
  %safe = freeze <2 x i32> %result
  ret <2 x i32> %safe
}

; This mixed scalar/vector program is large enough for helper-sharded handlers.
; Its discarded and frozen selects must also remain safe across island routes.
define i32 @vm_select_island(i32 %x, i32 %y) {
entry:
  %a0 = insertelement <2 x i32> poison, i32 %x, i32 0
  %a = insertelement <2 x i32> %a0, i32 %y, i32 1
  %b = xor <2 x i32> %a, <i32 31, i32 63>
  %mask = icmp slt <2 x i32> %a, %b
  %chosen = select <2 x i1> %mask, <2 x i32> %a, <2 x i32> %b
  %r0 = extractelement <2 x i32> %chosen, i32 0
  %r1 = extractelement <2 x i32> %chosen, i32 1
  %f0 = sitofp i32 %r0 to float
  %f1 = sitofp i32 %r1 to float
  %pick = icmp sgt i32 %r0, %r1
  %float = select i1 %pick, float %f0, float %f1
  %integer = fptosi float %float to i32
  %delta = sub i32 %r0, %r1
  %negative = icmp slt i32 %delta, 0
  %negated = sub i32 0, %delta
  %absolute = select i1 %negative, i32 %negated, i32 %delta
  %sum = add i32 %integer, %absolute
  %other = select i1 %pick, i32 %sum, i32 %delta
  %unused.integer = select i1 poison, i32 %other, i32 %sum
  %unused.float = select i1 poison, float %f0, float %f1
  %unused.vector = select i1 poison, <2 x i32> %a, <2 x i32> %b
  %poison = select <2 x i1> <i1 poison, i1 false>, <2 x i32> %a, <2 x i32> %b
  %safe = freeze <2 x i32> %poison
  %defined.lane = extractelement <2 x i32> %safe, i32 1
  %result = add i32 %other, %defined.lane
  ret i32 %result
}

define i32 @main() {
entry:
  %discard = call i32 @vm_select_discard()
  %discard.ok = icmp eq i32 %discard, 0
  %frozen = call i32 @vm_select_freeze(i1 false)
  %frozen.integer.ok = icmp eq i32 %frozen, 7
  %frozen.float = load float, ptr @observed.float
  %frozen.float.ok = fcmp oeq float %frozen.float, 13.0
  %frozen.pointer = load ptr, ptr @observed.pointer
  %frozen.pointer.ok = icmp eq ptr %frozen.pointer, @selected.true
  %frozen.vector = load <2 x i32>, ptr @observed.vector
  %frozen.vector.compare = icmp eq <2 x i32> %frozen.vector, <i32 7, i32 11>
  %frozen.vector.first.ok = extractelement <2 x i1> %frozen.vector.compare, i32 0
  %frozen.vector.second.ok = extractelement <2 x i1> %frozen.vector.compare, i32 1
  %frozen.ok0 = and i1 %frozen.integer.ok, %frozen.float.ok
  %frozen.ok1 = and i1 %frozen.ok0, %frozen.pointer.ok
  %frozen.ok2 = and i1 %frozen.ok1, %frozen.vector.first.ok
  %frozen.ok = and i1 %frozen.ok2, %frozen.vector.second.ok
  %arbitrary = call i32 @vm_select_freeze(i1 poison)
  store volatile i32 %arbitrary, ptr @observed.integer
  %undef.raw = call i32 @vm_select_undef()
  %undef = freeze i32 %undef.raw
  %undef.true = icmp eq i32 %undef, 7
  %undef.false = icmp eq i32 %undef, 13
  %undef.ok = or i1 %undef.true, %undef.false
  %int.true = call i32 @vm_select_integer(i1 true)
  %int.false = call i32 @vm_select_integer(i1 false)
  %int.true.ok = icmp eq i32 %int.true, 7
  %int.false.ok = icmp eq i32 %int.false, 13
  %float.true = call float @vm_select_float(i1 true)
  %float.false = call float @vm_select_float(i1 false)
  %float.true.ok = fcmp oeq float %float.true, 7.0
  %float.false.ok = fcmp oeq float %float.false, 13.0
  %ptr.true = call ptr @vm_select_pointer(i1 true)
  %ptr.false = call ptr @vm_select_pointer(i1 false)
  %ptr.true.ok = icmp eq ptr %ptr.true, @selected.true
  %ptr.false.ok = icmp eq ptr %ptr.false, @selected.false
  %vec.true = call <2 x i32> @vm_select_scalar_vector(i1 true)
  %vec.false = call <2 x i32> @vm_select_scalar_vector(i1 false)
  %vec.true.ok = icmp eq <2 x i32> %vec.true, <i32 7, i32 11>
  %vec.false.ok = icmp eq <2 x i32> %vec.false, <i32 13, i32 17>
  %lanes.tf = call <2 x i32> @vm_select_lanes(<2 x i1> <i1 true, i1 false>)
  %lanes.ft = call <2 x i32> @vm_select_lanes(<2 x i1> <i1 false, i1 true>)
  %lanes.tt = call <2 x i32> @vm_select_lanes(<2 x i1> <i1 true, i1 true>)
  %lanes.ff = call <2 x i32> @vm_select_lanes(<2 x i1> <i1 false, i1 false>)
  %lanes.tf.ok = icmp eq <2 x i32> %lanes.tf, <i32 7, i32 17>
  %lanes.ft.ok = icmp eq <2 x i32> %lanes.ft, <i32 13, i32 11>
  %lanes.tt.ok = icmp eq <2 x i32> %lanes.tt, <i32 7, i32 11>
  %lanes.ff.ok = icmp eq <2 x i32> %lanes.ff, <i32 13, i32 17>
  %float.lanes = call <2 x float> @vm_select_float_lanes(<2 x float> <float 7.0, float 17.0>, <2 x float> <float 13.0, float 11.0>)
  %float.lanes.ok = fcmp oeq <2 x float> %float.lanes, <float 7.0, float 11.0>
  %float.nan = call <2 x float> @vm_select_float_lanes(<2 x float> <float 0x7FF8000000000000, float 17.0>, <2 x float> <float 13.0, float 11.0>)
  %float.nan.ok = fcmp oeq <2 x float> %float.nan, <float 13.0, float 11.0>
  %lanes.poison = call <2 x i32> @vm_select_lane_poison()
  %lanes.poison.ok = icmp eq <2 x i32> %lanes.poison, <i32 7, i32 17>
  %lanes.undef.raw = call <2 x i32> @vm_select_lane_undef()
  %lanes.undef = freeze <2 x i32> %lanes.undef.raw
  %lanes.undef.first = extractelement <2 x i32> %lanes.undef, i32 0
  %lanes.undef.second = extractelement <2 x i32> %lanes.undef, i32 1
  %lanes.undef.true = icmp eq i32 %lanes.undef.first, 7
  %lanes.undef.false = icmp eq i32 %lanes.undef.first, 13
  %lanes.undef.first.ok = or i1 %lanes.undef.true, %lanes.undef.false
  %lanes.undef.second.ok = icmp eq i32 %lanes.undef.second, 11
  %lanes.frozen = call <2 x i32> @vm_select_lane_freeze()
  %lanes.frozen.second = extractelement <2 x i32> %lanes.frozen, i32 1
  %lanes.frozen.ok = icmp eq i32 %lanes.frozen.second, 17
  %island.0 = call i32 @vm_select_island(i32 5, i32 9)
  %island.1 = call i32 @vm_select_island(i32 40, i32 100)
  %island.2 = call i32 @vm_select_island(i32 -7, i32 -20)
  %island.0.ok = icmp eq i32 %island.0, 50
  %island.1.ok = icmp eq i32 %island.1, 40
  %island.2.ok = icmp eq i32 %island.2, -52
  %vector.ok0 = and <2 x i1> %vec.true.ok, %vec.false.ok
  %vector.ok1 = and <2 x i1> %lanes.tf.ok, %lanes.ft.ok
  %vector.ok2 = and <2 x i1> %lanes.tt.ok, %lanes.ff.ok
  %vector.ok3 = and <2 x i1> %vector.ok0, %vector.ok1
  %vector.ok4 = and <2 x i1> %vector.ok2, %lanes.poison.ok
  %vector.ok5 = and <2 x i1> %vector.ok3, %vector.ok4
  %vector.ok6 = and <2 x i1> %vector.ok5, %float.lanes.ok
  %vector.ok7 = and <2 x i1> %vector.ok6, %float.nan.ok
  %vector.lane0 = extractelement <2 x i1> %vector.ok7, i32 0
  %vector.lane1 = extractelement <2 x i1> %vector.ok7, i32 1
  %ok0 = and i1 %discard.ok, %frozen.ok
  %ok1 = and i1 %ok0, %undef.ok
  %ok2 = and i1 %ok1, %int.true.ok
  %ok3 = and i1 %ok2, %int.false.ok
  %ok4 = and i1 %ok3, %float.true.ok
  %ok5 = and i1 %ok4, %float.false.ok
  %ok6 = and i1 %ok5, %ptr.true.ok
  %ok7 = and i1 %ok6, %ptr.false.ok
  %ok8 = and i1 %ok7, %vector.lane0
  %ok9 = and i1 %ok8, %vector.lane1
  %ok10 = and i1 %ok9, %lanes.undef.first.ok
  %ok11 = and i1 %ok10, %lanes.undef.second.ok
  %ok12 = and i1 %ok11, %lanes.frozen.ok
  %ok13 = and i1 %ok12, %island.0.ok
  %ok14 = and i1 %ok13, %island.1.ok
  %ok15 = and i1 %ok14, %island.2.ok
  %code = select i1 %ok15, i32 0, i32 1
  ret i32 %code
}

; ADMIT-DAG: vm_select_discard|candidate
; ADMIT-DAG: vm_select_freeze|candidate
; ADMIT-DAG: vm_select_undef|candidate
; ADMIT-DAG: vm_select_integer|candidate
; ADMIT-DAG: vm_select_float|candidate
; ADMIT-DAG: vm_select_pointer|candidate
; ADMIT-DAG: vm_select_scalar_vector|candidate
; ADMIT-DAG: vm_select_lanes|candidate
; ADMIT-DAG: vm_select_float_lanes|candidate
; ADMIT-DAG: vm_select_lane_poison|candidate
; ADMIT-DAG: vm_select_lane_undef|candidate
; ADMIT-DAG: vm_select_lane_freeze|candidate
; ADMIT-DAG: vm_select_island|candidate

; VM-DAG: define internal {{.*}} @__obf_vm_i_{{[A-Za-z0-9_]+}}({{.*}}i64 %obf.hidden_token)
; VM-DAG: vm.island.topology.helper_shards
