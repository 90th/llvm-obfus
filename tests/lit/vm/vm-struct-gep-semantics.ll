; RUN: %lli %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-struct-gep-semantics.yaml -passes='obf-vm,verify' -S %s -o %t.vm.ll
; RUN: %FileCheck %s --check-prefix=VM < %t.vm.ll
; RUN: %lli %t.vm.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-struct-gep-semantics.yaml --obf-seed=17 -passes='obf-vm,verify' -S %s -o %t.seed17.ll
; RUN: %FileCheck %s --check-prefix=VM < %t.seed17.ll
; RUN: %lli %t.seed17.ll
; RUN: %opt -passes='default<O2>,verify' -S %t.vm.ll -o %t.o2.ll
; RUN: %lli %t.o2.ll
;
; Lower the original GEP instructions before any optimization. In particular,
; struct fields 2 and later must stay constant even when intervening pointer,
; array and vector indices are dynamically materialized by the VM.
; Return values and complete selected records/lanes are checked independently;
; guard fields and neighboring elements detect stores to the wrong address.

target datalayout = "e-p:64:64-p1:64:64-i64:64-v128:128-n8:16:32:64-S128"

%Record = type { i64, i64, i64, i64 }
%Leaf = type { i8, i16, [4 x i64], i64 }
%Node = type { i32, i64, [3 x %Leaf], <4 x i32> }
%Root = type { i8, [2 x i32], [2 x %Node], i64 }
%Packed = type <{ i8, i16, i64, [3 x %Leaf], i32 }>

@records = internal global [3 x %Record] [
  %Record { i64 1, i64 2, i64 30, i64 40 },
  %Record { i64 3, i64 4, i64 50, i64 60 },
  %Record { i64 5, i64 6, i64 70, i64 80 }
], align 8
@nested = internal global %Root zeroinitializer, align 16
@packed = internal global %Packed <{
  i8 11, i16 22, i64 9001,
  [3 x %Leaf] [
    %Leaf zeroinitializer,
    %Leaf { i8 7, i16 9, [4 x i64] [i64 1, i64 2, i64 777, i64 4], i64 100 },
    %Leaf zeroinitializer
  ],
  i32 123
}>, align 1
@vectors = internal global [2 x %Node] [
  %Node { i32 1, i64 2, [3 x %Leaf] zeroinitializer, <4 x i32> <i32 10, i32 20, i32 30, i32 40> },
  %Node { i32 3, i64 4, [3 x %Leaf] zeroinitializer, <4 x i32> <i32 100, i32 200, i32 300, i32 400> }
], align 16
@as.records = internal addrspace(1) global [2 x %Record] [
  %Record { i64 1, i64 2, i64 10, i64 20 },
  %Record { i64 7, i64 8, i64 130, i64 140 }
], align 8

; The source type is a struct, but the first index is still a sequential step.
; Both the dynamic record index and constant pointer index 2 must stay eligible
; for ordinary VM encoding, unlike the field selectors 2 and 3.
define i64 @struct_fields(ptr %base, i64 %record, i64 %delta) {
entry:
  %third = getelementptr inbounds %Record, ptr %base, i64 %record, i32 2
  %fourth = getelementptr %Record, ptr %base, i64 %record, i32 3
  %guard = getelementptr %Record, ptr %base, i64 2, i32 2
  %old.third = load i64, ptr %third, align 8
  %old.fourth = load i64, ptr %fourth, align 8
  %guard.value = load i64, ptr %guard, align 8
  %new.third = add i64 %old.third, %delta
  %new.fourth = xor i64 %old.fourth, %delta
  store i64 %new.third, ptr %third, align 8
  store i64 %new.fourth, ptr %fourth, align 8
  %fields = add i64 %new.third, %new.fourth
  %result = add i64 %fields, %guard.value
  ret i64 %result
}

; Three struct selectors alternate with three dynamic array indices.
define i64 @nested_fields(ptr %base, i64 %node, i32 %leaf, i64 %element, i64 %delta) {
entry:
  %selected = getelementptr inbounds %Root, ptr %base, i64 0, i32 2, i64 %node, i32 2, i32 %leaf, i32 2, i64 %element
  %tail = getelementptr %Root, ptr %base, i64 0, i32 2, i64 %node, i32 2, i32 %leaf, i32 3
  %old = load i64, ptr %selected, align 8
  %old.tail = load i64, ptr %tail, align 8
  %new = add i64 %old, %delta
  %new.tail = add i64 %old.tail, 1
  store i64 %new, ptr %selected, align 8
  store i64 %new.tail, ptr %tail, align 8
  %result = add i64 %new, %new.tail
  ret i64 %result
}

; Unaligned fields and the fifth field of a packed struct need the same rule.
define i64 @packed_fields(ptr %base, i32 %leaf, i64 %element, i64 %delta) {
entry:
  %third = getelementptr %Packed, ptr %base, i64 0, i32 2
  %fifth = getelementptr inbounds %Packed, ptr %base, i64 0, i32 4
  %selected = getelementptr %Packed, ptr %base, i64 0, i32 3, i32 %leaf, i32 2, i64 %element
  %old.third = load i64, ptr %third, align 1
  %old.fifth = load i32, ptr %fifth, align 1
  %old.element = load i64, ptr %selected, align 1
  %new.third = add i64 %old.third, %delta
  %delta32 = trunc i64 %delta to i32
  %new.fifth = add i32 %old.fifth, %delta32
  %new.element = xor i64 %old.element, %delta
  store i64 %new.third, ptr %third, align 1
  store i32 %new.fifth, ptr %fifth, align 1
  store i64 %new.element, ptr %selected, align 1
  %wide.fifth = zext i32 %new.fifth to i64
  %fields = add i64 %new.third, %wide.fifth
  %result = add i64 %fields, %new.element
  ret i64 %result
}

; A vector lane is a sequential index even after selecting a struct field.
define i32 @vector_fields(ptr %base, i64 %record, i32 %lane, i32 %delta) {
entry:
  %selected = getelementptr inbounds %Node, ptr %base, i64 %record, i32 3, i32 %lane
  %last = getelementptr %Node, ptr %base, i64 %record, i32 3, i64 3
  %old = load i32, ptr %selected, align 4
  %old.last = load i32, ptr %last, align 4
  %new = add i32 %old, %delta
  %new.last = xor i32 %old.last, %delta
  store i32 %new, ptr %selected, align 4
  store i32 %new.last, ptr %last, align 4
  %result = add i32 %new, %new.last
  ret i32 %result
}

; Reconstruct the GEP in its original address space, for both GEP forms.
define i64 @addrspace_fields(ptr addrspace(1) %base, i64 %record, i64 %delta) {
entry:
  %third = getelementptr inbounds %Record, ptr addrspace(1) %base, i64 %record, i32 2
  %fourth = getelementptr %Record, ptr addrspace(1) %base, i64 %record, i32 3
  %old.third = load i64, ptr addrspace(1) %third, align 8
  %old.fourth = load i64, ptr addrspace(1) %fourth, align 8
  %new.third = add i64 %old.third, %delta
  %new.fourth = add i64 %old.fourth, %delta
  store i64 %new.third, ptr addrspace(1) %third, align 8
  store i64 %new.fourth, ptr addrspace(1) %fourth, align 8
  %result = add i64 %new.third, %new.fourth
  ret i64 %result
}

; These consumer-side oracles are intentionally not selected for VM lowering.
define internal i1 @record_matches(%Record %value, i64 %a, i64 %b, i64 %c, i64 %d) {
entry:
  %first = extractvalue %Record %value, 0
  %second = extractvalue %Record %value, 1
  %third = extractvalue %Record %value, 2
  %fourth = extractvalue %Record %value, 3
  %ok.first = icmp eq i64 %first, %a
  %ok.second = icmp eq i64 %second, %b
  %ok.third = icmp eq i64 %third, %c
  %ok.fourth = icmp eq i64 %fourth, %d
  %ok.ab = and i1 %ok.first, %ok.second
  %ok.cd = and i1 %ok.third, %ok.fourth
  %ok = and i1 %ok.ab, %ok.cd
  ret i1 %ok
}

define internal i1 @leaf_matches(%Leaf %value, i64 %element, i64 %tail) {
entry:
  %first = extractvalue %Leaf %value, 0
  %second = extractvalue %Leaf %value, 1
  %lane0 = extractvalue %Leaf %value, 2, 0
  %lane1 = extractvalue %Leaf %value, 2, 1
  %lane2 = extractvalue %Leaf %value, 2, 2
  %lane3 = extractvalue %Leaf %value, 2, 3
  %last = extractvalue %Leaf %value, 3
  %ok.first = icmp eq i8 %first, 7
  %ok.second = icmp eq i16 %second, 9
  %ok.lane0 = icmp eq i64 %lane0, 1
  %ok.lane1 = icmp eq i64 %lane1, 2
  %ok.lane2 = icmp eq i64 %lane2, %element
  %ok.lane3 = icmp eq i64 %lane3, 4
  %ok.last = icmp eq i64 %last, %tail
  %ok.header = and i1 %ok.first, %ok.second
  %ok.low = and i1 %ok.lane0, %ok.lane1
  %ok.high = and i1 %ok.lane2, %ok.lane3
  %ok.lanes = and i1 %ok.low, %ok.high
  %ok.body = and i1 %ok.lanes, %ok.last
  %ok = and i1 %ok.header, %ok.body
  ret i1 %ok
}

define i32 @main() {
entry:
  %nested.leaf = getelementptr inbounds %Root, ptr @nested, i64 0, i32 2, i64 1, i32 2, i64 2
  store %Leaf { i8 7, i16 9, [4 x i64] [i64 1, i64 2, i64 30, i64 4], i64 100 }, ptr %nested.leaf, align 8
  %nested.tail = getelementptr inbounds %Root, ptr @nested, i64 0, i32 3
  store i64 1234, ptr %nested.tail, align 8

  %record0.result = call i64 @struct_fields(ptr @records, i64 0, i64 7)
  %record1.result = call i64 @struct_fields(ptr @records, i64 1, i64 11)
  %nested.result = call i64 @nested_fields(ptr @nested, i64 1, i32 2, i64 2, i64 13)
  %packed.result = call i64 @packed_fields(ptr @packed, i32 1, i64 2, i64 5)
  %vector.result = call i32 @vector_fields(ptr @vectors, i64 1, i32 2, i32 17)
  %as.result = call i64 @addrspace_fields(ptr addrspace(1) @as.records, i64 1, i64 9)
  %ok.record0.result = icmp eq i64 %record0.result, 154
  %ok.record1.result = icmp eq i64 %record1.result, 186
  %ok.nested.result = icmp eq i64 %nested.result, 144
  %ok.packed.result = icmp eq i64 %packed.result, 9914
  %ok.vector.result = icmp eq i32 %vector.result, 702
  %ok.as.result = icmp eq i64 %as.result, 288

  %records.value = load [3 x %Record], ptr @records, align 8
  %record0 = extractvalue [3 x %Record] %records.value, 0
  %record1 = extractvalue [3 x %Record] %records.value, 1
  %record2 = extractvalue [3 x %Record] %records.value, 2
  %ok.record0 = call i1 @record_matches(%Record %record0, i64 1, i64 2, i64 37, i64 47)
  %ok.record1 = call i1 @record_matches(%Record %record1, i64 3, i64 4, i64 61, i64 55)
  %ok.record2 = call i1 @record_matches(%Record %record2, i64 5, i64 6, i64 70, i64 80)

  %nested.value = load %Root, ptr @nested, align 16
  %leaf.value = extractvalue %Root %nested.value, 2, 1, 2, 2
  %other.node = extractvalue %Root %nested.value, 2, 0, 2, 2, 2, 2
  %other.leaf = extractvalue %Root %nested.value, 2, 1, 2, 1, 2, 2
  %root.tail = extractvalue %Root %nested.value, 3
  %ok.leaf = call i1 @leaf_matches(%Leaf %leaf.value, i64 43, i64 101)
  %ok.other.node = icmp eq i64 %other.node, 0
  %ok.other.leaf = icmp eq i64 %other.leaf, 0
  %ok.root.tail = icmp eq i64 %root.tail, 1234

  %packed.value = load %Packed, ptr @packed, align 1
  %packed.first = extractvalue %Packed %packed.value, 0
  %packed.second = extractvalue %Packed %packed.value, 1
  %packed.third = extractvalue %Packed %packed.value, 2
  %packed.leaf = extractvalue %Packed %packed.value, 3, 1
  %packed.guard = extractvalue %Packed %packed.value, 3, 0, 2, 2
  %packed.fifth = extractvalue %Packed %packed.value, 4
  %ok.packed.first = icmp eq i8 %packed.first, 11
  %ok.packed.second = icmp eq i16 %packed.second, 22
  %ok.packed.third = icmp eq i64 %packed.third, 9006
  %ok.packed.leaf = call i1 @leaf_matches(%Leaf %packed.leaf, i64 780, i64 100)
  %ok.packed.guard = icmp eq i64 %packed.guard, 0
  %ok.packed.fifth = icmp eq i32 %packed.fifth, 128

  %vectors.value = load [2 x %Node], ptr @vectors, align 16
  %vector0 = extractvalue [2 x %Node] %vectors.value, 0, 3
  %vector1 = extractvalue [2 x %Node] %vectors.value, 1, 3
  %ok.vector0.lanes = icmp eq <4 x i32> %vector0, <i32 10, i32 20, i32 30, i32 40>
  %ok.vector1.lanes = icmp eq <4 x i32> %vector1, <i32 100, i32 200, i32 317, i32 385>
  %ok.vector.lanes = and <4 x i1> %ok.vector0.lanes, %ok.vector1.lanes
  %ok.vector.bits = bitcast <4 x i1> %ok.vector.lanes to i4
  %ok.vectors = icmp eq i4 %ok.vector.bits, -1

  %as.value = load [2 x %Record], ptr addrspace(1) @as.records, align 8
  %as.record0 = extractvalue [2 x %Record] %as.value, 0
  %as.record1 = extractvalue [2 x %Record] %as.value, 1
  %ok.as.record0 = call i1 @record_matches(%Record %as.record0, i64 1, i64 2, i64 10, i64 20)
  %ok.as.record1 = call i1 @record_matches(%Record %as.record1, i64 7, i64 8, i64 139, i64 149)

  %ok0 = and i1 %ok.record0.result, %ok.record1.result
  %ok1 = and i1 %ok0, %ok.nested.result
  %ok2 = and i1 %ok1, %ok.packed.result
  %ok3 = and i1 %ok2, %ok.vector.result
  %ok4 = and i1 %ok3, %ok.as.result
  %ok5 = and i1 %ok4, %ok.record0
  %ok6 = and i1 %ok5, %ok.record1
  %ok7 = and i1 %ok6, %ok.record2
  %ok8 = and i1 %ok7, %ok.leaf
  %ok9 = and i1 %ok8, %ok.other.node
  %ok10 = and i1 %ok9, %ok.other.leaf
  %ok11 = and i1 %ok10, %ok.root.tail
  %ok12 = and i1 %ok11, %ok.packed.first
  %ok13 = and i1 %ok12, %ok.packed.second
  %ok14 = and i1 %ok13, %ok.packed.third
  %ok15 = and i1 %ok14, %ok.packed.leaf
  %ok16 = and i1 %ok15, %ok.packed.guard
  %ok17 = and i1 %ok16, %ok.packed.fifth
  %ok18 = and i1 %ok17, %ok.vectors
  %ok19 = and i1 %ok18, %ok.as.record0
  %ok = and i1 %ok19, %ok.as.record1
  %result = select i1 %ok, i32 0, i32 1
  ret i32 %result
}

; Require emitted protection, not a silently skipped candidate. The helper name
; suffix and direct/indirect call choice are deliberately not pinned.
; VM-LABEL: define i64 @struct_fields(ptr %base, i64 %record, i64 %delta)
; VM: call i64 {{(@__obf_vm_[ie]_[A-Za-z0-9_]+|%[A-Za-z0-9$._-]+)}}(ptr %base, i64 %record, i64 %delta, i64 {{[^)]+}})
; VM: ret i64
; VM-LABEL: define i64 @nested_fields(ptr %base, i64 %node, i32 %leaf, i64 %element, i64 %delta)
; VM: call i64 {{(@__obf_vm_[ie]_[A-Za-z0-9_]+|%[A-Za-z0-9$._-]+)}}(ptr %base, i64 %node, i32 %leaf, i64 %element, i64 %delta, i64 {{[^)]+}})
; VM: ret i64
; VM-LABEL: define i64 @packed_fields(ptr %base, i32 %leaf, i64 %element, i64 %delta)
; VM: call i64 {{(@__obf_vm_[ie]_[A-Za-z0-9_]+|%[A-Za-z0-9$._-]+)}}(ptr %base, i32 %leaf, i64 %element, i64 %delta, i64 {{[^)]+}})
; VM: ret i64
; VM-LABEL: define i32 @vector_fields(ptr %base, i64 %record, i32 %lane, i32 %delta)
; VM: call i32 {{(@__obf_vm_[ie]_[A-Za-z0-9_]+|%[A-Za-z0-9$._-]+)}}(ptr %base, i64 %record, i32 %lane, i32 %delta, i64 {{[^)]+}})
; VM: ret i32
; VM-LABEL: define i64 @addrspace_fields(ptr addrspace(1) %base, i64 %record, i64 %delta)
; VM: call i64 {{(@__obf_vm_[ie]_[A-Za-z0-9_]+|%[A-Za-z0-9$._-]+)}}(ptr addrspace(1) %base, i64 %record, i64 %delta, i64 {{[^)]+}})
; VM: ret i64
