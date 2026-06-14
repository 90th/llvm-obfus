; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-linkage-attrs.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-linkage-attrs.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

@readonly_data = private constant [2 x i32] [i32 7, i32 11], align 4

define i32 @attr_readnone(i32 %x) #0 {
entry:
  %mul = mul nsw i32 %x, 3
  %sum = add nsw i32 %mul, 5
  ret i32 %sum
}

define i32 @attr_readonly(ptr %base, i32 %index) #1 {
entry:
  %ptr = getelementptr inbounds i32, ptr %base, i32 %index
  %value = load i32, ptr %ptr, align 4
  %sum = add nsw i32 %value, 9
  ret i32 %sum
}

define i32 @main() {
entry:
  %a = call i32 @attr_readnone(i32 4)
  %b = call i32 @attr_readonly(ptr @readonly_data, i32 1)
  %ok.a = icmp eq i32 %a, 17
  %ok.b = icmp eq i32 %b, 20
  %ok = and i1 %ok.a, %ok.b
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

attributes #0 = { mustprogress nofree norecurse nosync willreturn memory(none) }
attributes #1 = { mustprogress nofree norecurse nosync willreturn memory(read) }

; CHECK-NOT: memory(none)
; CHECK-NOT: memory(read)
; CHECK-NOT: willreturn
; CHECK-NOT: nosync
; CHECK-NOT: nofree
; CHECK-NOT: norecurse
; CHECK-NOT: mustprogress

; CHECK-LABEL: define i32 @attr_readnone(i32 %x) {
; CHECK: %attr_readnone.obf.wrapper.call{{[0-9]*}} = call i32 %attr_readnone.obf.wrapper.indirect(i32 %x, i64 %attr_readnone.obf.wrapper.token)

; CHECK-LABEL: define i32 @attr_readonly(ptr %base, i32 %index) {
; CHECK: %attr_readonly.obf.wrapper.call{{[0-9]*}} = call i32 %attr_readonly.obf.wrapper.indirect(ptr %base, i32 %index, i64 %attr_readonly.obf.wrapper.token)

; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; CHECK-SAME: #[[IMPL:[0-9]+]] {
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(ptr %base, i32 %index, i64 %obf.hidden_token)
; CHECK-SAME: #[[IMPL2:[0-9]+]] {
; CHECK-DAG: attributes #[[IMPL]] = { {{.*}}noinline{{.*}}"instcombine-no-verify-fixpoint"{{.*}} }
; CHECK-DAG: attributes #[[IMPL2]] = { {{.*}}noinline{{.*}}"instcombine-no-verify-fixpoint"{{.*}} }
