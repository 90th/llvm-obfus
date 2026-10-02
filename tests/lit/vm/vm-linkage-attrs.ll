; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-linkage-attrs.yaml -passes=obf-vm -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t
; RUN: %opt -passes='default<O2>,verify' -S %t -o %t.optimized
; RUN: %lli %t.optimized

@readonly_data = private global [2 x i32] [i32 7, i32 11], align 4

$attr_hidden = comdat any

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

define weak_odr hidden i32 @attr_hidden(i32 %x) comdat {
entry:
  %value = add i32 %x, 7
  ret i32 %value
}

define i32 @main() {
entry:
  %a = call i32 @attr_readnone(i32 4)
  %b = call i32 @attr_readonly(ptr @readonly_data, i32 1)
  %changed = getelementptr inbounds i32, ptr @readonly_data, i32 1
  store i32 17, ptr %changed, align 4
  %b.changed = call i32 @attr_readonly(ptr @readonly_data, i32 1)
  %c = call i32 @attr_hidden(i32 9)
  %ok.a = icmp eq i32 %a, 17
  %ok.b = icmp eq i32 %b, 20
  %ok.b.changed = icmp eq i32 %b.changed, 26
  %ok.c = icmp eq i32 %c, 16
  %ok.ab = and i1 %ok.a, %ok.b
  %ok.abc = and i1 %ok.ab, %ok.c
  %ok = and i1 %ok.abc, %ok.b.changed
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

attributes #0 = { mustprogress nofree norecurse nosync willreturn memory(none) }
attributes #1 = { mustprogress nofree norecurse nosync willreturn memory(read) }
