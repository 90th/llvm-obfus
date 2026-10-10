; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-resolver-shapes.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @normal_vm_value(i32 %x) {
entry:
  %mul = mul i32 %x, 2
  %sum = add i32 %mul, 7
  ret i32 %sum
}

define i32 @strong_vm_value(i32 %x) {
entry:
  %xor = xor i32 %x, 85
  %sum = add i32 %xor, 3
  ret i32 %sum
}

define i32 @main() {
entry:
  %normal = call i32 @normal_vm_value(i32 10)
  %strong = call i32 @strong_vm_value(i32 12)
  %normal.ok = icmp eq i32 %normal, 27
  %strong.ok = icmp eq i32 %strong, 92
  %ok = and i1 %normal.ok, %strong.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

