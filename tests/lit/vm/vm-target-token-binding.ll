; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-target-token-binding.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @token_bound_normal(i32 %x) {
entry:
  %mul = mul i32 %x, 3
  %sum = add i32 %mul, 4
  ret i32 %sum
}

define i32 @token_bound_strong(i32 %x) {
entry:
  %xor = xor i32 %x, 19
  %sum = add i32 %xor, 8
  ret i32 %sum
}

define i32 @normal_site_a() {
entry:
  %normal = call i32 @token_bound_normal(i32 9)
  ret i32 %normal
}

define i32 @main() {
entry:
  %normal = call i32 @token_bound_normal(i32 7)
  %strong = call i32 @token_bound_strong(i32 12)
  %via.caller = call i32 @normal_site_a()
  %normal.ok = icmp eq i32 %normal, 25
  %strong.ok = icmp eq i32 %strong, 39
  %caller.ok = icmp eq i32 %via.caller, 31
  %normal.and = and i1 %normal.ok, %strong.ok
  %ok = and i1 %normal.and, %caller.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
