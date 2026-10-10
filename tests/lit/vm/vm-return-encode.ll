; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-return-encode.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
;
; Check consumer-visible return values for i1, i32, and i64 VM functions.

define i32 @encode_i32(i32 %x) {
entry:
  %r = add i32 %x, 100
  ret i32 %r
}

define i1 @encode_i1(i32 %x) {
entry:
  %cmp = icmp sgt i32 %x, 42
  ret i1 %cmp
}

define i64 @encode_i64(i64 %x) {
entry:
  %r = xor i64 %x, 1234567890123456789
  ret i64 %r
}

define i32 @main() {
entry:
  %v32 = call i32 @encode_i32(i32 5)
  %ok1 = icmp eq i32 %v32, 105

  %v1 = call i1 @encode_i1(i32 100)

  %v64 = call i64 @encode_i64(i64 0)
  %ok3 = icmp eq i64 %v64, 1234567890123456789

  %ok12 = and i1 %ok1, %v1
  %ok = and i1 %ok12, %ok3
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

