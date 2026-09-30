; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/lto-protection-config.yaml -passes='lto<O0>,verify' -S %s -o %t
; RUN: %lli %t

define i32 @protected_calc(i32 %value) optdebug {
entry:
  %slot = alloca i32
  store i32 %value, ptr %slot
  %loaded = load i32, ptr %slot
  %mixed = xor i32 %loaded, 23130
  %offset = add i32 %mixed, 17
  %result = mul i32 %offset, 3
  ret i32 %result
}

define i32 @main() {
entry:
  %result = call i32 @protected_calc(i32 1)
  %ok = icmp eq i32 %result, 69444
  %failed = xor i1 %ok, true
  %status = zext i1 %failed to i32
  ret i32 %status
}
