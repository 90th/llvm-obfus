; RUN: %lli %s

@__obf_entropy_anchor = external global i64, align 8

define i32 @main() {
entry:
  %value = load i64, ptr @__obf_entropy_anchor
  %ok = icmp ne i64 %value, 0
  %result = select i1 %ok, i32 0, i32 1
  ret i32 %result
}
