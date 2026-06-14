; RUN: %lli %s

@rt_core_ea = external global i64, align 8

define i32 @main() {
entry:
  %value = load i64, ptr @rt_core_ea
  %ok = icmp ne i64 %value, 0
  %result = select i1 %ok, i32 0, i32 1
  ret i32 %result
}
