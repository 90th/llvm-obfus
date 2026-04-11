@.obf.strong = private unnamed_addr constant [11 x i8] c"obf:strong\00", section "llvm.metadata"
@.sample.file = private unnamed_addr constant [10 x i8] c"sample.ll\00", section "llvm.metadata"
@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }] [{ ptr, ptr, ptr, i32, ptr } { ptr @add, ptr @.obf.strong, ptr @.sample.file, i32 1, ptr null }], section "llvm.metadata"

@.str = private unnamed_addr constant [6 x i8] c"hello\00"

declare i32 @puts(ptr)

define i32 @add(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  ret i32 %sum
}

define i32 @main() {
entry:
  %call = call i32 @puts(ptr @.str)
  ret i32 0
}
