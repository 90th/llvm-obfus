; REQUIRES: system-linux
; RUN: %raw_clang -O0 -flto=thin -c %S/../Inputs/lto-protection-target.c -o %t.absent.o
; RUN: %raw_clang -O0 -flto=thin -c -x ir %S/../Inputs/tooling-lto-dependent-libraries-empty.ir -o %t.empty.o
; RUN: %raw_clang -O0 -flto=thin -c -x ir %S/../Inputs/tooling-lto-dependent-libraries.ir -o %t.dependent.o
; RUN: %llvm_ar rcs %t.empty.a %t.empty.o
; RUN: %llvm_ar rcs %t.dependent.a %t.dependent.o
; RUN: %obf_driver --quiet --config=%S/../Inputs/lto-protection-config.yaml --validate-lto-input=%t.absent.o
; RUN: %obf_driver --quiet --config=%S/../Inputs/lto-protection-config.yaml --validate-lto-input=%t.empty.o
; RUN: %obf_driver --quiet --config=%S/../Inputs/lto-protection-config.yaml --validate-lto-input=%t.empty.a
; RUN: not %obf_driver --quiet --config=%S/../Inputs/lto-protection-config.yaml --validate-lto-input=%t.dependent.o 2>&1 | %FileCheck %s --check-prefix=DIRECT
; RUN: not %obf_driver --quiet --config=%S/../Inputs/lto-protection-config.yaml --validate-lto-input=%t.dependent.a 2>&1 | %FileCheck %s --check-prefix=ARCHIVE
;
; DIRECT: unsupported implicit dependent-library input metadata llvm.dependent-libraries in {{.*}}dependent.o; pass the library closure explicitly
; ARCHIVE: unsupported implicit dependent-library input metadata llvm.dependent-libraries in {{.*}}dependent.a({{.*}}dependent.o); pass the library closure explicitly

define void @dummy() {
entry:
  ret void
}
