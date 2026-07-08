; RUN: %obf_clangxx -### --obf-config=%S/../Inputs/obf-clang-wrapper.yaml -I%obf_build_include %S/../Inputs/obf-clang-wrapper.cpp -o %t.exe 2>&1 | %FileCheck %s --check-prefix=DRY
; RUN: %obf_clangxx -### -c --obf-config=%S/../Inputs/obf-clang-wrapper.yaml -I%obf_build_include %S/../Inputs/obf-clang-wrapper.cpp -o %t.o 2>&1 | %FileCheck %s --check-prefix=COMPILEONLY
; RUN: %obf_clangxx --obf-config=%S/../Inputs/obf-clang-wrapper.yaml -I%obf_build_include %S/../Inputs/obf-clang-wrapper.cpp -o %t.exe
; RUN: %t.exe
;
; DRY: -fpass-plugin=
; DRY: libobf_runtime.a
; COMPILEONLY: -fpass-plugin=
; COMPILEONLY-NOT: libobf_runtime.a

define void @dummy() {
entry:
  ret void
}
