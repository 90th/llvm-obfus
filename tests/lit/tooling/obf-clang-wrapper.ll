; RUN: %obf_clangxx -### --obf-config=%S/../Inputs/obf-clang-wrapper.yaml -I%obf_build_include %S/../Inputs/obf-clang-wrapper.cpp -o %t.exe 2>&1 | %FileCheck %s --check-prefix=DRY
; RUN: %obf_clangxx -### -c --obf-config=%S/../Inputs/obf-clang-wrapper.yaml -I%obf_build_include %S/../Inputs/obf-clang-wrapper.cpp -o %t.o 2>&1 | %FileCheck %s --check-prefix=COMPILEONLY
; RUN: %obf_clangxx --obf-config=%S/../Inputs/obf-clang-wrapper.yaml -I%obf_build_include %S/../Inputs/obf-clang-wrapper.cpp -o %t.exe
; RUN: %t.exe
; RUN: %python -c "import importlib.machinery; import importlib.util; loader = importlib.machinery.SourceFileLoader('obf_clang', r'%obf_clang'); spec = importlib.util.spec_from_loader(loader.name, loader); module = importlib.util.module_from_spec(spec); loader.exec_module(module); args = ['-flto']; module._inject_windows_lto_linker(args, True); assert args == ['-flto', '-fuse-ld=lld-link']; args = ['-flto=thin']; module._inject_windows_lto_linker(args, True, False); assert args == ['-flto=thin', '-fuse-ld=lld']"
;
; DRY: -fpass-plugin=
; DRY: libobf_runtime.a
; COMPILEONLY: -fpass-plugin=
; COMPILEONLY-NOT: libobf_runtime.a

define void @dummy() {
entry:
  ret void
}
