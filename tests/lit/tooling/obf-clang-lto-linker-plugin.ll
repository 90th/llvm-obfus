; UNSUPPORTED: system-windows
;
; Compile with %raw_clang so any obfuscation visible in the saved LTO temps must
; come from the linker-driven LTO backend, not from the frontend pipeline.
; Full LTO links at -O0 to cover the full-LTO post-link extension point.
; ThinLTO links at -O2 to cover the ThinLTO optimizer-last extension point.
; This fixture requires ld.lld and llvm-dis; the first RUN line records ld.lld in
; %t.have_lld when both are available.
;
; RUN: rm -f %t.have_lld && LD_LLD=$(%raw_clang -print-prog-name=ld.lld) && LLVM_DIS=$(dirname %opt)/llvm-dis && if [ ! -x "$LD_LLD" ]; then LD_LLD=$(command -v "$LD_LLD" 2>/dev/null || true); fi && if [ ! -x "$LLVM_DIS" ]; then LLVM_DIS=$(command -v llvm-dis 2>/dev/null || true); fi && if [ -x "$LD_LLD" ] && [ -x "$LLVM_DIS" ]; then printf '%s\n' "$LD_LLD" > %t.have_lld; else echo "SKIP: requires ld.lld and llvm-dis"; fi
;
; RUN: if test -f %t.have_lld; then LD_LLD=$(cat %t.have_lld); timeout 120 %raw_clang -O0 -flto=full -c %S/../Inputs/tooling-lto-linker-plugin.c -o %t.full.o && OBF_CONFIG=%S/../Inputs/tooling-lto-linker-plugin.yaml timeout 120 %raw_clang -O0 -flto=full -fuse-ld="$LD_LLD" -Wl,--load-pass-plugin=%obf_plugin -Wl,--save-temps %t.full.o %obf_runtime -o %t.full.exe; fi
; RUN: if test -f %t.have_lld; then LLVM_DIS=$(dirname %opt)/llvm-dis && if [ ! -x "$LLVM_DIS" ]; then LLVM_DIS=$(command -v llvm-dis 2>/dev/null || true); fi && "$LLVM_DIS" %t.full.exe.0.0.preopt.bc -o - | %FileCheck %s --check-prefix=PREOPT; fi
; RUN: if test -f %t.have_lld; then LLVM_DIS=$(dirname %opt)/llvm-dis && if [ ! -x "$LLVM_DIS" ]; then LLVM_DIS=$(command -v llvm-dis 2>/dev/null || true); fi && "$LLVM_DIS" %t.full.exe.0.4.opt.bc -o - | %FileCheck %s --check-prefix=LTO-IR; fi
; RUN: if test -f %t.have_lld; then %t.full.exe | %FileCheck %s --check-prefix=RESULT; fi
;
; RUN: if test -f %t.have_lld; then LD_LLD=$(cat %t.have_lld); timeout 120 %raw_clang -O0 -flto=thin -c %S/../Inputs/tooling-lto-linker-plugin.c -o %t.thin.o && OBF_CONFIG=%S/../Inputs/tooling-lto-linker-plugin.yaml timeout 120 %raw_clang -O2 -flto=thin -fuse-ld="$LD_LLD" -Wl,--load-pass-plugin=%obf_plugin -Wl,--save-temps %t.thin.o %obf_runtime -o %t.thin.exe; fi
; RUN: if test -f %t.have_lld; then LLVM_DIS=$(dirname %opt)/llvm-dis && if [ ! -x "$LLVM_DIS" ]; then LLVM_DIS=$(command -v llvm-dis 2>/dev/null || true); fi && "$LLVM_DIS" %t.thin.o.0.preopt.bc -o - | %FileCheck %s --check-prefix=PREOPT; fi
; RUN: if test -f %t.have_lld; then LLVM_DIS=$(dirname %opt)/llvm-dis && if [ ! -x "$LLVM_DIS" ]; then LLVM_DIS=$(command -v llvm-dis 2>/dev/null || true); fi && "$LLVM_DIS" %t.thin.o.4.opt.bc -o - | %FileCheck %s --check-prefix=LTO-IR; fi
; RUN: if test -f %t.have_lld; then %t.thin.exe | %FileCheck %s --check-prefix=RESULT; fi
;
; PREOPT: @.str = private unnamed_addr constant [20 x i8] c"lto-linkonly-secret\00"
; PREOPT: define internal i32 @checksum(ptr
; PREOPT: define internal i32 @fold(i32
;
; LTO-IR: @rt_core_ea = external{{.*}}global i64
; LTO-IR-NOT: c"lto-linkonly-secret\00"
; LTO-IR: define dso_local{{.*}} @main(
;
; RESULT: link-lto consistent=1 value=4723

define void @dummy() {
entry:
  ret void
}
