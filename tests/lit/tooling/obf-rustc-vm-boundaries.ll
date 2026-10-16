; RUN: %opt -passes=verify -disable-output %s
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/obf-rustc-vm-boundary-rust-target.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=NON-C
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/obf-rustc-vm-boundary-rust-override.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=LOCAL-EH
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/obf-rustc-vm-boundary-zig-target.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=NON-C
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/obf-rustc-vm-boundary-zig-override.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=LOCAL-EH
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/obf-rustc-vm-boundary-tinygo-target.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=TINYGO
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/obf-rustc-vm-boundary-tinygo-override.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=TINYGO
;
; Both selectors resolve aliases before they check the implementation boundary.
; VM requests cannot silently become native code because of local EH or a non-C ABI.
;
; NON-C: LLVM ERROR: config error: non-generic frontend configured VM function 'non_c_export' must use the C calling convention
; LOCAL-EH: LLVM ERROR: config error: non-generic frontend configured VM function 'local_eh_export' must not contain local exception handling
; TINYGO: LLVM ERROR: config error: non-generic frontend entries must use light or strong

@non_c_export = alias i32 (i32), ptr @non_c_target
@local_eh_export = alias i32 (i32), ptr @local_eh_target

declare i32 @__gxx_personality_v0(...)
declare i32 @may_throw(i32)

define internal fastcc i32 @non_c_target(i32 %value) {
entry:
  %result = add i32 %value, 7
  ret i32 %result
}

define internal i32 @local_eh_target(i32 %value) personality ptr @__gxx_personality_v0 {
entry:
  %result = invoke i32 @may_throw(i32 %value) to label %normal unwind label %cleanup
normal:
  ret i32 %result
cleanup:
  %exception = landingpad { ptr, i32 } cleanup
  resume { ptr, i32 } %exception
}

define i32 @plain_c(i32 %value) {
entry:
  %result = xor i32 %value, 85
  ret i32 %result
}
