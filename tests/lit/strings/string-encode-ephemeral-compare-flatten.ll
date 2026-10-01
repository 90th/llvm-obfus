; Definition-site CFG state must survive the comparison's split blocks, original
; PHI edges, diamonds, and loop backedges. Each protected comparison rejects a
; zero expected state at runtime, so skipped flattening plus placeholder cleanup
; cannot satisfy this test. The libc oracle remains outside the selected target.
;
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml --obf-seed=1 -passes='obf-string-encode,obf-control-flatten,obf-cfg-state-cleanup,verify' -S %s -o %t.ll
; RUN: %lli %t.ll
; RUN: %raw_clang -O0 %t.ll %obf_runtime -o %t.exe
; RUN: %t.exe
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml --obf-seed=7 -passes='obf-string-encode,obf-control-flatten,obf-cfg-state-cleanup,verify' -S %s -o %t.other.ll
; RUN: %lli %t.other.ll
; RUN: %opt -passes='default<O2>,verify' -S %t.other.ll -o %t.optimized.ll
; RUN: %lli %t.optimized.ll
;
; Inject a one-bit expected-state mismatch in only test_fusion, after string
; lowering but before flattening binds the placeholders. Its nonzero-state
; admission check still succeeds. Equality with the runtime "fusion" input must
; fail because the CFG mask changes the decrypted bytes. Disabling that mask
; would instead leave main successful, making the negative run fail.
; Fresh named temporaries preserve numeric SSA slot order. Require both the
; admission read and the string-mask read, and mutate every expected-state call.
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml --obf-seed=1 -passes=obf-string-encode -S %s -o %t.strings.ll
; RUN: %python -c "import itertools,pathlib,re,sys; text=pathlib.Path(sys.argv[1]).read_text(); function=re.search(r'(?ms)^define [^\n]*@test_fusion\([^\n]*\n.*?^}', text); assert function is not None, 'missing test_fusion'; temps=('%fault.expected.bound.'+str(i) for i in itertools.count() if 'fault.expected.bound.'+str(i) not in text); call=r'(?m)^([ \t]*)(%[-a-zA-Z$._0-9]+) = call i32 @__obf_get_expected_cfg_state\(\)'; replacement=lambda m: '{0}{2} = call i32 @__obf_get_expected_cfg_state()\n{0}{1} = xor i32 {2}, 1'.format(m[1],m[2],next(temps)); body,count=re.subn(call,replacement,function[0]); assert count>=2 and count==function[0].count('call i32 @__obf_get_expected_cfg_state()'), 'did not mutate admission and string-mask expected-state calls in test_fusion'; text=text[:function.start()]+body+text[function.end():]; pathlib.Path(sys.argv[2]).write_text(text)" %t.strings.ll %t.mismatch.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare-e2e.yaml --obf-seed=1 -passes='obf-control-flatten,obf-cfg-state-cleanup,verify' -S %t.mismatch.ll -o %t.tampered.ll
; RUN: not %lli %t.tampered.ll

@fusion = private constant [7 x i8] c"fusion\00"
@mem_bytes = private constant [5 x i8] c"f\FFa\80\00"
@ncmp_bytes = private constant [5 x i8] c"f\FFa\80\00"
@fusion_reference = internal global [7 x i8] c"fusion\00"
@fusion_input = internal global [7 x i8] zeroinitializer
@bytes_reference = internal global [8 x i8] c"f\FFa\80\00\CC\DD\00"
@bytes_input = internal global [8 x i8] zeroinitializer

declare i32 @strcmp(ptr, ptr)
declare i32 @memcmp(ptr, ptr, i64)
declare i32 @strncmp(ptr, ptr, i64)
declare i32 @__obf_get_cfg_state()
declare i32 @__obf_get_expected_cfg_state()
declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1 immarg)

define i32 @test_fusion(ptr %rhs) noinline {
entry:
  %expected = call i32 @__obf_get_expected_cfg_state()
  %result = call i32 @strcmp(ptr @fusion, ptr %rhs)
  %flattened = icmp ne i32 %expected, 0
  %checked = select i1 %flattened, i32 %result, i32 256
  ret i32 %checked
}

define i32 @test_memcmp(ptr %lhs) noinline {
entry:
  %expected = call i32 @__obf_get_expected_cfg_state()
  %result = call i32 @memcmp(ptr %lhs, ptr @mem_bytes, i64 5)
  %flattened = icmp ne i32 %expected, 0
  %checked = select i1 %flattened, i32 %result, i32 256
  ret i32 %checked
}

define i32 @test_strncmp(ptr %rhs) noinline {
entry:
  %expected = call i32 @__obf_get_expected_cfg_state()
  %result = call i32 @strncmp(ptr @ncmp_bytes, ptr %rhs, i64 8)
  %flattened = icmp ne i32 %expected, 0
  %checked = select i1 %flattened, i32 %result, i32 256
  ret i32 %checked
}

define i1 @test_state_diamond(i32 %route) noinline {
entry:
  %entry.current = call i32 @__obf_get_cfg_state()
  %entry.expected = call i32 @__obf_get_expected_cfg_state()
  %bit = and i32 %route, 1
  %take.left = icmp eq i32 %bit, 0
  br i1 %take.left, label %left, label %right
left:
  %left.current = call i32 @__obf_get_cfg_state()
  %left.expected = call i32 @__obf_get_expected_cfg_state()
  %second.bit = and i32 %route, 2
  %take.extra = icmp ne i32 %second.bit, 0
  br i1 %take.extra, label %extra, label %join
extra:
  br label %join
right:
  %right.current = call i32 @__obf_get_cfg_state()
  %right.expected = call i32 @__obf_get_expected_cfg_state()
  br label %join
join:
  %current = phi i32 [ %left.current, %left ], [ %left.current, %extra ], [ %right.current, %right ]
  %expected = phi i32 [ %left.expected, %left ], [ %left.expected, %extra ], [ %right.expected, %right ]
  %entry.matches = icmp eq i32 %entry.current, %entry.expected
  %selected.matches = icmp eq i32 %current, %expected
  %entry.bound = icmp ne i32 %entry.expected, 0
  %selected.bound = icmp ne i32 %expected, 0
  %matches = and i1 %entry.matches, %selected.matches
  %bound = and i1 %entry.bound, %selected.bound
  %ok = and i1 %matches, %bound
  ret i1 %ok
}

define i1 @test_state_loop(i32 %count) noinline {
entry:
  %entry.current = call i32 @__obf_get_cfg_state()
  %entry.expected = call i32 @__obf_get_expected_cfg_state()
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %next, %latch ]
  %previous.current = phi i32 [ %entry.current, %entry ], [ %current, %latch ]
  %previous.expected = phi i32 [ %entry.expected, %entry ], [ %expected, %latch ]
  %all.ok = phi i1 [ true, %entry ], [ %next.ok, %latch ]
  %body.current = call i32 @__obf_get_cfg_state()
  %body.expected = call i32 @__obf_get_expected_cfg_state()
  %bit = and i32 %i, 1
  %even = icmp eq i32 %bit, 0
  br i1 %even, label %left, label %right
left:
  br label %latch
right:
  br label %latch
latch:
  %current = phi i32 [ %body.current, %left ], [ %body.current, %right ]
  %expected = phi i32 [ %body.expected, %left ], [ %body.expected, %right ]
  %entry.matches = icmp eq i32 %entry.current, %entry.expected
  %previous.matches = icmp eq i32 %previous.current, %previous.expected
  %body.matches = icmp eq i32 %current, %expected
  %previous.bound = icmp ne i32 %previous.expected, 0
  %body.bound = icmp ne i32 %expected, 0
  %old.matches = and i1 %entry.matches, %previous.matches
  %matches = and i1 %old.matches, %body.matches
  %bound = and i1 %previous.bound, %body.bound
  %iteration.ok = and i1 %matches, %bound
  %next.ok = and i1 %all.ok, %iteration.ok
  %next = add i32 %i, 1
  %again = icmp slt i32 %next, %count
  br i1 %again, label %loop, label %exit
exit:
  ret i1 %next.ok
}

; A switch is unsupported by flattening. Cleanup must still neutralize both
; unbound placeholders, including their cross-block uses.
define i1 @test_unsupported_cleanup(i32 %route) noinline {
entry:
  %current = call i32 @__obf_get_cfg_state()
  %expected = call i32 @__obf_get_expected_cfg_state()
  switch i32 %route, label %left [ i32 0, label %right ]
left:
  br label %join
right:
  br label %join
join:
  %current.zero = icmp eq i32 %current, 0
  %expected.zero = icmp eq i32 %expected, 0
  %ok = and i1 %current.zero, %expected.zero
  ret i1 %ok
}

define i32 @oracle_strcmp(ptr %lhs, ptr %rhs) noinline {
entry:
  %result = call i32 @strcmp(ptr %lhs, ptr %rhs)
  ret i32 %result
}

define i32 @oracle_memcmp(ptr %lhs, ptr %rhs) noinline {
entry:
  %result = call i32 @memcmp(ptr %lhs, ptr %rhs, i64 5)
  ret i32 %result
}

define i32 @oracle_strncmp(ptr %lhs, ptr %rhs) noinline {
entry:
  %result = call i32 @strncmp(ptr %lhs, ptr %rhs, i64 8)
  ret i32 %result
}

; libc promises the sign of a nonzero comparison, not its exact magnitude.
define i1 @same_comparison(i32 %protected, i32 %oracle) {
entry:
  %protected.zero = icmp eq i32 %protected, 0
  %oracle.zero = icmp eq i32 %oracle, 0
  %same.zero = icmp eq i1 %protected.zero, %oracle.zero
  %protected.negative = icmp slt i32 %protected, 0
  %oracle.negative = icmp slt i32 %oracle, 0
  %same.sign = icmp eq i1 %protected.negative, %oracle.negative
  %same = and i1 %same.zero, %same.sign
  ret i1 %same
}

define i32 @main() {
entry:
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %next, %loop ]
  %all.ok = phi i1 [ true, %entry ], [ %next.ok, %loop ]
  call void @llvm.memcpy.p0.p0.i64(ptr @fusion_input, ptr @fusion_reference, i64 7, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr @bytes_input, ptr @bytes_reference, i64 8, i1 false)
  %case1 = icmp eq i32 %i, 1
  %case2 = icmp eq i32 %i, 2
  %case3 = icmp eq i32 %i, 3
  %case4 = icmp eq i32 %i, 4
  %case5 = icmp eq i32 %i, 5
  %case6 = icmp eq i32 %i, 6
  %case7 = icmp eq i32 %i, 7
  %fusion.first.1 = select i1 %case1, i8 101, i8 102
  %fusion.first.2 = select i1 %case2, i8 103, i8 %fusion.first.1
  %fusion.first = select i1 %case6, i8 0, i8 %fusion.first.2
  store i8 %fusion.first, ptr @fusion_input
  %fusion.second.1 = select i1 %case4, i8 0, i8 117
  %fusion.second = select i1 %case5, i8 -1, i8 %fusion.second.1
  store i8 %fusion.second, ptr getelementptr ([7 x i8], ptr @fusion_input, i64 0, i64 1)
  %fusion.last.1 = select i1 %case3, i8 109, i8 110
  %fusion.last = select i1 %case7, i8 -1, i8 %fusion.last.1
  store i8 %fusion.last, ptr getelementptr ([7 x i8], ptr @fusion_input, i64 0, i64 5)
  %bytes.second = select i1 %case1, i8 -2, i8 -1
  store i8 %bytes.second, ptr getelementptr ([8 x i8], ptr @bytes_input, i64 0, i64 1)
  %bytes.third = select i1 %case4, i8 0, i8 97
  store i8 %bytes.third, ptr getelementptr ([8 x i8], ptr @bytes_input, i64 0, i64 2)
  %bytes.fourth.1 = select i1 %case2, i8 127, i8 -128
  %bytes.fourth = select i1 %case6, i8 -2, i8 %bytes.fourth.1
  store i8 %bytes.fourth, ptr getelementptr ([8 x i8], ptr @bytes_input, i64 0, i64 3)
  %bytes.fifth = select i1 %case3, i8 1, i8 0
  store i8 %bytes.fifth, ptr getelementptr ([8 x i8], ptr @bytes_input, i64 0, i64 4)
  %bytes.after.nul = select i1 %case7, i8 0, i8 -52
  store i8 %bytes.after.nul, ptr getelementptr ([8 x i8], ptr @bytes_input, i64 0, i64 5)
  %fusion.protected = call i32 @test_fusion(ptr @fusion_input)
  %fusion.oracle = call i32 @oracle_strcmp(ptr @fusion_reference, ptr @fusion_input)
  %fusion.ok = call i1 @same_comparison(i32 %fusion.protected, i32 %fusion.oracle)
  %mem.protected = call i32 @test_memcmp(ptr @bytes_input)
  %mem.oracle = call i32 @oracle_memcmp(ptr @bytes_input, ptr @bytes_reference)
  %mem.ok = call i1 @same_comparison(i32 %mem.protected, i32 %mem.oracle)
  %ncmp.protected = call i32 @test_strncmp(ptr @bytes_input)
  %ncmp.oracle = call i32 @oracle_strncmp(ptr @bytes_reference, ptr @bytes_input)
  %ncmp.ok = call i1 @same_comparison(i32 %ncmp.protected, i32 %ncmp.oracle)
  %diamond.ok = call i1 @test_state_diamond(i32 %i)
  %next = add i32 %i, 1
  %state.loop.ok = call i1 @test_state_loop(i32 %next)
  %cleanup.ok = call i1 @test_unsupported_cleanup(i32 %i)
  %strings.ok.1 = and i1 %fusion.ok, %mem.ok
  %strings.ok = and i1 %strings.ok.1, %ncmp.ok
  %state.ok.1 = and i1 %diamond.ok, %state.loop.ok
  %state.ok = and i1 %state.ok.1, %cleanup.ok
  %iteration.ok = and i1 %strings.ok, %state.ok
  %next.ok = and i1 %all.ok, %iteration.ok
  %again = icmp slt i32 %next, 8
  br i1 %again, label %loop, label %exit
exit:
  %status = select i1 %next.ok, i32 0, i32 1
  ret i32 %status
}
