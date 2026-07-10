; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ephemeral.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t
; RUN: %python -c "import sys, re; data = open(sys.argv[1]).read(); data = re.sub(r'(@__obf_string_ct__secret = internal constant \[8 x i8\] c\")[^\"]*', lambda m: m.group(1) + r'\\00\\00\\00\\00\\00\\00\\00\\00', data); open(sys.argv[1], 'w').write(data)" %t
; RUN: not --crash %lli %t

@.secret = private unnamed_addr constant [8 x i8] c"delta-7\00"

declare i32 @bcmp(ptr, ptr, i64)

define i32 @main() {
entry:
  %cmp = call i32 @bcmp(ptr @.secret, ptr @.secret, i64 7)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
