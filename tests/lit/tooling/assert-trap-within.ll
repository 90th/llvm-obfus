; REQUIRES: system-windows-x86-64 || system-linux-x86-64
;
; Real native exceptions must retain their classification without crash collection.
; Normal exits, unrelated exceptions, and a child that does not exit must fail.
; RUN: %raw_clang -std=c11 -O2 %S/../Inputs/assert-trap-within.c -o %t.exe
; RUN: %python %S/../Inputs/assert_trap_within.py %t.exe illegal
; RUN: %python %S/../Inputs/assert_trap_within.py %t.exe breakpoint
; RUN: %python %S/../Inputs/expect_failure.py %python %S/../Inputs/assert_trap_within.py %t.exe success
; RUN: %python %S/../Inputs/expect_failure.py %python %S/../Inputs/assert_trap_within.py %t.exe failure
; RUN: %python %S/../Inputs/expect_failure.py %python %S/../Inputs/assert_trap_within.py %t.exe access-violation
; RUN: %python %S/../Inputs/expect_failure.py %python %S/../Inputs/assert_trap_within.py %t.exe wait
