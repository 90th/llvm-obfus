; RUN: %python %S/../Inputs/re-harness-binary-ownership.py --analyzer %S/../../../tools/obf-re-harness/score_binary_recovery.py | %FileCheck %s

; CHECK: shared_tail_ownership=pass
