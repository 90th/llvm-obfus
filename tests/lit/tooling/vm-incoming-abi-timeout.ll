; Exercise the shared ABI process runner with real socket-owning Python
; processes, both directly and through a launcher that waits for its child.
; An isolated watchdog and out-of-band fixture cleanup keep a broken runner
; from hanging this test or leaving descendants in the rest of the suite.
; Socket rebinding is checked before cleanup, without PID/zombie polling.
;
; RUN: %python "%S/../Inputs/vm_incoming_abi_timeout.py" --work "%t.work"
