.setcpu "6502"

; =============================================================================
; data_test.s - Test-driver-only buffers.
;
; Split from the monolithic data.s as part of #40 (SPEC §6 minimal-archive
; build targets). These buffers are linked into the standalone test PRG so
; the c64-test-harness Python driver can stage BE input structs (the jsr()
; helper cannot pass register arguments), but they are NEVER linked into a
; consumer archive: production consumers pass their own struct pointer to
; ecdsa_verify_256 / ecdsa_verify_384 directly.
;
; If the Makefile MODULES list ever drops this file, every tools/test_*.py
; that pokes ecdsa_inputs_* / sha384_msg_buf via labels.txt will break.
; =============================================================================

.segment "LIB_NISTCURVES_TEST_BSS"

; --- ECDSA verify test-driver staging buffers.
;     The c64-test-harness jsr() helper cannot pass register arguments, so
;     the 160-/240-byte BE input struct for ecdsa_verify_{256,384} is
;     staged here by the Python test driver; the trampoline in main.s
;     loads A/X with a pointer to the buffer and invokes the verify
;     routine, capturing the returned C flag into the matching result
;     byte (0 = valid, 1 = invalid). Buffers are test-only; production
;     consumers pass their own pointer directly to ecdsa_verify_*.
.export ecdsa_inputs_256
ecdsa_inputs_256:       .res 160, 0     ; r|s|h|Qx|Qy each 32 B BE
.export ecdsa_result_256
ecdsa_result_256:       .byte 0

.export ecdsa_inputs_384
ecdsa_inputs_384:       .res 240, 0     ; r|s|h|Qx|Qy each 48 B BE
.export ecdsa_result_384
ecdsa_result_384:       .byte 0

; --- ecdsa_verify_with_message_384 test driver result byte (mirrors
;     ecdsa_result_384). Test-only: the harness peeks this after invoking
;     the test trampoline; production consumers branch on C directly.
.export ecdsa_result_msg_384
ecdsa_result_msg_384:   .byte 0

; --- SHA-384 test scratch buffer (poked by the harness with the message
;     before invoking ecdsa_verify_with_msg_384_tramp). Owned by main.s's
;     test driver; not used by sha384.s itself.
.export sha384_msg_buf
sha384_msg_buf:   .res 1024, 0
