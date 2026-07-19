.setcpu "6502"

; ===========================================================================
; ecdsa384_msg.s -- One-shot hash-then-verify wrapper for P-384 ECDSA.
;
; Factored out of src/ecdsa384.s as part of #40 (SPEC §6) so the
; lib-p384-verify minimal archive can ship the verify primitive without
; pulling SHA-384 in. Consumers that drive sha384_init / update (n times) /
; final themselves (e.g. TLS-style streaming transcripts spanning multiple
; buffers) link against ecdsa_verify_384 directly and never see this file.
; Consumers that want the "give me a struct + message, run the whole
; pipeline" one-shot path link against this file too, which transitively
; pulls in sha384.s.
;
; Calling contract documented inline at ecdsa_verify_with_message_384; the
; underlying ecdsa_verify_384 routine and the SHA-384 streaming primitives
; live in their own translation units. The test-only trampoline
; (ecdsa_verify_with_msg_384_tramp) lives in src/main.s with the other
; test/bench trampolines (issue #63): keeping it here made this object
; import the test-driver buffers, which are excluded from every consumer
; archive, so the shipping wrapper was unlinkable from any archive.
; ===========================================================================

.segment "LIB_NISTCURVES_P384_CODE"

.export ecdsa_verify_with_message_384

.importzp sha_src, sha_len
.importzp fp_dst

; --- The base ecdsa verify ABI we wrap ---
.import ecdsa_verify_384

; --- SHA-384 streaming entry points ---
.import sha384_init, sha384_update, sha384_final
.import sha384_digest

; --- ecdsa_verify_with_message_384 scratch ---
.import ecdsa384_msg_struct_ptr

; ===========================================================================
; ecdsa_verify_with_message_384 -- one-shot "hash message + verify" wrapper.
;
; Thin shim around sha384_init / sha384_update / sha384_final / ecdsa_verify_384.
; Equivalent to the caller doing:
;
;     jsr sha384_init
;     ; sha_src / sha_len pre-set by caller
;     jsr sha384_update
;     jsr sha384_final
;     ; copy sha384_digest into struct[96..143]
;     ; restore A/X to struct pointer
;     jsr ecdsa_verify_384
;
; Calling contract:
;   Entry:
;     A = low byte, X = high byte of a pointer to a 240-byte struct:
;       +0    r       48 B big-endian
;       +48   s       48 B big-endian
;       +96   h_slot  48 B  -- INPUT-IGNORED. Wrapper overwrites it with the
;                              SHA-384 digest of the message before calling
;                              ecdsa_verify_384. The struct must be writable.
;       +144  pub_x   48 B big-endian affine X of public key
;       +192  pub_y   48 B big-endian affine Y of public key
;     sha_src (ZP, 2 B) -- pointer to message bytes
;     sha_len (ZP, 2 B) -- 16-bit message length in bytes (single update call;
;                          callers wanting > 1024 B should drive the SHA
;                          ABI directly and call ecdsa_verify_384 themselves)
;   Output: C=0 VALID, C=1 INVALID/malformed (matches ecdsa_verify_384).
;   Clobbers: everything -- composes ecdsa_verify_384 + the SHA streaming
;             primitives, both of which clobber freely.
;
; Streaming caveat: this routine issues exactly one sha384_update call. To
; hash a transcript fragmented across multiple buffers (e.g. TLS) call
; sha384_init / sha384_update (multiple) / sha384_final directly, then
; jsr ecdsa_verify_384 with sha384_digest already stored at struct[96..143].
; ===========================================================================
ecdsa_verify_with_message_384:
        ; Save struct pointer across the SHA calls (which clobber A/X/Y).
        sta ecdsa384_msg_struct_ptr+0
        stx ecdsa384_msg_struct_ptr+1

        ; --- Hash the message --------------------------------------------------
        jsr sha384_init
        ; sha_src / sha_len already set up by caller; sha384_update consumes
        ; them. For a zero-length message sha384_update returns immediately.
        jsr sha384_update
        jsr sha384_final          ; sha384_digest = SHA-384(message), 48 B BE

        ; --- Splice digest into struct[96..143] -------------------------------
        ; struct + 96 -> fp_dst.
        clc
        lda ecdsa384_msg_struct_ptr+0
        adc #96
        sta fp_dst
        lda ecdsa384_msg_struct_ptr+1
        adc #0
        sta fp_dst+1

        ; Copy 48 BE bytes from sha384_digest into (fp_dst). 47 ($2F) has bit 7
        ; clear so ldy #47 / dey / bpl is safe; the loop body uses Y for both
        ; src and (fp_dst),y dst so no LDA-clobbers-Z hazard against BPL on the
        ; final iteration (BPL tests the N flag set by DEY, not the loaded
        ; byte). Same idiom as fp_reverse48's phase 2.
        ldy #47
@msg_cp:
        lda sha384_digest, y
        sta (fp_dst), y
        dey
        bpl @msg_cp

        ; --- Restore struct pointer to A/X and tail-call ecdsa_verify_384 -----
        ; The verify routine's first action is to save A/X into ecdsa384_in_ptr,
        ; then re-establish the REU defensive state, exactly as needed.
        lda ecdsa384_msg_struct_ptr+0
        ldx ecdsa384_msg_struct_ptr+1
        jmp ecdsa_verify_384      ; tail-call: C return passes through
