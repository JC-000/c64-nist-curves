.setcpu "6502"

; ===========================================================================
; ecdsa384.s -- Packaged ECDSA verify for P-384 (FIPS 186-4).
;
; ecdsa_verify_384 is NOT constant-time. Branches on public inputs
; (r, s, h, Qx, Qy from the peer certificate/signature). Acceptable for
; verify; unacceptable for sign (which this file does not provide).
;
; Calling contract (ecdsa_verify_384):
;   Input:  A = low byte, X = high byte of a pointer to a 240-byte struct:
;             +0    r       48 B big-endian
;             +48   s       48 B big-endian
;             +96   h       48 B big-endian SHA-384 digest
;             +144  pub_x   48 B big-endian affine X of public key
;             +192  pub_y   48 B big-endian affine Y of public key
;   Output: C=0 on VALID signature, C=1 on INVALID or malformed inputs.
;   Clobbers: everything -- uses full field/point scratch like any top-level op.
;
; fp_reverse48 contract:
;   Input:  fp_src1 -> 48-byte source
;           fp_dst  -> 48-byte destination
;   Output: dst[i] = src[47 - i] for i = 0..47  (BE<->LE byte reversal).
;   Uses fp_rev_buf_384 as a temporary staging buffer so src and dst may overlap
;   arbitrarily.
;
; 144-byte Jacobian copies use the X-counter countdown pattern (ldx #144 /
; iny / dex / bne), NOT the ldy #143 / dey / bpl pattern. Two reasons:
;   (1) bit 7 of 143 ($8F) is set so BPL never branches on iteration 0;
;   (2) LDA ...,y inside the loop clobbers the Z flag that BNE would read.
; Both bug families caught earlier in P-384 development (ec_scalar_mul_var_384
; Task #4, infinity-fill Wave 5). 48-byte copies use the ldy #47 / bpl idiom
; because 47 ($2F) has bit 7 clear.
; ===========================================================================

.segment "CODE"

.export ecdsa_verify_384
.export ecdsa_verify_with_message_384
.export ecdsa_verify_with_msg_384_tramp
.export fp_reverse48

.importzp fp_src1, fp_src2, fp_dst, fp_misc, zp_ptr2, ec_scalar_ptr
.importzp sha_src, sha_len
.importzp fp_carry

.import fp_copy_384, fp_zero_384, fp_cmp_384, fp_add_384, fp_sub_384, fp_is_zero_384
.import fp_mod_mul_n_384, fp_mod_inv_384
.import ec_set_modp_384, ec_set_modn_384
.import ec_mulp_384, ec_sqrp_384
.import ec_n384, ec_p384
.import ec_scalar_mul_384, ec_scalar_mul_var_384
.import ec_point_add_384, ec_jacobian_to_affine_384
.import reu_reu_lo, reu_addr_ctrl     ; issue #33-class defence

.import fp384_r0
.import ec384_p1, ec384_p2, ec384_p3
.import ec384_t1, ec384_t2, ec384_t3
.import ec384_affine_x, ec384_affine_y
.import ec_base384_x, ec_base384_y
.import ecdsa384_r, ecdsa384_s, ecdsa384_h, ecdsa384_qx, ecdsa384_qy
.import ecdsa384_w, ecdsa384_u1, ecdsa384_u2
.import ecdsa384_u1_be, ecdsa384_u2_be
.import ecdsa384_u1g_x, ecdsa384_u1g_y
.import fp_rev_buf_384

; --- ecdsa_verify_with_message_384 scratch + SHA-384 entry points ---
.import ecdsa384_msg_struct_ptr
.import ecdsa_inputs_384, ecdsa_result_msg_384  ; test-trampoline only
.import sha384_init, sha384_update, sha384_final
.import sha384_digest, sha384_msg_buf

; Use zp_ptr2 ($fd-$fe by default) as the struct base pointer.
ecdsa384_in_ptr = zp_ptr2

; ===========================================================================
; fp_reverse48 -- 48-byte byte-reverse via a scratch staging buffer.
; Callers set fp_src1 and fp_dst before the jsr.
; ===========================================================================
fp_reverse48:
        ; Phase 1: src[y] -> fp_rev_buf_384[47-y] (using X = 47-Y walking up)
        ldy #47
        ldx #0
@rev1:
        lda (fp_src1),y
        sta fp_rev_buf_384,x
        inx
        dey
        bpl @rev1

        ; Phase 2: fp_rev_buf_384[y] -> dst[y]
        ldy #47
@rev2:
        lda fp_rev_buf_384,y
        sta (fp_dst),y
        dey
        bpl @rev2
        rts

; ===========================================================================
; ecdsa_verify_384 -- P-384 ECDSA verification.
; Returns C=0 for valid, C=1 for invalid/malformed. Does not return a result
; in any register; callers branch on C.
; ===========================================================================
ecdsa_verify_384:
        sta ecdsa384_in_ptr
        stx ecdsa384_in_ptr+1

        ; --- Defensive REU register init (issue #33-class defence;
        ; see c64-x25519 commit 817f525). Defence-in-depth at the
        ; public surface; the inner fp_mul_384/sqr_384 primitives are
        ; also patched. Must run after the A/X input save above.
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        ; --- Step 2: byte-reverse 5 BE input fields into LE scratch. ---
        ; fp_src1 = ecdsa384_in_ptr + 0,   fp_dst = ecdsa384_r
        lda ecdsa384_in_ptr
        sta fp_src1
        lda ecdsa384_in_ptr+1
        sta fp_src1+1
        lda #<ecdsa384_r
        sta fp_dst
        lda #>ecdsa384_r
        sta fp_dst+1
        jsr fp_reverse48

        ; fp_src1 = ecdsa384_in_ptr + 48,  fp_dst = ecdsa384_s
        clc
        lda ecdsa384_in_ptr
        adc #48
        sta fp_src1
        lda ecdsa384_in_ptr+1
        adc #0
        sta fp_src1+1
        lda #<ecdsa384_s
        sta fp_dst
        lda #>ecdsa384_s
        sta fp_dst+1
        jsr fp_reverse48

        ; fp_src1 = ecdsa384_in_ptr + 96,  fp_dst = ecdsa384_h
        clc
        lda ecdsa384_in_ptr
        adc #96
        sta fp_src1
        lda ecdsa384_in_ptr+1
        adc #0
        sta fp_src1+1
        lda #<ecdsa384_h
        sta fp_dst
        lda #>ecdsa384_h
        sta fp_dst+1
        jsr fp_reverse48

        ; fp_src1 = ecdsa384_in_ptr + 144, fp_dst = ecdsa384_qx
        clc
        lda ecdsa384_in_ptr
        adc #144
        sta fp_src1
        lda ecdsa384_in_ptr+1
        adc #0
        sta fp_src1+1
        lda #<ecdsa384_qx
        sta fp_dst
        lda #>ecdsa384_qx
        sta fp_dst+1
        jsr fp_reverse48

        ; fp_src1 = ecdsa384_in_ptr + 192, fp_dst = ecdsa384_qy
        clc
        lda ecdsa384_in_ptr
        adc #192
        sta fp_src1
        lda ecdsa384_in_ptr+1
        adc #0
        sta fp_src1+1
        lda #<ecdsa384_qy
        sta fp_dst
        lda #>ecdsa384_qy
        sta fp_dst+1
        jsr fp_reverse48

        ; --- Step 3: validate r, s in [1, n-1] ---
        ; r == 0?
        lda #<ecdsa384_r
        sta fp_src1
        lda #>ecdsa384_r
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @ev_rnz             ; NE = nonzero, continue
        jmp @ev_fail
@ev_rnz:

        ; s == 0?
        lda #<ecdsa384_s
        sta fp_src1
        lda #>ecdsa384_s
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @ev_snz
        jmp @ev_fail
@ev_snz:

        ; r >= n384?  (fp_cmp_384: C=1 if src1>=src2, Z=1 if equal)
        lda #<ecdsa384_r
        sta fp_src1
        lda #>ecdsa384_r
        sta fp_src1+1
        lda #<ec_n384
        sta fp_src2
        lda #>ec_n384
        sta fp_src2+1
        jsr fp_cmp_384
        bcc @ev_rlt             ; r < n -> ok
        jmp @ev_fail
@ev_rlt:

        ; s >= n384?
        lda #<ecdsa384_s
        sta fp_src1
        lda #>ecdsa384_s
        sta fp_src1+1
        lda #<ec_n384
        sta fp_src2
        lda #>ec_n384
        sta fp_src2+1
        jsr fp_cmp_384
        bcc @ev_slt             ; s < n -> ok
        jmp @ev_fail
@ev_slt:

        ; --- Step 4: w = s^-1 mod n. Result lands in fp384_r0. ---
        jsr ec_set_modn_384
        lda #<ecdsa384_s
        sta fp_src1
        lda #>ecdsa384_s
        sta fp_src1+1
        ; fp_mod_inv_384 also touches fp_dst (preserved by internal push/pop).
        ; Point fp_dst somewhere safe; it is restored on return.
        lda #<ecdsa384_w
        sta fp_dst
        lda #>ecdsa384_w
        sta fp_dst+1
        jsr fp_mod_inv_384      ; fp384_r0 = s^-1

        ; Copy fp384_r0 -> ecdsa384_w
        lda #<fp384_r0
        sta fp_src1
        lda #>fp384_r0
        sta fp_src1+1
        lda #<ecdsa384_w
        sta fp_dst
        lda #>ecdsa384_w
        sta fp_dst+1
        jsr fp_copy_384

        ; --- Step 5: u1 = (h * w) mod n ---
        lda #<ecdsa384_h
        sta fp_src1
        lda #>ecdsa384_h
        sta fp_src1+1
        lda #<ecdsa384_w
        sta fp_src2
        lda #>ecdsa384_w
        sta fp_src2+1
        lda #<ecdsa384_u1
        sta fp_dst
        lda #>ecdsa384_u1
        sta fp_dst+1
        jsr fp_mod_mul_n_384

        ; --- Step 6: u2 = (r * w) mod n ---
        lda #<ecdsa384_r
        sta fp_src1
        lda #>ecdsa384_r
        sta fp_src1+1
        lda #<ecdsa384_w
        sta fp_src2
        lda #>ecdsa384_w
        sta fp_src2+1
        lda #<ecdsa384_u2
        sta fp_dst
        lda #>ecdsa384_u2
        sta fp_dst+1
        jsr fp_mod_mul_n_384

        ; --- Step 7: u1 * G (fixed-base comb). Needs BE scalar. ---
        ; Reverse u1 (LE) -> ecdsa384_u1_be (BE) and point ec_scalar_ptr at it.
        lda #<ecdsa384_u1
        sta fp_src1
        lda #>ecdsa384_u1
        sta fp_src1+1
        lda #<ecdsa384_u1_be
        sta fp_dst
        lda #>ecdsa384_u1_be
        sta fp_dst+1
        jsr fp_reverse48

        lda #<ecdsa384_u1_be
        sta ec_scalar_ptr
        lda #>ecdsa384_u1_be
        sta ec_scalar_ptr+1
        jsr ec_scalar_mul_384   ; ec384_p3 = u1 * G (Jacobian)

        ; Convert to affine -> ec384_affine_x / ec384_affine_y.
        ; ec_jacobian_to_affine_384 maps Z=0 to all-zero affine, so all-zero
        ; in ecdsa384_u1g_{x,y} marks "u1*G == infinity".
        jsr ec_jacobian_to_affine_384

        ; Copy ec384_affine_x -> ecdsa384_u1g_x
        lda #<ec384_affine_x
        sta fp_src1
        lda #>ec384_affine_x
        sta fp_src1+1
        lda #<ecdsa384_u1g_x
        sta fp_dst
        lda #>ecdsa384_u1g_x
        sta fp_dst+1
        jsr fp_copy_384

        ; Copy ec384_affine_y -> ecdsa384_u1g_y
        lda #<ec384_affine_y
        sta fp_src1
        lda #>ec384_affine_y
        sta fp_src1+1
        lda #<ecdsa384_u1g_y
        sta fp_dst
        lda #>ecdsa384_u1g_y
        sta fp_dst+1
        jsr fp_copy_384

        ; --- Step 8: u2 * Q (variable-base). ---
        ; Move Q into ec_base384_x / ec_base384_y.
        lda #<ecdsa384_qx
        sta fp_src1
        lda #>ecdsa384_qx
        sta fp_src1+1
        lda #<ec_base384_x
        sta fp_dst
        lda #>ec_base384_x
        sta fp_dst+1
        jsr fp_copy_384

        lda #<ecdsa384_qy
        sta fp_src1
        lda #>ecdsa384_qy
        sta fp_src1+1
        lda #<ec_base384_y
        sta fp_dst
        lda #>ec_base384_y
        sta fp_dst+1
        jsr fp_copy_384

        ; Reverse u2 (LE) -> ecdsa384_u2_be (BE) and point scalar_ptr at it.
        lda #<ecdsa384_u2
        sta fp_src1
        lda #>ecdsa384_u2
        sta fp_src1+1
        lda #<ecdsa384_u2_be
        sta fp_dst
        lda #>ecdsa384_u2_be
        sta fp_dst+1
        jsr fp_reverse48

        lda #<ecdsa384_u2_be
        sta ec_scalar_ptr
        lda #>ecdsa384_u2_be
        sta ec_scalar_ptr+1
        jsr ec_scalar_mul_var_384   ; ec384_p3 = u2 * Q (Jacobian)

        ; --- Step 9: R = u1*G + u2*Q ---
        ; u2*Q currently in ec384_p3 (Jacobian, 144 B). Copy it to ec384_p1.
        ; 144-byte copy: must use X-counter pattern because LDY #143 / BPL
        ; never branches on iteration 0 (bit 7 of $8F set) AND because LDA
        ; clobbers the Z flag that a data-dependent BNE would read.
        ldx #144
        ldy #0
@evcpq:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        dex
        bne @evcpq

        ; Is u2*Q infinity? (ec384_p1+96..143 all zero, 48 bytes of Z)
        lda #<(ec384_p1+96)
        sta fp_src1
        lda #>(ec384_p1+96)
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @ev_u2q_ok          ; NE -> nonzero, normal path

        ; u2*Q is infinity: R = u1*G.
        ; If u1*G is ALSO infinity, R = infinity -> fail.
        ; Otherwise u1*G affine is already in ecdsa384_u1g_{x,y}; use those as R.x
        ; directly and skip the Jacobian-path entirely.
        lda #<ecdsa384_u1g_x
        sta fp_src1
        lda #>ecdsa384_u1g_x
        sta fp_src1+1
        jsr fp_is_zero_384
        beq @ev_u1gx_zero
        jmp @ev_r_from_u1g      ; u1*G.x != 0 -> use it as R.x
@ev_u1gx_zero:
        lda #<ecdsa384_u1g_y
        sta fp_src1
        lda #>ecdsa384_u1g_y
        sta fp_src1+1
        jsr fp_is_zero_384
        beq @ev_fail_jmp        ; both x and y zero: R = infinity -> fail
        jmp @ev_r_from_u1g
@ev_fail_jmp:
        jmp @ev_fail

@ev_u2q_ok:
        ; Is u1*G infinity? (ecdsa384_u1g_x == 0 AND ecdsa384_u1g_y == 0)
        lda #<ecdsa384_u1g_x
        sta fp_src1
        lda #>ecdsa384_u1g_x
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @ev_do_add          ; u1*G.x != 0 -> not infinity
        lda #<ecdsa384_u1g_y
        sta fp_src1
        lda #>ecdsa384_u1g_y
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @ev_do_add          ; u1*G.y != 0 -> not infinity
        ; u1*G == infinity. R = u2*Q, already Jacobian in ec384_p1.
        ; 144-byte copy ec384_p1 -> ec384_p3 -- X-counter guardrail as @evcpq.
        ldx #144
        ldy #0
@evcpq2:
        lda ec384_p1,y
        sta ec384_p3,y
        iny
        dex
        bne @evcpq2
        jmp @ev_cofactor_cmp

@ev_do_add:
        ; Load u1*G affine into ec384_p2 (X at +0, Y at +48). ec_point_add_384
        ; is a mixed Jacobian+affine add; Z2 is implicitly 1 and never read.
        ldy #47
@evcpx:
        lda ecdsa384_u1g_x,y
        sta ec384_p2,y
        dey
        bpl @evcpx
        ldy #47
@evcpy:
        lda ecdsa384_u1g_y,y
        sta ec384_p2+48,y
        dey
        bpl @evcpy

        jsr ec_set_modp_384     ; point-add works mod p
        jsr ec_point_add_384    ; ec384_p3 = ec384_p1 + ec384_p2

        ; --- Step 10: if R == infinity (ec384_p3+96..143 all zero) fail. ---
        lda #<(ec384_p3+96)
        sta fp_src1
        lda #>(ec384_p3+96)
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @ev_cofactor_cmp
        jmp @ev_fail

@ev_cofactor_cmp:
        ; --- Cofactor comparison: r * Z^2 == X (mod p)? ---
        ; Replaces ec_jacobian_to_affine_384 on the final point. R is Jacobian
        ; in ec384_p3: X at +0..47, Y at +48..95 (unused), Z at +96..143.

        ; ec384_t1 = Z^2 mod p
        lda #<(ec384_p3+96)
        sta fp_src1
        lda #>(ec384_p3+96)
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_dst
        lda #>ec384_t1
        sta fp_dst+1
        jsr ec_sqrp_384

        ; ec384_t2 = r * Z^2 mod p
        lda #<ecdsa384_r
        sta fp_src1
        lda #>ecdsa384_r
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t2
        sta fp_dst
        lda #>ec384_t2
        sta fp_dst+1
        jsr ec_mulp_384

        ldy #47
@ev_cof_cmp1:
        lda ec384_t2,y
        cmp ec384_p3,y
        bne @ev_cof_fallback
        dey
        bpl @ev_cof_cmp1
        clc
        rts

@ev_cof_fallback:
        ; Try (r + n) * Z^2 mod p. Valid only when r + n < p (p - n ~ 2^192
        ; for P-384) so the integer sum doesn't reduce.
        lda #<ecdsa384_r
        sta fp_src1
        lda #>ecdsa384_r
        sta fp_src1+1
        lda #<ec_n384
        sta fp_src2
        lda #>ec_n384
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr fp_add_384

        lda fp_carry
        beq @ev_cof_no_carry
        jmp @ev_fail
@ev_cof_no_carry:

        lda #<ec384_t3
        sta fp_src1
        lda #>ec384_t3
        sta fp_src1+1
        lda #<ec_p384
        sta fp_src2
        lda #>ec_p384
        sta fp_src2+1
        jsr fp_cmp_384
        bcc @ev_cof_in_range
        jmp @ev_fail
@ev_cof_in_range:

        lda #<ec384_t3
        sta fp_src1
        lda #>ec384_t3
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t2
        sta fp_dst
        lda #>ec384_t2
        sta fp_dst+1
        jsr ec_mulp_384

        ldy #47
@ev_cof_cmp2:
        lda ec384_t2,y
        cmp ec384_p3,y
        bne @ev_cof_cmp2_fail
        dey
        bpl @ev_cof_cmp2
        clc
        rts
@ev_cof_cmp2_fail:
        jmp @ev_fail

@ev_r_from_u1g:
        ; R is affine (u2*Q was infinity). Reduce ecdsa384_u1g_x mod n then
        ; byte-compare against ecdsa384_r.
        lda #<ecdsa384_u1g_x
        sta fp_src1
        lda #>ecdsa384_u1g_x
        sta fp_src1+1
        lda #<ec_n384
        sta fp_src2
        lda #>ec_n384
        sta fp_src2+1
        jsr fp_cmp_384
        bcc @ev_u1g_cmp

        lda #<ecdsa384_u1g_x
        sta fp_src1
        lda #>ecdsa384_u1g_x
        sta fp_src1+1
        lda #<ec_n384
        sta fp_src2
        lda #>ec_n384
        sta fp_src2+1
        lda #<ec384_affine_x
        sta fp_dst
        lda #>ec384_affine_x
        sta fp_dst+1
        jsr fp_sub_384
        ldy #47
@ev_u1g_cmp_sub:
        lda ec384_affine_x,y
        cmp ecdsa384_r,y
        bne @ev_u1g_fail_jmp
        dey
        bpl @ev_u1g_cmp_sub
        clc
        rts
@ev_u1g_fail_jmp:
        jmp @ev_fail

@ev_u1g_cmp:
        ldy #47
@ev_u1g_cmp_loop:
        lda ecdsa384_u1g_x,y
        cmp ecdsa384_r,y
        bne @ev_u1g_cmp_fail
        dey
        bpl @ev_u1g_cmp_loop
        clc
        rts
@ev_u1g_cmp_fail:
        jmp @ev_fail

@ev_fail:
        sec
        rts

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

; ===========================================================================
; ecdsa_verify_with_msg_384_tramp -- test-only trampoline.
;
; The c64-test-harness jsr() helper cannot pass register arguments, so we
; fix the struct address at the BSS-resident ecdsa_inputs_384 buffer (already
; used by the existing ecdsa_verify_384 tests) and the message at
; sha384_msg_buf. The Python driver pre-pokes:
;   - ecdsa_inputs_384  : 240 B BE struct (h slot can be left zero -- the
;                         wrapper overwrites it)
;   - sha384_msg_buf    : the message bytes
;   - sha_src           : low/high pointer to sha384_msg_buf
;   - sha_len           : 16-bit message byte count
; Then calls this trampoline. Result byte: 0 = valid, 1 = invalid (mirrors
; ecdsa_result_384's encoding).
; ===========================================================================
ecdsa_verify_with_msg_384_tramp:
        lda #<ecdsa_inputs_384
        ldx #>ecdsa_inputs_384
        jsr ecdsa_verify_with_message_384
        lda #0
        rol a                     ; shift C into bit 0
        sta ecdsa_result_msg_384
        rts
