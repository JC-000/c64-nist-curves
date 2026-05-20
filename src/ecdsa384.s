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

.segment "LIB_NISTCURVES_P384_CODE"

.export ecdsa_verify_384
.export fp_reverse48

.importzp fp_src1, fp_src2, fp_dst, fp_misc, zp_ptr2, ec_scalar_ptr
.importzp fp_carry

.import fp_copy_384, fp_zero_384, fp_cmp_384, fp_add_384, fp_sub_384, fp_is_zero_384
.import fp_mod_mul_n_384, fp_mod_inv_384
.import ec_set_modp_384, ec_set_modn_384
.import ec_mulp_384, ec_sqrp_384
.import ec_n384, ec_p384
.import ec_scalar_mul_384, ec_scalar_mul_var_384
.import ec_point_add_jj_384
.import reu_reu_lo, reu_addr_ctrl     ; issue #33-class defence

.import fp384_r0
.import ec384_p1, ec384_p2, ec384_p3
.import ec384_t1, ec384_t2, ec384_t3
.import ec_base384_x, ec_base384_y
.import ecdsa384_r, ecdsa384_s, ecdsa384_h, ecdsa384_qx, ecdsa384_qy
.import ecdsa384_w, ecdsa384_u1, ecdsa384_u2
.import ecdsa384_u1_be, ecdsa384_u2_be
.import ecdsa384_u1g_jac
.import fp_rev_buf_384

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

        ; --- Step 2: byte-reverse 5 BE input fields into LE scratch.
        ; Parametric loop drives fp_reverse48 over the 5 (src_offset,
        ; dst) pairs; index lives in @rev_idx since fp_reverse48
        ; clobbers X and Y across the call.
        lda #0
        sta @rev_idx
@rev_loop:
        ldx @rev_idx
        clc
        lda ecdsa384_in_ptr
        adc @rev_offsets,x
        sta fp_src1
        lda ecdsa384_in_ptr+1
        adc #0
        sta fp_src1+1
        lda @rev_dst_lo,x
        sta fp_dst
        lda @rev_dst_hi,x
        sta fp_dst+1
        jsr fp_reverse48
        inc @rev_idx
        lda @rev_idx
        cmp #5
        bcc @rev_loop
        jmp @rev_done

@rev_idx:       .byte 0
@rev_offsets:   .byte 0, 48, 96, 144, 192
@rev_dst_lo:    .byte <ecdsa384_r, <ecdsa384_s, <ecdsa384_h, <ecdsa384_qx, <ecdsa384_qy
@rev_dst_hi:    .byte >ecdsa384_r, >ecdsa384_s, >ecdsa384_h, >ecdsa384_qx, >ecdsa384_qy
@rev_done:

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

        ; Stash full 144 B Jacobian u1*G into ecdsa384_u1g_jac so it survives
        ; the u2*Q scalar_mul that overwrites ec384_p3 below. See ecdsa256.s
        ; for the rationale (the affine-conversion cost was eliminated by
        ; replacing the mixed add at the join with ec_point_add_jj_384;
        ; this is approach (a) follow-up to PR #26's cofactor-compare).
        ;
        ; 144 B copy hazard guards (CLAUDE.md "Known issues"):
        ;   * X-counter countdown (DEX/BNE), not LDY #143/BPL: BPL never
        ;     branches on iter 0 (bit 7 of $8F is set), AND LDA clobbers Z
        ;     so a counter BNE on Y wouldn't see DEY's flags.
        ldx #144
        ldy #0
@evcp_u1g_jac:
        lda ec384_p3,y
        sta ecdsa384_u1g_jac,y
        iny
        dex
        bne @evcp_u1g_jac

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

        ; --- Step 9: R = u1*G + u2*Q via full Jacobian+Jacobian add ---
        ; u2*Q currently in ec384_p3 (Jacobian, 144 B). Copy to ec384_p1
        ; with the X-counter hazard guard (same as @evcp_u1g_jac above).
        ldx #144
        ldy #0
@evcpq:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        dex
        bne @evcpq

        ; Copy stashed u1*G Jacobian into ec384_p2 (full 144 B including Z).
        ldx #144
        ldy #0
@evcp_u1g_to_p2:
        lda ecdsa384_u1g_jac,y
        sta ec384_p2,y
        iny
        dex
        bne @evcp_u1g_to_p2

        ; ec_point_add_jj_384 handles all infinity / same-point / negation
        ; cases natively; the post-add Z-test below catches the result =
        ; infinity case (both inputs infinity, or P1 = -P2). The PR #26
        ; @ev_r_from_u1g mixed-add shortcut is subsumed by the cofactor
        ; compare (see ecdsa256.s for the full rationale).
        jsr ec_set_modp_384
        jsr ec_point_add_jj_384

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

@ev_fail:
        sec
        rts

