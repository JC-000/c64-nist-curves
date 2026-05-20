.setcpu "6502"

; ===========================================================================
; ecdsa256.s -- Packaged ECDSA verify for P-256 (FIPS 186-4 / RFC 6979).
;
; ecdsa_verify_256 is NOT constant-time. It branches on bits of r, s, h, Qx,
; Qy -- all of which are PUBLIC inputs in the TLS/ECDSA verify context (they
; come from the signature and peer certificate, not secret material). A
; constant-time verify would be correct but much slower and is unnecessary
; for the verifier.
;
; Calling contract (ecdsa_verify_256):
;   Input:  A = low byte, X = high byte of a pointer to a 160-byte struct:
;             +0   r       32 B big-endian
;             +32  s       32 B big-endian
;             +64  h       32 B big-endian SHA-256 digest
;             +96  pub_x   32 B big-endian affine X of public key
;             +128 pub_y   32 B big-endian affine Y of public key
;   Output: C=0 on VALID signature, C=1 on INVALID or malformed inputs.
;   Clobbers: everything -- uses full field/point scratch like any top-level op.
;
; fp_reverse32 contract:
;   Input:  fp_src1 -> 32-byte source
;           fp_dst  -> 32-byte destination
;   Output: dst[i] = src[31 - i] for i = 0..31  (BE<->LE byte reversal).
;   Uses fp_rev_buf as a temporary staging buffer so src and dst may overlap
;   arbitrarily.
; ===========================================================================

.segment "LIB_NISTCURVES_P256_CODE"

.export ecdsa_verify_256
.export fp_reverse32

.importzp fp_src1, fp_src2, fp_dst, fp_misc, zp_ptr2, ec_scalar_ptr
.importzp fp_carry

.import fp_copy, fp_zero, fp_cmp, fp_add, fp_sub, fp_is_zero
.import fp_mod_mul_n, fp_mod_inv
.import ec_set_modp, ec_set_modn
.import ec_mulp, ec_sqrp
.import ec_n256, ec_p256
.import ec_scalar_mul, ec_scalar_mul_var, ec_point_add_jj
.import reu_reu_lo, reu_addr_ctrl     ; issue #33-class defence

.import fp_r0
.import ec_p1, ec_p2, ec_p3
.import ec_t1, ec_t2, ec_t3
.import ec_base_x, ec_base_y
.import ecdsa_r, ecdsa_s, ecdsa_h, ecdsa_qx, ecdsa_qy
.import ecdsa_w, ecdsa_u1, ecdsa_u2
.import ecdsa_u1_be, ecdsa_u2_be
.import ecdsa_u1g_jac
.import fp_rev_buf

; Use zp_ptr2 ($fd-$fe by default) as the struct base pointer.
ecdsa_in_ptr = zp_ptr2

; ===========================================================================
; fp_reverse32 -- 32-byte byte-reverse via a scratch staging buffer.
; Callers set fp_src1 and fp_dst before the jsr.
; ===========================================================================
fp_reverse32:
        ; Phase 1: src[y] -> fp_rev_buf[31-y] (using X = 31-Y walking up)
        ldy #31
        ldx #0
@rev1:
        lda (fp_src1),y
        sta fp_rev_buf,x
        inx
        dey
        bpl @rev1

        ; Phase 2: fp_rev_buf[y] -> dst[y]
        ldy #31
@rev2:
        lda fp_rev_buf,y
        sta (fp_dst),y
        dey
        bpl @rev2
        rts

; ===========================================================================
; ecdsa_verify_256 -- P-256 ECDSA verification.
; Returns C=0 for valid, C=1 for invalid/malformed. Does not return a result
; in any register; callers branch on C.
; ===========================================================================
ecdsa_verify_256:
        sta ecdsa_in_ptr
        stx ecdsa_in_ptr+1

        ; --- Defensive REU register init (issue #33-class defence;
        ; see c64-x25519 commit 817f525). Defence-in-depth at the
        ; public surface; the inner fp_mul/sqr primitives are also
        ; patched. Must run after the A/X input save above.
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        ; --- Step 2: byte-reverse 5 BE input fields into LE scratch.
        ; Parametric loop drives fp_reverse32 over the 5 (src_offset,
        ; dst) pairs; index lives in @rev_idx since fp_reverse32
        ; clobbers X and Y across the call.
        lda #0
        sta @rev_idx
@rev_loop:
        ldx @rev_idx
        clc
        lda ecdsa_in_ptr
        adc @rev_offsets,x
        sta fp_src1
        lda ecdsa_in_ptr+1
        adc #0
        sta fp_src1+1
        lda @rev_dst_lo,x
        sta fp_dst
        lda @rev_dst_hi,x
        sta fp_dst+1
        jsr fp_reverse32
        inc @rev_idx
        lda @rev_idx
        cmp #5
        bcc @rev_loop
        jmp @rev_done

@rev_idx:       .byte 0
@rev_offsets:   .byte 0, 32, 64, 96, 128
@rev_dst_lo:    .byte <ecdsa_r, <ecdsa_s, <ecdsa_h, <ecdsa_qx, <ecdsa_qy
@rev_dst_hi:    .byte >ecdsa_r, >ecdsa_s, >ecdsa_h, >ecdsa_qx, >ecdsa_qy
@rev_done:

        ; --- Step 3: validate r, s in [1, n-1] ---
        ; r == 0?
        lda #<ecdsa_r
        sta fp_src1
        lda #>ecdsa_r
        sta fp_src1+1
        jsr fp_is_zero
        bne @ev_rnz             ; NE = nonzero, continue
        jmp @ev_fail
@ev_rnz:

        ; s == 0?
        lda #<ecdsa_s
        sta fp_src1
        lda #>ecdsa_s
        sta fp_src1+1
        jsr fp_is_zero
        bne @ev_snz
        jmp @ev_fail
@ev_snz:

        ; r >= n256?  (fp_cmp: C=1 if src1>=src2, Z=1 if equal)
        lda #<ecdsa_r
        sta fp_src1
        lda #>ecdsa_r
        sta fp_src1+1
        lda #<ec_n256
        sta fp_src2
        lda #>ec_n256
        sta fp_src2+1
        jsr fp_cmp
        bcc @ev_rlt             ; r < n -> ok
        jmp @ev_fail
@ev_rlt:

        ; s >= n256?
        lda #<ecdsa_s
        sta fp_src1
        lda #>ecdsa_s
        sta fp_src1+1
        lda #<ec_n256
        sta fp_src2
        lda #>ec_n256
        sta fp_src2+1
        jsr fp_cmp
        bcc @ev_slt             ; s < n -> ok
        jmp @ev_fail
@ev_slt:

        ; --- Step 4: w = s^-1 mod n. Result lands in fp_r0. ---
        jsr ec_set_modn
        lda #<ecdsa_s
        sta fp_src1
        lda #>ecdsa_s
        sta fp_src1+1
        ; fp_mod_inv also touches fp_dst (preserved by internal push/pop).
        ; Point fp_dst somewhere safe; it is restored on return.
        lda #<ecdsa_w
        sta fp_dst
        lda #>ecdsa_w
        sta fp_dst+1
        jsr fp_mod_inv          ; fp_r0 = s^-1

        ; Copy fp_r0 -> ecdsa_w
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        lda #<ecdsa_w
        sta fp_dst
        lda #>ecdsa_w
        sta fp_dst+1
        jsr fp_copy

        ; --- Step 5: u1 = (h * w) mod n ---
        lda #<ecdsa_h
        sta fp_src1
        lda #>ecdsa_h
        sta fp_src1+1
        lda #<ecdsa_w
        sta fp_src2
        lda #>ecdsa_w
        sta fp_src2+1
        lda #<ecdsa_u1
        sta fp_dst
        lda #>ecdsa_u1
        sta fp_dst+1
        jsr fp_mod_mul_n

        ; --- Step 6: u2 = (r * w) mod n ---
        lda #<ecdsa_r
        sta fp_src1
        lda #>ecdsa_r
        sta fp_src1+1
        lda #<ecdsa_w
        sta fp_src2
        lda #>ecdsa_w
        sta fp_src2+1
        lda #<ecdsa_u2
        sta fp_dst
        lda #>ecdsa_u2
        sta fp_dst+1
        jsr fp_mod_mul_n

        ; --- Step 7: u1 * G (fixed-base comb). Needs BE scalar. ---
        ; Reverse u1 (LE) -> ecdsa_u1_be (BE) and point ec_scalar_ptr at it.
        lda #<ecdsa_u1
        sta fp_src1
        lda #>ecdsa_u1
        sta fp_src1+1
        lda #<ecdsa_u1_be
        sta fp_dst
        lda #>ecdsa_u1_be
        sta fp_dst+1
        jsr fp_reverse32

        lda #<ecdsa_u1_be
        sta ec_scalar_ptr
        lda #>ecdsa_u1_be
        sta ec_scalar_ptr+1
        jsr ec_scalar_mul       ; ec_p3 = u1 * G (Jacobian)

        ; Stash full 96 B Jacobian u1*G into ecdsa_u1g_jac so it survives
        ; the u2*Q scalar_mul that overwrites ec_p3 below. The Jacobian
        ; form is the input we need for the J+J add at @ev_do_add; the
        ; previous affine-conversion path paid one binary-GCD inversion
        ; here that is now skipped (approach (a) follow-up to the
        ; cofactor-compare landing in PR #26).
        ldy #95
@evcp_u1g_jac:
        lda ec_p3,y
        sta ecdsa_u1g_jac,y
        dey
        bpl @evcp_u1g_jac

        ; --- Step 8: u2 * Q (variable-base). ---
        ; Move Q into ec_base_x / ec_base_y.
        lda #<ecdsa_qx
        sta fp_src1
        lda #>ecdsa_qx
        sta fp_src1+1
        lda #<ec_base_x
        sta fp_dst
        lda #>ec_base_x
        sta fp_dst+1
        jsr fp_copy

        lda #<ecdsa_qy
        sta fp_src1
        lda #>ecdsa_qy
        sta fp_src1+1
        lda #<ec_base_y
        sta fp_dst
        lda #>ec_base_y
        sta fp_dst+1
        jsr fp_copy

        ; Reverse u2 (LE) -> ecdsa_u2_be (BE) and point scalar_ptr at it.
        lda #<ecdsa_u2
        sta fp_src1
        lda #>ecdsa_u2
        sta fp_src1+1
        lda #<ecdsa_u2_be
        sta fp_dst
        lda #>ecdsa_u2_be
        sta fp_dst+1
        jsr fp_reverse32

        lda #<ecdsa_u2_be
        sta ec_scalar_ptr
        lda #>ecdsa_u2_be
        sta ec_scalar_ptr+1
        jsr ec_scalar_mul_var   ; ec_p3 = u2 * Q (Jacobian)

        ; --- Step 9: R = u1*G + u2*Q via full Jacobian+Jacobian add ---
        ; u2*Q is currently in ec_p3 (Jacobian). Copy 96 B to ec_p1.
        ldy #95
@evcpq:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl @evcpq

        ; Copy stashed u1*G Jacobian into ec_p2 (full 96 B including Z).
        ldy #95
@evcp_u1g_to_p2:
        lda ecdsa_u1g_jac,y
        sta ec_p2,y
        dey
        bpl @evcp_u1g_to_p2

        ; ec_point_add_jj handles all infinity cases natively:
        ;   P1 inf -> ec_p3 := P2 (== u1*G)
        ;   P2 inf -> ec_p3 := P1 (== u2*Q)
        ;   both inf -> ec_p3 := infinity (caught by the post-add Z-test below)
        ;   same projective point -> jmp ec_point_double on P1
        ;   negation -> ec_p3 := infinity
        ; The mixed-add @ev_r_from_u1g shortcut from PR #26 is now subsumed by
        ; the cofactor compare: when u2*Q is infinity and u1*G is the result,
        ; the J+J primitive copies u1*G's original (non-unit) Z into ec_p3,
        ; and the cofactor compare's r * Z^2 ≡ X (mod p) gate handles both
        ; the Z=1 and Z!=1 cases uniformly.
        jsr ec_set_modp         ; J+J body uses mod p
        jsr ec_point_add_jj     ; ec_p3 = ec_p1 + ec_p2

        ; --- Step 10: if R == infinity (ec_p3+64..95 all zero) fail. ---
        lda #<(ec_p3+64)
        sta fp_src1
        lda #>(ec_p3+64)
        sta fp_src1+1
        jsr fp_is_zero
        bne @ev_cofactor_cmp
        jmp @ev_fail

@ev_cofactor_cmp:
        ; --- Cofactor comparison: r * Z^2 == X (mod p)? ---
        ; Replaces ec_jacobian_to_affine on the final point (saves one binary
        ; GCD inversion + 3 mod-p multiplies). R is Jacobian in ec_p3:
        ;   X at +0..31, Y at +32..63 (unused), Z at +64..95.
        ; X_R from ec_point_add is canonical (< p), so a byte-equality compare
        ; against (r * Z^2 mod p) on both sides is well-defined.

        ; ec_t1 = Z^2 mod p
        lda #<(ec_p3+64)
        sta fp_src1
        lda #>(ec_p3+64)
        sta fp_src1+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr ec_sqrp

        ; ec_t2 = r * Z^2 mod p
        lda #<ecdsa_r
        sta fp_src1
        lda #>ecdsa_r
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr ec_mulp

        ; Compare ec_t2 vs ec_p3 (X_R), LE 32 bytes
        ldy #31
@ev_cof_cmp1:
        lda ec_t2,y
        cmp ec_p3,y
        bne @ev_cof_fallback
        dey
        bpl @ev_cof_cmp1
        clc                     ; all bytes equal -> VALID
        rts

@ev_cof_fallback:
        ; First test failed; try (r + n) * Z^2 mod p. Valid only when
        ; r + n < p (so the integer sum doesn't reduce); this is the case
        ; r in [0, p - n - 1]. p - n ~ 2^128, so this branch is essentially
        ; never taken on honest inputs but is correctness-required.
        lda #<ecdsa_r
        sta fp_src1
        lda #>ecdsa_r
        sta fp_src1+1
        lda #<ec_n256
        sta fp_src2
        lda #>ec_n256
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr fp_add              ; ec_t3 = r + n (33-bit carry into fp_carry)

        lda fp_carry
        beq @ev_cof_no_carry
        jmp @ev_fail            ; r + n >= 2^256 > p: no fallback applicable
@ev_cof_no_carry:

        ; Compare ec_t3 to p256: if ec_t3 >= p, fallback not applicable.
        lda #<ec_t3
        sta fp_src1
        lda #>ec_t3
        sta fp_src1+1
        lda #<ec_p256
        sta fp_src2
        lda #>ec_p256
        sta fp_src2+1
        jsr fp_cmp
        bcc @ev_cof_in_range
        jmp @ev_fail            ; r + n >= p
@ev_cof_in_range:

        ; ec_t2 = (r + n) * Z^2 mod p
        lda #<ec_t3
        sta fp_src1
        lda #>ec_t3
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr ec_mulp

        ldy #31
@ev_cof_cmp2:
        lda ec_t2,y
        cmp ec_p3,y
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
