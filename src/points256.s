.setcpu "6502"

; =============================================================================
; points256.s - P-256 point operations (Jacobian coordinates)
; ec_point_double, ec_point_add, ec_scalar_mul, ec_jacobian_to_affine
;
; All field elements are LITTLE-ENDIAN (byte 0 = LSB).
; Point layout: X = offset 0..31, Y = offset 32..63, Z = offset 64..95
; Point at infinity: Z = 0
; =============================================================================

.segment "CODE"

; --- Exports ---
.export ec_point_double, ec_point_add
.export ec_precompute_256, ec_scalar_mul, ec_scalar_mul_var
.export ec_jacobian_to_affine

; --- ZP imports ---
.importzp fp_src1, fp_src2, fp_dst, fp_misc, ec_scalar_ptr, zp_ptr1

; --- fp256 imports ---
.import fp_is_zero, fp_copy

; --- mod256 imports ---
.import ec_set_modp, ec_mulp, ec_sqrp
.import fp_mod_add, fp_mod_sub, fp_mod_inv, ec_p256

; --- curve256 imports ---
.import ec_gx256, ec_gy256

; --- data imports ---
.import ec_p1, ec_p2, ec_p3
.import ec_t1, ec_t2, ec_t3, ec_t4, ec_t5, ec_t6
.import ec_affine_x, ec_affine_y
.import fp_r0, fp_tmp1
.import ec_aff2g_256_x, ec_aff2g_256_y
.import ec_anchor1_x, ec_anchor2_x, ec_anchor3_x, ec_anchor4_x
.import ec_anchor5_x, ec_anchor6_x, ec_anchor7_x, ec_anchor8_x
.import ec_anchor1_y, ec_anchor2_y, ec_anchor3_y, ec_anchor4_y
.import ec_anchor5_y, ec_anchor6_y, ec_anchor7_y, ec_anchor8_y
.import cm_k, mul_dma_lo
.import ec_sc_byte, ec_sc_mask
.import ec_base_x, ec_base_y
.import var_wnaf, var_wnaf_len, var_wnaf_len_hi
.import var_tbl_base, var_jac_save, var_neg_y, var_zero32

; --- constants imports ---
.import reu_c64_lo, reu_c64_hi, reu_reu_lo, reu_reu_hi
.import reu_reu_bank, reu_len_lo, reu_len_hi
.import reu_addr_ctrl, reu_command

; =============================================================================
; ec_point_double: ec_p3 = 2 * ec_p1 (Jacobian)
; Formula for a = -3 (P-256):
;   M = 3*(X1 - Z1^2)*(X1 + Z1^2)
;   S = 4*X1*Y1^2
;   X3 = M^2 - 2*S
;   Y3 = M*(S - X3) - 8*Y1^4
;   Z3 = 2*Y1*Z1
; =============================================================================
ec_point_double:
        ; Check Z1 == 0 (point at infinity)
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        jsr fp_is_zero
        bne @dbl_notinf
        ; Result = infinity (zero all of ec_p3)
        ldy #95
        lda #0
@dbl_ci:
        sta ec_p3,y
        dey
        bpl @dbl_ci
        rts

@dbl_notinf:
        jsr ec_set_modp

        ; t1 = Z1^2
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        lda #<(ec_p1+64)
        sta fp_src2
        lda #>(ec_p1+64)
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr ec_sqrp             ; t1 = Z1^2

        ; t2 = X1 - t1
        lda #<ec_p1
        sta fp_src1
        lda #>ec_p1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr fp_mod_sub          ; t2 = X1 - Z1^2

        ; t3 = X1 + t1
        lda #<ec_p1
        sta fp_src1
        lda #>ec_p1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr fp_mod_add          ; t3 = X1 + Z1^2

        ; t4 = t2 * t3 = (X1-Z^2)(X1+Z^2)
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = X1^2 - Z1^4

        ; M = 3*t4: t5 = 2*t4, then t2 = t5 + t4 = 3*t4
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr fp_mod_add          ; t5 = 2*t4

        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr fp_mod_add          ; t2 = M = 3*(X1^2 - Z1^4)

        ; t3 = Y1^2
        lda #<(ec_p1+32)
        sta fp_src1
        lda #>(ec_p1+32)
        sta fp_src1+1
        lda #<(ec_p1+32)
        sta fp_src2
        lda #>(ec_p1+32)
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_sqrp             ; t3 = Y1^2

        ; t4 = X1 * Y1^2
        lda #<ec_p1
        sta fp_src1
        lda #>ec_p1
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = X1*Y1^2

        ; S = 4*X1*Y1^2: t5 = 2*t4, then t1 = 2*t5 = 4*t4
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr fp_mod_add          ; t5 = 2*X1*Y1^2

        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t5
        sta fp_src2
        lda #>ec_t5
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr fp_mod_add          ; t1 = S = 4*X1*Y1^2

        ; X3 = M^2 - 2*S
        ; t4 = M^2
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_sqrp             ; t4 = M^2

        ; t5 = 2*S
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr fp_mod_add          ; t5 = 2*S

        ; X3 = t4 - t5
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t5
        sta fp_src2
        lda #>ec_t5
        sta fp_src2+1
        lda #<ec_p3
        sta fp_dst
        lda #>ec_p3
        sta fp_dst+1
        jsr fp_mod_sub          ; X3 = M^2 - 2S

        ; Y3 = M*(S - X3) - 8*Y1^4
        ; t4 = S - X3
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_p3
        sta fp_src2
        lda #>ec_p3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr fp_mod_sub          ; t4 = S - X3

        ; t5 = M*(S - X3)
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr ec_mulp             ; t5 = M*(S-X3)

        ; t4 = Y1^4 = t3^2
        lda #<ec_t3
        sta fp_src1
        lda #>ec_t3
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_sqrp             ; t4 = Y1^4

        ; 8*Y1^4: t6 = 2*t4, t4 = 2*t6, t6 = 2*t4
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr fp_mod_add          ; t6 = 2*Y1^4

        lda #<ec_t6
        sta fp_src1
        lda #>ec_t6
        sta fp_src1+1
        lda #<ec_t6
        sta fp_src2
        lda #>ec_t6
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr fp_mod_add          ; t4 = 4*Y1^4

        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr fp_mod_add          ; t6 = 8*Y1^4

        ; Y3 = t5 - t6
        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t6
        sta fp_src2
        lda #>ec_t6
        sta fp_src2+1
        lda #<(ec_p3+32)
        sta fp_dst
        lda #>(ec_p3+32)
        sta fp_dst+1
        jsr fp_mod_sub          ; Y3 = M*(S-X3) - 8*Y1^4

        ; Z3 = 2*Y1*Z1
        ; t1 = Y1*Z1
        lda #<(ec_p1+32)
        sta fp_src1
        lda #>(ec_p1+32)
        sta fp_src1+1
        lda #<(ec_p1+64)
        sta fp_src2
        lda #>(ec_p1+64)
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr ec_mulp             ; t1 = Y1*Z1

        ; Z3 = 2*t1
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<(ec_p3+64)
        sta fp_dst
        lda #>(ec_p3+64)
        sta fp_dst+1
        jsr fp_mod_add          ; Z3 = 2*Y1*Z1

        rts

; =============================================================================
; ec_point_add: ec_p3 = ec_p1 + ec_p2
; P1 is Jacobian (X1,Y1,Z1). P2 is AFFINE (X2,Y2, Z2 assumed 1).
;
;   U2 = X2*Z1^2,  S2 = Y2*Z1^3
;   H = U2 - X1,   R = S2 - Y1
;   If H==0: if R==0 -> double, else -> infinity
;   X3 = R^2 - H^3 - 2*X1*H^2
;   Y3 = R*(X1*H^2 - X3) - Y1*H^3
;   Z3 = H*Z1
; =============================================================================
ec_point_add:
        ; If P1 is infinity (Z1==0): result = P2 with Z=1
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        jsr fp_is_zero
        bne @add_p1ok

        ; Copy P2 X to P3 X
        ldy #31
@add_cpx:
        lda ec_p2,y
        sta ec_p3,y
        dey
        bpl @add_cpx
        ; Copy P2 Y to P3 Y
        ldy #31
@add_cpy:
        lda ec_p2+32,y
        sta ec_p3+32,y
        dey
        bpl @add_cpy
        ; Set Z = 1 (little-endian: byte 0 = 1, rest = 0)
        ldy #31
        lda #0
@add_clz:
        sta ec_p3+64,y
        dey
        bpl @add_clz
        lda #1
        sta ec_p3+64            ; Z byte 0 = 1 (LSB in little-endian)
        rts

@add_p1ok:
        jsr ec_set_modp

        ; t1 = Z1^2
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        lda #<(ec_p1+64)
        sta fp_src2
        lda #>(ec_p1+64)
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr ec_sqrp             ; t1 = Z1^2

        ; t2 = X2*Z1^2 = U2
        lda #<ec_p2
        sta fp_src1
        lda #>ec_p2
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr ec_mulp             ; t2 = U2

        ; t3 = Z1^3 = Z1*t1
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_mulp             ; t3 = Z1^3

        ; t4 = Y2*Z1^3 = S2
        lda #<(ec_p2+32)
        sta fp_src1
        lda #>(ec_p2+32)
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = S2

        ; H = U2 - X1 = t2 - X1 -> t1
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_p1
        sta fp_src2
        lda #>ec_p1
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr fp_mod_sub          ; t1 = H = U2 - X1

        ; R = S2 - Y1 = t4 - Y1 -> t2
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<(ec_p1+32)
        sta fp_src2
        lda #>(ec_p1+32)
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr fp_mod_sub          ; t2 = R = S2 - Y1

        ; Check H == 0
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        jsr fp_is_zero
        bne @add_h_nonzero

        ; H == 0: check R
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        jsr fp_is_zero
        bne @add_set_inf
        ; H==0, R==0: points are equal, double P1
        jmp ec_point_double

@add_set_inf:
        ; H==0, R!=0: inverse points, result = infinity
        ldy #95
        lda #0
@add_sinf:
        sta ec_p3,y
        dey
        bpl @add_sinf
        rts

@add_h_nonzero:
        ; t3 = H^2
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_sqrp             ; t3 = H^2

        ; t4 = H^3 = H*H^2
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = H^3

        ; t5 = X1*H^2
        lda #<ec_p1
        sta fp_src1
        lda #>ec_p1
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr ec_mulp             ; t5 = X1*H^2

        ; X3 = R^2 - H^3 - 2*X1*H^2
        ; t3 = R^2
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_sqrp             ; t3 = R^2

        ; t3 = R^2 - H^3
        lda #<ec_t3
        sta fp_src1
        lda #>ec_t3
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr fp_mod_sub          ; t3 = R^2 - H^3

        ; t6 = 2*X1*H^2
        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t5
        sta fp_src2
        lda #>ec_t5
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr fp_mod_add          ; t6 = 2*X1*H^2

        ; X3 = t3 - t6
        lda #<ec_t3
        sta fp_src1
        lda #>ec_t3
        sta fp_src1+1
        lda #<ec_t6
        sta fp_src2
        lda #>ec_t6
        sta fp_src2+1
        lda #<ec_p3
        sta fp_dst
        lda #>ec_p3
        sta fp_dst+1
        jsr fp_mod_sub          ; X3

        ; Y3 = R*(X1*H^2 - X3) - Y1*H^3
        ; t3 = X1*H^2 - X3 = t5 - X3
        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_p3
        sta fp_src2
        lda #>ec_p3
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr fp_mod_sub          ; t3 = X1*H^2 - X3

        ; t5 = R * t3
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr ec_mulp             ; t5 = R*(X1*H^2 - X3)

        ; t6 = Y1*H^3
        lda #<(ec_p1+32)
        sta fp_src1
        lda #>(ec_p1+32)
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr ec_mulp             ; t6 = Y1*H^3

        ; Y3 = t5 - t6
        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t6
        sta fp_src2
        lda #>ec_t6
        sta fp_src2+1
        lda #<(ec_p3+32)
        sta fp_dst
        lda #>(ec_p3+32)
        sta fp_dst+1
        jsr fp_mod_sub          ; Y3

        ; Z3 = H*Z1 = t1*Z1
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<(ec_p1+64)
        sta fp_src2
        lda #>(ec_p1+64)
        sta fp_src2+1
        lda #<(ec_p3+64)
        sta fp_dst
        lda #>(ec_p3+64)
        sta fp_dst+1
        jsr ec_mulp             ; Z3 = H*Z1

        rts

; =============================================================================
; ec_scalar_mul: ec_p3 = k * G
; k is a 32-byte scalar pointed to by (ec_scalar_ptr), BIG-ENDIAN byte order.
; Uses 4-bit windowed method with precomputed table T[0..15] in REU bank 2.
; Each T[i] = i*G stored as 64-byte AFFINE point (X,Y).
; T[0] is never fetched (nibble=0 skips addition).
; Result in ec_p3 (Jacobian).
;
; Cost: 64 nibbles -> 256 doublings (same) but only ~32 additions (vs ~128).
; Precompute: 14 point_adds + 15 jacobian_to_affine conversions (one-time).
; =============================================================================

; --- REU DMA: stash 64 bytes (affine X,Y) to REU table slot ---
; Input: A = table index (0..15)
; Source: ec_affine_x (64 consecutive bytes: ec_affine_x + ec_affine_y)
sm256_reu_stash_affine:
        sta sm256_reu_idx
        jsr sm256_calc_offset_64  ; compute sm256_reu_off_lo/hi = idx * 64
        lda #<ec_affine_x
        sta reu_c64_lo
        lda #>ec_affine_x
        sta reu_c64_hi
        lda sm256_reu_off_lo
        sta reu_reu_lo
        lda sm256_reu_off_hi
        sta reu_reu_hi
        lda #2
        sta reu_reu_bank
        lda #64
        sta reu_len_lo
        lda #0
        sta reu_len_hi
        sta reu_addr_ctrl
        lda #$B0                ; execute + autoload + STASH
        sta reu_command
        jmp sm256_reu_restore

; --- REU DMA: fetch 64 bytes (affine X,Y) from REU table slot to ec_p2 ---
; Input: A = table index (1..15)
sm256_reu_fetch_affine:
        sta sm256_reu_idx
        jsr sm256_calc_offset_64
        lda #<ec_p2
        sta reu_c64_lo
        lda #>ec_p2
        sta reu_c64_hi
        lda sm256_reu_off_lo
        sta reu_reu_lo
        lda sm256_reu_off_hi
        sta reu_reu_hi
        lda #2
        sta reu_reu_bank
        lda #64
        sta reu_len_lo
        lda #0
        sta reu_len_hi
        sta reu_addr_ctrl
        lda #$B1                ; execute + autoload + FETCH
        sta reu_command
        jmp sm256_reu_restore

; --- Calculate offset = idx * 64 (idx in 0..255 -> 16-bit result 0..16320) ---
sm256_calc_offset_64:
        lda sm256_reu_idx
        asl                     ; *2
        asl                     ; *4
        asl                     ; *8
        asl                     ; *16
        asl                     ; *32
        asl                     ; *64 (top two bits of idx discarded here)
        sta sm256_reu_off_lo
        lda sm256_reu_idx
        lsr                     ; high-byte = idx >> 2
        lsr
        sta sm256_reu_off_hi
        rts

; --- Restore mul-table REU registers after point DMA ---
sm256_reu_restore:
        lda #<mul_dma_lo
        sta reu_c64_lo
        lda #>mul_dma_lo
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo
        sta reu_len_lo
        sta reu_addr_ctrl
        lda #2
        sta reu_len_hi
        rts

; --- Working variables ---
sm256_reu_idx:    .byte 0
sm256_reu_off_lo: .byte 0
sm256_reu_off_hi: .byte 0
sm256_reu_tmp:    .word 0
sm256_nibble_val: .byte 0         ; current nibble value

; =============================================================================
; ec_precompute_256: Build Lim-Lee 8-way fixed-base comb table for P-256
; (Wave 7a h=8).
;
; Comb parameters: h = 8 sub-scalars, a = 32 bits each (h*a = 256).
; Anchors: A_p = 2^(32*(p-1)) * G for p = 1..8.
;   A1 = G, A2 = 2^32 * G, ..., A8 = 2^224 * G.
; Each non-trivial anchor A_{p+1} is built by 32 doublings of A_p.
; Table T[j] for j in 1..255:
;   T[j] = sum over p=0..7 of ((j>>p) & 1) * A_{p+1}
; Bit p of j corresponds to sub-scalar K_p (matches ec_scalar_mul).
; T[0] is the identity and is never fetched.
;
; Storage: 256 slots * 64-byte affine (X,Y) in REU bank 2 at offset
; $0000..$3FFF (16 KB). Slot 0 is never fetched.
;
; Called once at init. Uses 224 ec_point_doubles (7*32 for anchors A2..A8),
; plus 762 mixed ec_point_adds (sum over j=1..255 of popcount(j)-1), plus
; 255 jacobian_to_affine conversions (T[1..255]). Boot cost ~25 Mcyc.
; =============================================================================
ec_precompute_256:
        jsr ec_set_modp

        ; ----- A1 = G affine: store directly into ec_anchor1_x/y. -----
        ldy #31
@cmp_a1x:
        lda ec_gx256,y
        sta ec_anchor1_x,y
        dey
        bpl @cmp_a1x
        ldy #31
@cmp_a1y:
        lda ec_gy256,y
        sta ec_anchor1_y,y
        dey
        bpl @cmp_a1y

        ; ----- Build A2..A8: each via 32 doublings from the previous. -----
        jsr @cmp_load_p1_g              ; ec_p1 = G (Jacobian, Z=1)

        ; A2 = 2^32 * G
        lda #32
        jsr @cmp_double_p1_n
        jsr @cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        ldy #31
@cmp_sa2x:
        lda ec_affine_x,y
        sta ec_anchor2_x,y
        dey
        bpl @cmp_sa2x
        ldy #31
@cmp_sa2y:
        lda ec_affine_y,y
        sta ec_anchor2_y,y
        dey
        bpl @cmp_sa2y

        ; A3 = 2^64 * G
        lda #32
        jsr @cmp_double_p1_n
        jsr @cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        ldy #31
@cmp_sa3x:
        lda ec_affine_x,y
        sta ec_anchor3_x,y
        dey
        bpl @cmp_sa3x
        ldy #31
@cmp_sa3y:
        lda ec_affine_y,y
        sta ec_anchor3_y,y
        dey
        bpl @cmp_sa3y

        ; A4 = 2^96 * G
        lda #32
        jsr @cmp_double_p1_n
        jsr @cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        ldy #31
@cmp_sa4x:
        lda ec_affine_x,y
        sta ec_anchor4_x,y
        dey
        bpl @cmp_sa4x
        ldy #31
@cmp_sa4y:
        lda ec_affine_y,y
        sta ec_anchor4_y,y
        dey
        bpl @cmp_sa4y

        ; A5 = 2^128 * G
        lda #32
        jsr @cmp_double_p1_n
        jsr @cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        ldy #31
@cmp_sa5x:
        lda ec_affine_x,y
        sta ec_anchor5_x,y
        dey
        bpl @cmp_sa5x
        ldy #31
@cmp_sa5y:
        lda ec_affine_y,y
        sta ec_anchor5_y,y
        dey
        bpl @cmp_sa5y

        ; A6 = 2^160 * G
        lda #32
        jsr @cmp_double_p1_n
        jsr @cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        ldy #31
@cmp_sa6x:
        lda ec_affine_x,y
        sta ec_anchor6_x,y
        dey
        bpl @cmp_sa6x
        ldy #31
@cmp_sa6y:
        lda ec_affine_y,y
        sta ec_anchor6_y,y
        dey
        bpl @cmp_sa6y

        ; A7 = 2^192 * G
        lda #32
        jsr @cmp_double_p1_n
        jsr @cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        ldy #31
@cmp_sa7x:
        lda ec_affine_x,y
        sta ec_anchor7_x,y
        dey
        bpl @cmp_sa7x
        ldy #31
@cmp_sa7y:
        lda ec_affine_y,y
        sta ec_anchor7_y,y
        dey
        bpl @cmp_sa7y

        ; A8 = 2^224 * G
        lda #32
        jsr @cmp_double_p1_n
        jsr @cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        ldy #31
@cmp_sa8x:
        lda ec_affine_x,y
        sta ec_anchor8_x,y
        dey
        bpl @cmp_sa8x
        ldy #31
@cmp_sa8y:
        lda ec_affine_y,y
        sta ec_anchor8_y,y
        dey
        bpl @cmp_sa8y

        ; ----- Build T[j] for j = 1..255 by subset-sum over 8 anchors. -----
        lda #1
        sta ec_sc_byte                  ; j counter (wraps to 0 after 255)
@cmp_tloop:
        lda #0
        sta cm_seeded
        lda ec_sc_byte
        and #$01
        beq @cmp_tj_b1
        lda #0
        jsr @cmp_accum_anchor
@cmp_tj_b1:
        lda ec_sc_byte
        and #$02
        beq @cmp_tj_b2
        lda #1
        jsr @cmp_accum_anchor
@cmp_tj_b2:
        lda ec_sc_byte
        and #$04
        beq @cmp_tj_b3
        lda #2
        jsr @cmp_accum_anchor
@cmp_tj_b3:
        lda ec_sc_byte
        and #$08
        beq @cmp_tj_b4
        lda #3
        jsr @cmp_accum_anchor
@cmp_tj_b4:
        lda ec_sc_byte
        and #$10
        beq @cmp_tj_b5
        lda #4
        jsr @cmp_accum_anchor
@cmp_tj_b5:
        lda ec_sc_byte
        and #$20
        beq @cmp_tj_b6
        lda #5
        jsr @cmp_accum_anchor
@cmp_tj_b6:
        lda ec_sc_byte
        and #$40
        beq @cmp_tj_b7
        lda #6
        jsr @cmp_accum_anchor
@cmp_tj_b7:
        lda ec_sc_byte
        and #$80
        beq @cmp_tj_done
        lda #7
        jsr @cmp_accum_anchor
@cmp_tj_done:
        ; ec_p1 holds T[j] in Jacobian. Convert to affine and stash.
        jsr @cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        lda ec_sc_byte
        jsr sm256_reu_stash_affine
        inc ec_sc_byte
        bne @cmp_tloop                  ; loop until ec_sc_byte wraps 255->0
        rts

; --- Internal helper: load ec_p1 = G as Jacobian (Z=1). ---
@cmp_load_p1_g:
        ldy #31
@cmp_lpg_x:
        lda ec_gx256,y
        sta ec_p1,y
        dey
        bpl @cmp_lpg_x
        ldy #31
@cmp_lpg_y:
        lda ec_gy256,y
        sta ec_p1+32,y
        dey
        bpl @cmp_lpg_y
        ldy #31
        lda #0
@cmp_lpg_z:
        sta ec_p1+64,y
        dey
        bpl @cmp_lpg_z
        lda #1
        sta ec_p1+64
        rts

; --- Internal helper: ec_p1 = 2^A * ec_p1 (A successive doublings). ---
; A in 1..255 (uses ec_sc_mask as counter so as not to clobber ec_sc_byte).
@cmp_double_p1_n:
        sta ec_sc_mask
@cmp_dpn_loop:
        jsr ec_point_double
        ldy #95
@cmp_dpn_cp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl @cmp_dpn_cp
        dec ec_sc_mask
        bne @cmp_dpn_loop
        rts

; --- Internal helper: copy ec_p1 -> ec_p3 (96 bytes). ---
@cmp_p1_to_p3:
        ldy #95
@cmp_pp3_cp:
        lda ec_p1,y
        sta ec_p3,y
        dey
        bpl @cmp_pp3_cp
        rts

; --- Internal helper: accumulate anchor[A] into ec_p1 (Jacobian). ---
; If cm_seeded == 0: copy anchor into ec_p1 with Z=1, set cm_seeded=1.
; Else: copy anchor into ec_p2 (affine), call ec_point_add, copy ec_p3->ec_p1.
; A in 0..7 (anchor index).
@cmp_accum_anchor:
        sta cm_anch_idx
        lda cm_seeded
        bne @cmp_acc_add
        ; Seed: ec_p1 = anchor (Z=1)
        lda cm_anch_idx
        jsr @cmp_load_anchor_p1
        lda #1
        sta cm_seeded
        rts
@cmp_acc_add:
        lda cm_anch_idx
        jsr @cmp_load_anchor_p2
        jsr ec_point_add
        ldy #95
@cmp_acc_cp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl @cmp_acc_cp
        rts

; --- Load anchor[A] into ec_p1 (Jacobian, Z=1). A in 0..7. ---
@cmp_load_anchor_p1:
        asl
        tax
        lda @cmp_anchor_tbl,x
        sta zp_ptr1
        lda @cmp_anchor_tbl+1,x
        sta zp_ptr1+1
        ; Copy 32 X bytes from (zp_ptr1) to ec_p1
        ldy #31
@cmp_lap1_x:
        lda (zp_ptr1),y
        sta ec_p1,y
        dey
        bpl @cmp_lap1_x
        ; Advance pointer by 32 to Y coordinate
        lda zp_ptr1
        clc
        adc #32
        sta zp_ptr1
        bcc :+
        inc zp_ptr1+1
:
        ldy #31
@cmp_lap1_y:
        lda (zp_ptr1),y
        sta ec_p1+32,y
        dey
        bpl @cmp_lap1_y
        ldy #31
        lda #0
@cmp_lap1_z:
        sta ec_p1+64,y
        dey
        bpl @cmp_lap1_z
        lda #1
        sta ec_p1+64
        rts

; --- Load anchor[A] into ec_p2 (affine X,Y; Z slot unused). A in 0..7. ---
@cmp_load_anchor_p2:
        asl
        tax
        lda @cmp_anchor_tbl,x
        sta zp_ptr1
        lda @cmp_anchor_tbl+1,x
        sta zp_ptr1+1
        ldy #31
@cmp_lap2_x:
        lda (zp_ptr1),y
        sta ec_p2,y
        dey
        bpl @cmp_lap2_x
        lda zp_ptr1
        clc
        adc #32
        sta zp_ptr1
        bcc :+
        inc zp_ptr1+1
:
        ldy #31
@cmp_lap2_y:
        lda (zp_ptr1),y
        sta ec_p2+32,y
        dey
        bpl @cmp_lap2_y
        rts

; --- Anchor X-base address table (Y is anchor_x + 32, contiguous in data). ---
@cmp_anchor_tbl:
        .word ec_anchor1_x
        .word ec_anchor2_x
        .word ec_anchor3_x
        .word ec_anchor4_x
        .word ec_anchor5_x
        .word ec_anchor6_x
        .word ec_anchor7_x
        .word ec_anchor8_x

; =============================================================================
; ec_scalar_mul: ec_p3 = k * G using an 8-way Lim-Lee fixed-base comb (Wave 7a).
;
; k is a 32-byte scalar pointed to by (ec_scalar_ptr), BIG-ENDIAN byte order.
; The 256-bit scalar is split into K7||K6||...||K0 (each 32 bits = 4 bytes,
; K0 = LSBs). The comb table T[1..255] in REU bank 2 offset $0000 holds
;     T[j] = sum over p=0..7 of ((j>>p) & 1) * A_{p+1}
; where A_p = 2^(32*(p-1)) * G. Bit p of j corresponds to sub-scalar K_p.
;
; For each iteration b = 31 downto 0:
;   - double R
;   - idx = sum over p=0..7 of bit_b(K_p) << p
;   - if idx != 0: R += T[idx] (mixed Jacobian + affine add)
; The first non-zero idx seeds R (was point at infinity); tracked by cm_r_inf.
;
; Cost: 32 doublings + ~32 mixed adds (vs 64 doublings + ~60 adds for h=4).
;
; Result in ec_p3 (Jacobian).
; REQUIRES: ec_precompute_256 must have been called first.
; =============================================================================
ec_scalar_mul:
        ; --- Defensive REU register init (issue #33-class defence;
        ; see c64-x25519 commit 817f525). The per-row DMA in fp_mul/sqr
        ; trusts reu_reu_lo / reu_addr_ctrl remain 0 from reu_mul_init.
        ; Defence-in-depth at the public surface; the inner primitives
        ; are also patched.
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        ; --- Transpose 32-byte BE scalar -> cm_k little-endian ---
        ; cm_k[i] = scalar[31 - i]; cm_k[0..3] = K0 (LSBs), ..., cm_k[28..31] = K7.
        ldy #31                 ; BE source index
        ldx #0                  ; LE destination index
@cm_xpose:
        lda (ec_scalar_ptr),y
        sta cm_k,x
        inx
        dey
        bpl @cm_xpose

        ; --- Init state ---
        lda #3
        sta cm_byte_off         ; bit 31 of each K_p lives in cm_k[3 + 4*p]
        lda #$80
        sta cm_bit_mask
        lda #32
        sta cm_loop_ctr
        lda #1
        sta cm_r_inf            ; R starts at the point at infinity

        jsr ec_set_modp

@cm_loop:
        ; --- Double R (skip if R is still infinity) ---
        lda cm_r_inf
        bne @cm_skip_double
        jsr ec_point_double
        ldy #95
@cm_dcp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl @cm_dcp
@cm_skip_double:

        ; --- Extract idx (8 bits) from current bit position, K7..K0 -----
        lda #0
        sta cm_idx
        ldx cm_byte_off

        lda cm_k+28,x           ; K7
        and cm_bit_mask
        beq @cm_b7z
        lda #$80
        ora cm_idx
        sta cm_idx
@cm_b7z:
        lda cm_k+24,x           ; K6
        and cm_bit_mask
        beq @cm_b6z
        lda #$40
        ora cm_idx
        sta cm_idx
@cm_b6z:
        lda cm_k+20,x           ; K5
        and cm_bit_mask
        beq @cm_b5z
        lda #$20
        ora cm_idx
        sta cm_idx
@cm_b5z:
        lda cm_k+16,x           ; K4
        and cm_bit_mask
        beq @cm_b4z
        lda #$10
        ora cm_idx
        sta cm_idx
@cm_b4z:
        lda cm_k+12,x           ; K3
        and cm_bit_mask
        beq @cm_b3z
        lda #$08
        ora cm_idx
        sta cm_idx
@cm_b3z:
        lda cm_k+8,x            ; K2
        and cm_bit_mask
        beq @cm_b2z
        lda #$04
        ora cm_idx
        sta cm_idx
@cm_b2z:
        lda cm_k+4,x            ; K1
        and cm_bit_mask
        beq @cm_b1z
        lda #$02
        ora cm_idx
        sta cm_idx
@cm_b1z:
        lda cm_k+0,x            ; K0
        and cm_bit_mask
        beq @cm_b0z
        lda #$01
        ora cm_idx
        sta cm_idx
@cm_b0z:

        ; --- Advance bit position (next-lower bit) ---
        lsr cm_bit_mask
        bne @cm_after_advance
        lda #$80
        sta cm_bit_mask
        dec cm_byte_off
@cm_after_advance:

        ; --- If idx == 0, no addition this iteration ---
        lda cm_idx
        beq @cm_after_add

        ; --- Fetch T[idx] (affine) into ec_p2 ---
        lda cm_idx
        jsr sm256_reu_fetch_affine

        ; --- If R was infinity, seed R = T[idx] (Z=1) and clear flag ---
        lda cm_r_inf
        beq @cm_real_add
        ldy #31
@cm_seed_x:
        lda ec_p2,y
        sta ec_p1,y
        dey
        bpl @cm_seed_x
        ldy #31
@cm_seed_y:
        lda ec_p2+32,y
        sta ec_p1+32,y
        dey
        bpl @cm_seed_y
        ldy #31
        lda #0
@cm_seed_z:
        sta ec_p1+64,y
        dey
        bpl @cm_seed_z
        lda #1
        sta ec_p1+64
        lda #0
        sta cm_r_inf
        jmp @cm_after_add

@cm_real_add:
        jsr ec_point_add
        ldy #95
@cm_acp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl @cm_acp

@cm_after_add:
        dec cm_loop_ctr
        beq @cm_done
        jmp @cm_loop

@cm_done:
        ; --- If R is still infinity, return all-zero point. ---
        lda cm_r_inf
        beq @cm_copy_out
        ldy #95
        lda #0
@cm_zinf:
        sta ec_p3,y
        dey
        bpl @cm_zinf
        rts

@cm_copy_out:
        ; --- Final result currently lives in ec_p1; copy to ec_p3. ---
        ldy #95
@cm_finc:
        lda ec_p1,y
        sta ec_p3,y
        dey
        bpl @cm_finc
        rts

; --- Comb scalar-mul state vars ---
cm_byte_off:    .byte 0
cm_bit_mask:    .byte 0
cm_loop_ctr:    .byte 0
cm_idx:         .byte 0
cm_r_inf:       .byte 0
cm_seeded:      .byte 0         ; precompute helper
cm_anch_idx:    .byte 0         ; precompute helper

; =============================================================================
; ec_scalar_mul_var: variable-base scalar multiplication using width-4 w-NAF.
;   Average nonzero digit density 1/(w+1) = 1/5, so a 256-bit scalar emits
;   ~52 nonzero digits vs ~128 set bits in plain binary -- roughly 60% fewer
;   mixed-adds than the previous left-to-right double-and-add path.
;
; Precompute strategy (1 inversion path):
;   T[1] = Q affine (input).
;   T[3] = 2Q + Q (mixed-add); convert 3Q Jacobian -> affine.
;   T[5] = 3Q + 2Q (mixed-add against 2Q affine, computed once); convert.
;   T[7] = 5Q + 2Q (mixed-add against 2Q affine); convert.
;   Total: 4 jacobian->affine conversions (4 inversions) + 3 mixed-adds +
;   1 doubling. Amortised across ~76 saved point adds (vs plain).
;
; Negations are free: at digit-fetch time, if the signed w-NAF digit is
; negative we negate Y in var_neg_y via fp_mod_sub from var_zero32, and
; stage the table entry (X, -Y) into ec_p2 for the mixed-add.
;
; Input:  ec_scalar_ptr -> 32-byte BE scalar
;         ec_base_x, ec_base_y -> 32-byte LE affine base point
; Output: ec_p3 (Jacobian, 96 B)
; NOT re-entrant. Serialize with all other field/point ops.
; NOT constant-time (intended for ECDSA verify; scalar is public).
; =============================================================================
ec_scalar_mul_var:
        ; --- Defensive REU register init (issue #33-class defence;
        ; see ec_scalar_mul above and c64-x25519 commit 817f525).
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        jsr ec_set_modp

        ; --- Zero the var_zero32 scratch buffer once. Used as src1 in
        ;     fp_mod_sub for "0 - Y mod p" point-Y negation.
        ldy #31
        lda #0
@vz_zero:
        sta var_zero32,y
        dey
        bpl @vz_zero

        ; --- Transpose BE scalar -> LE work buffer var_k33 (32 + 1 carry byte). ---
        ldy #31
        ldx #0
@vxpose:
        lda (ec_scalar_ptr),y
        sta var_k33,x
        inx
        dey
        bpl @vxpose
        lda #0
        sta var_k33+32          ; high byte = 0 (room for carry from k+=1..7)

        ; --- Recode scalar to w-NAF digits in var_wnaf[0..len-1] (LSB first). ---
        jsr v_recode_wnaf

        ; --- Build precompute table {T[1]=Q, T[3], T[5], T[7]} affine. ---
        jsr v_precompute

        ; --- Scan w-NAF digits MSB->LSB, doubling and mixed-adding. ---
        lda #1
        sta var_r_inf           ; R = infinity

        ; Scan index (16-bit): start at (len_hi:len_lo) - 1, count down to 0.
        ; If len == 0, scalar was zero -> jump straight to done (R = infinity).
        lda var_wnaf_len
        ora var_wnaf_len_hi
        bne @v_scan_init
        jmp @v_scan_done
@v_scan_init:

        ; Set up scan_idx = len - 1.
        sec
        lda var_wnaf_len
        sbc #1
        sta v_scan_idx_lo
        lda var_wnaf_len_hi
        sbc #0
        sta v_scan_idx_hi

@v_scan_loop:
        ; --- Double R unless still infinity ---
        lda var_r_inf
        bne @v_sl_skip_double
        jsr ec_point_double
        ; 96-byte copy ec_p3 -> ec_p1 via X-counter (LDA clobbers Z; use DEX/BNE).
        ldx #96
        ldy #0
@v_sl_dcp:
        lda ec_p3,y
        sta ec_p1,y
        iny
        dex
        bne @v_sl_dcp
@v_sl_skip_double:

        ; --- Fetch current digit. Index lives in (v_scan_idx_hi:v_scan_idx_lo). ---
        ; If hi==0 we can index var_wnaf directly with Y.
        ; If hi==1, index 256..len-1; use self-modified address.
        lda v_scan_idx_hi
        bne @v_fetch_hi
        ldy v_scan_idx_lo
        lda var_wnaf,y
        jmp @v_have_digit
@v_fetch_hi:
        ; index >= 256: read var_wnaf+256+lo (only valid when len > 256).
        ldy v_scan_idx_lo
        lda var_wnaf+256,y
@v_have_digit:
        ; A = digit (two's complement signed). 0 -> just advance.
        bne @v_have_nonzero
        jmp @v_digit_zero
@v_have_nonzero:
        sta v_digit            ; save signed digit

        ; --- Compute |d| and (d < 0?) ---
        bpl @v_digit_pos
        ; d < 0: |d| = -d
        eor #$FF
        clc
        adc #1
        sta v_abs_d
        lda #1
        sta v_digit_neg
        jmp @v_have_abs
@v_digit_pos:
        sta v_abs_d
        lda #0
        sta v_digit_neg
@v_have_abs:
        ; v_abs_d in {1,3,5,7}. Table index = (|d|-1)/2 in {0,1,2,3}.
        ; Each table entry is 64 bytes (32 X + 32 Y) at var_tbl_base + idx*64.
        ; Compute offset = (|d|-1) * 32 (since |d|-1 in {0,2,4,6}).
        ; Equivalently: offset = (|d|-1) << 5. With |d| odd low byte, |d|-1 even.
        lda v_abs_d
        sec
        sbc #1                  ; |d|-1 in {0,2,4,6}
        ; multiply by 32: shift left 5 times. Result fits in one byte (max 192).
        asl
        asl
        asl
        asl
        asl                     ; offset = (|d|-1) * 32 in {0,64,128,192}
        sta v_tbl_off

        ; --- Stage P2 = T[|d|] (with Y negated if d < 0) ---
        ; Both source and destination indices ascend in lockstep so byte i of
        ; the table entry lands at byte i of ec_p2 (preserves LE order).
        ldx v_tbl_off
        ldy #0
@v_cpx:
        lda var_tbl_base,x      ; X-bytes (32 of them) at offset 0..31
        sta ec_p2,y
        inx
        iny
        cpy #32
        bne @v_cpx
        ; (X-offset advanced 32, now pointing at Y bytes of this entry.)
        ; ec_p2+32 = Y or -Y depending on v_digit_neg.
        lda v_digit_neg
        bne @v_neg_y

        ; Positive: copy Y bytes directly.
        ldy #0
@v_cpy:
        lda var_tbl_base,x
        sta ec_p2+32,y
        inx
        iny
        cpy #32
        bne @v_cpy
        jmp @v_have_p2

@v_neg_y:
        ; Negative: var_neg_y = 0 - Y mod p (via fp_mod_sub).
        ; First copy Y bytes into a scratch (use fp_tmp1 since field ops haven't
        ; been invoked yet for this digit).
        ldy #0
@v_neg_cpy:
        lda var_tbl_base,x
        sta fp_tmp1,y
        inx
        iny
        cpy #32
        bne @v_neg_cpy
        lda #<var_zero32
        sta fp_src1
        lda #>var_zero32
        sta fp_src1+1
        lda #<fp_tmp1
        sta fp_src2
        lda #>fp_tmp1
        sta fp_src2+1
        lda #<var_neg_y
        sta fp_dst
        lda #>var_neg_y
        sta fp_dst+1
        jsr fp_mod_sub          ; var_neg_y = (0 - Y) mod p
        ; Copy var_neg_y -> ec_p2+32.
        ldy #31
@v_cpy_neg:
        lda var_neg_y,y
        sta ec_p2+32,y
        dey
        bpl @v_cpy_neg

@v_have_p2:
        ; --- R += signed_d * Q ---
        lda var_r_inf
        beq @v_real_add_d

        ; R was infinity: seed R = (X, Y) Jacobian with Z=1.
        ldy #31
@v_seedx_d:
        lda ec_p2,y
        sta ec_p1,y
        dey
        bpl @v_seedx_d
        ldy #31
@v_seedy_d:
        lda ec_p2+32,y
        sta ec_p1+32,y
        dey
        bpl @v_seedy_d
        ldy #31
        lda #0
@v_seedz_d:
        sta ec_p1+64,y
        dey
        bpl @v_seedz_d
        lda #1
        sta ec_p1+64
        lda #0
        sta var_r_inf
        jmp @v_digit_zero

@v_real_add_d:
        jsr ec_point_add
        ; 96-byte copy ec_p3 -> ec_p1.
        ldx #96
        ldy #0
@v_sl_acp:
        lda ec_p3,y
        sta ec_p1,y
        iny
        dex
        bne @v_sl_acp

@v_digit_zero:
        ; --- Advance scan index ---
        lda v_scan_idx_lo
        bne @v_sl_dec_lo
        ; lo == 0: if hi == 0, we're done (we just processed digit 0).
        lda v_scan_idx_hi
        beq @v_scan_done
        dec v_scan_idx_hi
        lda #$FF
        sta v_scan_idx_lo
        jmp @v_scan_loop
@v_sl_dec_lo:
        dec v_scan_idx_lo
        jmp @v_scan_loop

@v_scan_done:
        ; --- Done. If R still infinity, return zero; else copy ec_p1 -> ec_p3. ---
        lda var_r_inf
        beq @v_copy_out
        ldx #96
        ldy #0
        lda #0
@v_zinf:
        sta ec_p3,y
        iny
        dex
        bne @v_zinf
        rts

@v_copy_out:
        ldx #96
        ldy #0
@v_finc:
        lda ec_p1,y
        sta ec_p3,y
        iny
        dex
        bne @v_finc
        rts

; -----------------------------------------------------------------------------
; v_recode_wnaf: read 33-byte LE scalar var_k33 (var_k33+32 = 0 initially),
;   emit signed w-NAF digits into var_wnaf, store length in
;   var_wnaf_len:var_wnaf_len_hi (lo:hi). Width 4 (max digit magnitude 7).
;
; Algorithm (Solinas):
;   i = 0
;   while k != 0:
;     if (k & 1):
;       d = k & 0x0F                 ; d in {1,3,5,7,9,11,13,15}
;       if d >= 8: d_signed = d - 16 ; k += (16 - d) i.e. positive
;                  store d | $F0     ; two's complement byte
;       else:      d_signed = d      ; k -= d
;                  store d
;     else:        d = 0; store 0
;     k >>= 1
;     i += 1
;
; HAZARD NOTES (per CLAUDE.md hazard family):
;   - The k +/- |d| step is a 32-byte multi-precision SBC/ADC chain. We use
;     X as the counter (DEX preserves C); Y as the index. CPY/CPX/CMP would
;     destroy the inter-ADC carry.
;   - The k >>= 1 step is a 33-byte multi-precision ROR chain. We use a
;     fresh CLC start and propagate via ROR (which both reads and writes C
;     in the right direction). Counter is X (DEX preserves C).
; -----------------------------------------------------------------------------
v_recode_wnaf:
        lda #0
        sta v_scan_idx_lo
        sta v_scan_idx_hi       ; reuse as write index during recoding

@vr_loop:
        ; Test k == 0. OR-fold all 33 bytes. NOTE: the BNE that exits the OR
        ; loop tests Z from DEX (always 1 on exit), not from A. We must
        ; restore Z = (A == 0?) before the BEQ. `cmp #0` is equivalent to
        ; testing A and sets Z without clobbering it (sets C also but we
        ; don't depend on C here).
        lda var_k33+0
        ldx #32
@vr_ortest:
        ora var_k33,x
        dex
        bne @vr_ortest
        cmp #0                  ; restore Z from A (final OR result)
        beq @vr_done            ; A == 0 -> all 33 bytes were zero

        lda var_k33+0
        and #1
        beq @vr_emit_zero

        ; --- k & 1 set: compute d in 1..15 ---
        lda var_k33+0
        and #$0F
        cmp #8
        bcs @vr_neg

        ; d in {1,3,5,7}: store +d, k -= d.
        sta v_abs_d             ; will reuse v_abs_d as scratch
        ; ---- emit positive digit ----
        ; v_abs_d = d  (1..7); store byte value d at var_wnaf[idx].
        jsr v_emit_digit_a      ; A still holds d (set right before jsr)
        ; (v_emit_digit_a expects A = digit byte; trashes Y.)
        ; ---- k -= d  ----
        sec
        lda var_k33+0
        sbc v_abs_d
        sta var_k33+0
        ldx #32                 ; propagate borrow through 32 more bytes
        ldy #1
@vr_sub_prop:
        lda var_k33,y
        sbc #0
        sta var_k33,y
        iny
        dex
        bne @vr_sub_prop
        jmp @vr_shift

@vr_neg:
        ; d in {9,11,13,15}: store (d | $F0) = d - 16 in two's complement.
        ; k += (16 - d).
        sta v_abs_d             ; save d (9..15)
        ora #$F0                ; encoded signed byte (-1..-7)
        jsr v_emit_digit_a
        ; compute (16 - d) and add to k.
        lda #16
        sec
        sbc v_abs_d             ; (16 - d) in {1,3,5,7}
        clc
        adc var_k33+0
        sta var_k33+0
        ldx #32
        ldy #1
@vr_add_prop:
        lda var_k33,y
        adc #0
        sta var_k33,y
        iny
        dex
        bne @vr_add_prop
        jmp @vr_shift

@vr_emit_zero:
        lda #0
        jsr v_emit_digit_a

@vr_shift:
        ; k >>= 1 across 33 bytes. Walk MSB -> LSB, ROR with initial CLC.
        ; X is the index (32..0) AND counter via BPL. ROR abs,X is the only
        ; available mode; DEX/BPL preserve C between iterations, ROR feeds
        ; its bit-0 into C for the next byte. Initial X = 32 = $20 has bit 7
        ; clear, so BPL takes the first iteration (forward-looking check
        ; per the BPL bit-7 hazard family).
        clc
        ldx #32
@vr_shr:
        ror var_k33,x
        dex
        bpl @vr_shr
        jmp @vr_loop

@vr_done:
        ; Store length in var_wnaf_len:var_wnaf_len_hi (= write index).
        lda v_scan_idx_lo
        sta var_wnaf_len
        lda v_scan_idx_hi
        sta var_wnaf_len_hi
        rts

; -----------------------------------------------------------------------------
; v_emit_digit_a: store A (already the encoded digit byte) at var_wnaf[idx];
;   advance idx (16-bit). Trashes Y. Preserves X (callers depend on it).
; -----------------------------------------------------------------------------
v_emit_digit_a:
        ; Use 16-bit index (v_scan_idx_hi:v_scan_idx_lo). When hi==0, store
        ; at var_wnaf,y; otherwise at var_wnaf+256,y.
        ldy v_scan_idx_hi
        bne @ved_hi
        ldy v_scan_idx_lo
        sta var_wnaf,y
        jmp @ved_adv
@ved_hi:
        ldy v_scan_idx_lo
        sta var_wnaf+256,y
@ved_adv:
        inc v_scan_idx_lo
        bne @ved_done
        inc v_scan_idx_hi
@ved_done:
        rts

; -----------------------------------------------------------------------------
; v_precompute: build affine table {T[1], T[3], T[5], T[7]} in var_tbl_base.
;
;   ec_p1 (Jacobian) is used as the running operand. Each precompute step:
;     1. Copy operand affine -> ec_p2 (for mixed-add).
;     2. ec_p1 = 2Q seeded or running Jacobian.
;     3. ec_point_add -> ec_p3.
;     4. Save ec_p3 to var_jac_save (since jacobian_to_affine doesn't clobber
;        ec_p3, but the next ec_point_add chain will).
;     5. ec_jacobian_to_affine -> ec_affine_x/y, copy into var_tbl_base entry.
;
;   T[1] = Q (no compute, just copy ec_base_x/y).
;   T[3] = 2Q + Q (mixed-add).  Need 2Q in Jacobian for the add, and 2Q in
;          affine to use as 2Q_aff source for T[5] and T[7].
;   T[5] = 3Q_Jac + 2Q_aff.
;   T[7] = 5Q_Jac + 2Q_aff.
;
; Cost: 4 jacobian_to_affine (2Q, 3Q, 5Q, 7Q), 1 doubling, 3 mixed-adds.
; -----------------------------------------------------------------------------
v_precompute:
        ; --- T[1] = Q (affine input): copy ec_base_x/y to var_tbl_base[0..63]. ---
        ldy #31
@vp_t1x:
        lda ec_base_x,y
        sta var_tbl_base+0,y
        dey
        bpl @vp_t1x
        ldy #31
@vp_t1y:
        lda ec_base_y,y
        sta var_tbl_base+32,y
        dey
        bpl @vp_t1y

        ; --- Seed ec_p1 = (Q, Z=1) Jacobian, then ec_point_double -> 2Q in ec_p3. ---
        ldy #31
@vp_seedx:
        lda ec_base_x,y
        sta ec_p1,y
        dey
        bpl @vp_seedx
        ldy #31
@vp_seedy:
        lda ec_base_y,y
        sta ec_p1+32,y
        dey
        bpl @vp_seedy
        ldy #31
        lda #0
@vp_seedz:
        sta ec_p1+64,y
        dey
        bpl @vp_seedz
        lda #1
        sta ec_p1+64
        jsr ec_point_double             ; ec_p3 = 2Q Jacobian

        ; Save 2Q Jacobian into var_jac_save (we'll need it for the next add).
        ldx #96
        ldy #0
@vp_sv2q:
        lda ec_p3,y
        sta var_jac_save,y
        iny
        dex
        bne @vp_sv2q

        ; Convert 2Q -> affine, store in ec_aff2g_256_x/y (persistent scratch).
        jsr ec_jacobian_to_affine
        ldy #31
@vp_2qax:
        lda ec_affine_x,y
        sta ec_aff2g_256_x,y
        dey
        bpl @vp_2qax
        ldy #31
@vp_2qay:
        lda ec_affine_y,y
        sta ec_aff2g_256_y,y
        dey
        bpl @vp_2qay

        ; --- T[3] = 2Q + Q.  ec_p1 = 2Q Jacobian (restore from save), ec_p2 = Q affine.
        ldx #96
        ldy #0
@vp_re2q:
        lda var_jac_save,y
        sta ec_p1,y
        iny
        dex
        bne @vp_re2q
        ldy #31
@vp_qax:
        lda ec_base_x,y
        sta ec_p2,y
        dey
        bpl @vp_qax
        ldy #31
@vp_qay:
        lda ec_base_y,y
        sta ec_p2+32,y
        dey
        bpl @vp_qay
        jsr ec_point_add                ; ec_p3 = 3Q Jacobian

        ; Save 3Q Jacobian.
        ldx #96
        ldy #0
@vp_sv3q:
        lda ec_p3,y
        sta var_jac_save,y
        iny
        dex
        bne @vp_sv3q

        ; Convert 3Q -> affine -> var_tbl_base[64..127].
        jsr ec_jacobian_to_affine
        ldy #31
@vp_t3x:
        lda ec_affine_x,y
        sta var_tbl_base+64,y
        dey
        bpl @vp_t3x
        ldy #31
@vp_t3y:
        lda ec_affine_y,y
        sta var_tbl_base+96,y
        dey
        bpl @vp_t3y

        ; --- T[5] = 3Q_Jac + 2Q_aff. ec_p1 = 3Q Jacobian, ec_p2 = 2Q affine. ---
        ldx #96
        ldy #0
@vp_re3q:
        lda var_jac_save,y
        sta ec_p1,y
        iny
        dex
        bne @vp_re3q
        ldy #31
@vp_2qax2:
        lda ec_aff2g_256_x,y
        sta ec_p2,y
        dey
        bpl @vp_2qax2
        ldy #31
@vp_2qay2:
        lda ec_aff2g_256_y,y
        sta ec_p2+32,y
        dey
        bpl @vp_2qay2
        jsr ec_point_add                ; ec_p3 = 5Q Jacobian

        ; Save 5Q.
        ldx #96
        ldy #0
@vp_sv5q:
        lda ec_p3,y
        sta var_jac_save,y
        iny
        dex
        bne @vp_sv5q

        ; Convert 5Q -> affine -> var_tbl_base[128..191].
        jsr ec_jacobian_to_affine
        ldy #31
@vp_t5x:
        lda ec_affine_x,y
        sta var_tbl_base+128,y
        dey
        bpl @vp_t5x
        ldy #31
@vp_t5y:
        lda ec_affine_y,y
        sta var_tbl_base+160,y
        dey
        bpl @vp_t5y

        ; --- T[7] = 5Q_Jac + 2Q_aff. ---
        ldx #96
        ldy #0
@vp_re5q:
        lda var_jac_save,y
        sta ec_p1,y
        iny
        dex
        bne @vp_re5q
        ldy #31
@vp_2qax3:
        lda ec_aff2g_256_x,y
        sta ec_p2,y
        dey
        bpl @vp_2qax3
        ldy #31
@vp_2qay3:
        lda ec_aff2g_256_y,y
        sta ec_p2+32,y
        dey
        bpl @vp_2qay3
        jsr ec_point_add                ; ec_p3 = 7Q Jacobian

        ; Convert 7Q -> affine -> var_tbl_base[192..255]. (Don't bother saving.)
        jsr ec_jacobian_to_affine
        ldy #31
@vp_t7x:
        lda ec_affine_x,y
        sta var_tbl_base+192,y
        dey
        bpl @vp_t7x
        ldy #31
@vp_t7y:
        lda ec_affine_y,y
        sta var_tbl_base+224,y
        dey
        bpl @vp_t7y
        rts

; --- ec_scalar_mul_var state vars (locally scoped; distinct from cm_*) ---
var_k33:         .res 33         ; LE scalar + 1 carry byte for w-NAF recoding
var_r_inf:       .byte 0
v_scan_idx_lo:   .byte 0
v_scan_idx_hi:   .byte 0
v_digit:         .byte 0
v_abs_d:         .byte 0
v_digit_neg:     .byte 0
v_tbl_off:       .byte 0

; =============================================================================
; ec_jacobian_to_affine: convert ec_p3 (Jacobian) to affine (x,y)
; Result: ec_affine_x, ec_affine_y (32 bytes each)
; Computes x = X/Z^2, y = Y/Z^3 using modular inverse.
; =============================================================================
ec_jacobian_to_affine:
        jsr ec_set_modp

        ; Compute Z^(-1)
        lda #<(ec_p3+64)
        sta fp_src1
        lda #>(ec_p3+64)
        sta fp_src1+1
        jsr fp_mod_inv          ; fp_r0 = Z^(-1)

        ; Copy Z^(-1) to ec_t1
        ldy #31
@jta_czi:
        lda fp_r0,y
        sta ec_t1,y
        dey
        bpl @jta_czi

        ; t2 = Z^(-2) = Z^(-1) * Z^(-1)
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr ec_mulp             ; t2 = Z^(-2)

        ; t3 = Z^(-3) = Z^(-2) * Z^(-1)
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_mulp             ; t3 = Z^(-3)

        ; x = X * Z^(-2)
        lda #<ec_p3
        sta fp_src1
        lda #>ec_p3
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_affine_x
        sta fp_dst
        lda #>ec_affine_x
        sta fp_dst+1
        jsr ec_mulp             ; affine_x = X*Z^(-2)

        ; y = Y * Z^(-3)
        lda #<(ec_p3+32)
        sta fp_src1
        lda #>(ec_p3+32)
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_affine_y
        sta fp_dst
        lda #>ec_affine_y
        sta fp_dst+1
        jsr ec_mulp             ; affine_y = Y*Z^(-3)

        rts
