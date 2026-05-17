.setcpu "6502"

; =============================================================================
; points384.s - P-384 point operations (Jacobian coordinates)
; ec_point_double_384, ec_point_add_384, ec_scalar_mul_384,
; ec_jacobian_to_affine_384
;
; All field elements are LITTLE-ENDIAN (byte 0 = LSB).
; Point layout: X = offset 0..47, Y = offset 48..95, Z = offset 96..143
; Point at infinity: Z = 0
; =============================================================================

.segment "CODE"

; --- Exports ---
.export ec_point_double_384, ec_point_add_384, ec_point_add_jj_384
.export ec_precompute_384, ec_scalar_mul_384
.export ec_scalar_mul_var_384
.export ec_jacobian_to_affine_384

; --- ZP imports ---
.importzp fp_src1, fp_src2, fp_dst, fp_misc, ec_scalar_ptr, zp_ptr1
.importzp zp_tmp1, zp_tmp2

; --- fp384 imports ---
.import fp_is_zero_384, fp_copy_384

; --- mod384 imports ---
.import ec_set_modp_384, ec_mulp_384, ec_sqrp_384
.import fp_mod_add_384, fp_mod_sub_384, fp_mod_inv_384, ec_p384

; --- curve384 imports ---
.import ec_gx384, ec_gy384

; --- data imports ---
.import ec384_p1, ec384_p2, ec384_p3
.import ec384_t1, ec384_t2, ec384_t3, ec384_t4, ec384_t5, ec384_t6, ec384_jj_tmp
.import ec384_affine_x, ec384_affine_y
.import fp384_r0, fp384_tmp1
.import ec_anchor1_384_x, ec_anchor2_384_x, ec_anchor3_384_x, ec_anchor4_384_x
.import ec_anchor5_384_x, ec_anchor6_384_x, ec_anchor7_384_x, ec_anchor8_384_x
.import ec_anchor1_384_y, ec_anchor2_384_y, ec_anchor3_384_y, ec_anchor4_384_y
.import ec_anchor5_384_y, ec_anchor6_384_y, ec_anchor7_384_y, ec_anchor8_384_y
.import cm_k_384, mul_dma_lo
.import ec384_sc_byte, ec384_sc_mask, ec384_precomp_i
.import ec_base384_x, ec_base384_y

; --- constants imports ---
.import reu_c64_lo, reu_c64_hi, reu_reu_lo, reu_reu_hi
.import reu_reu_bank, reu_len_lo, reu_len_hi
.import reu_addr_ctrl, reu_command

; REU bank holding the precompute table.
PRECOMP_REU_BANK = 2

; =============================================================================
; ec_point_double_384: ec384_p3 = 2 * ec384_p1 (Jacobian)
; Formula for a = -3 (P-384):
;   M = 3*(X1 - Z1^2)*(X1 + Z1^2)
;   S = 4*X1*Y1^2
;   X3 = M^2 - 2*S
;   Y3 = M*(S - X3) - 8*Y1^4
;   Z3 = 2*Y1*Z1
; =============================================================================
ec_point_double_384:
        ; Check Z1 == 0 (point at infinity)
        lda #<(ec384_p1+96)
        sta fp_src1
        lda #>(ec384_p1+96)
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @dbl384_notinf
        ; Result = infinity (zero all 144 bytes of ec384_p3).
        ; Count down through $00 via BNE (BPL would fail on $8F bit 7).
        ldy #144
        lda #0
@dbl384_ci:
        dey
        sta ec384_p3,y
        bne @dbl384_ci
        rts

@dbl384_notinf:
        jsr ec_set_modp_384

        ; t1 = Z1^2
        lda #<(ec384_p1+96)
        sta fp_src1
        lda #>(ec384_p1+96)
        sta fp_src1+1
        lda #<(ec384_p1+96)
        sta fp_src2
        lda #>(ec384_p1+96)
        sta fp_src2+1
        lda #<ec384_t1
        sta fp_dst
        lda #>ec384_t1
        sta fp_dst+1
        jsr ec_sqrp_384         ; t1 = Z1^2

        ; t2 = X1 - t1
        lda #<ec384_p1
        sta fp_src1
        lda #>ec384_p1
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t2
        sta fp_dst
        lda #>ec384_t2
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t2 = X1 - Z1^2

        ; t3 = X1 + t1
        lda #<ec384_p1
        sta fp_src1
        lda #>ec384_p1
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr fp_mod_add_384      ; t3 = X1 + Z1^2

        ; t4 = t2 * t3 = (X1-Z^2)(X1+Z^2)
        lda #<ec384_t2
        sta fp_src1
        lda #>ec384_t2
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr ec_mulp_384         ; t4 = X1^2 - Z1^4

        ; M = 3*t4: t5 = 2*t4, then t2 = t5 + t4 = 3*t4
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<ec384_t5
        sta fp_dst
        lda #>ec384_t5
        sta fp_dst+1
        jsr fp_mod_add_384      ; t5 = 2*t4

        lda #<ec384_t5
        sta fp_src1
        lda #>ec384_t5
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<ec384_t2
        sta fp_dst
        lda #>ec384_t2
        sta fp_dst+1
        jsr fp_mod_add_384      ; t2 = M = 3*(X1^2 - Z1^4)

        ; t3 = Y1^2
        lda #<(ec384_p1+48)
        sta fp_src1
        lda #>(ec384_p1+48)
        sta fp_src1+1
        lda #<(ec384_p1+48)
        sta fp_src2
        lda #>(ec384_p1+48)
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr ec_sqrp_384         ; t3 = Y1^2

        ; t4 = X1 * Y1^2
        lda #<ec384_p1
        sta fp_src1
        lda #>ec384_p1
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr ec_mulp_384         ; t4 = X1*Y1^2

        ; S = 4*X1*Y1^2: t5 = 2*t4, then t1 = 2*t5 = 4*t4
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<ec384_t5
        sta fp_dst
        lda #>ec384_t5
        sta fp_dst+1
        jsr fp_mod_add_384      ; t5 = 2*X1*Y1^2

        lda #<ec384_t5
        sta fp_src1
        lda #>ec384_t5
        sta fp_src1+1
        lda #<ec384_t5
        sta fp_src2
        lda #>ec384_t5
        sta fp_src2+1
        lda #<ec384_t1
        sta fp_dst
        lda #>ec384_t1
        sta fp_dst+1
        jsr fp_mod_add_384      ; t1 = S = 4*X1*Y1^2

        ; X3 = M^2 - 2*S
        ; t4 = M^2
        lda #<ec384_t2
        sta fp_src1
        lda #>ec384_t2
        sta fp_src1+1
        lda #<ec384_t2
        sta fp_src2
        lda #>ec384_t2
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr ec_sqrp_384         ; t4 = M^2

        ; t5 = 2*S
        lda #<ec384_t1
        sta fp_src1
        lda #>ec384_t1
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t5
        sta fp_dst
        lda #>ec384_t5
        sta fp_dst+1
        jsr fp_mod_add_384      ; t5 = 2*S

        ; X3 = t4 - t5
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        lda #<ec384_t5
        sta fp_src2
        lda #>ec384_t5
        sta fp_src2+1
        lda #<ec384_p3
        sta fp_dst
        lda #>ec384_p3
        sta fp_dst+1
        jsr fp_mod_sub_384      ; X3 = M^2 - 2S

        ; Y3 = M*(S - X3) - 8*Y1^4
        ; t4 = S - X3
        lda #<ec384_t1
        sta fp_src1
        lda #>ec384_t1
        sta fp_src1+1
        lda #<ec384_p3
        sta fp_src2
        lda #>ec384_p3
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t4 = S - X3

        ; t5 = M*(S - X3)
        lda #<ec384_t2
        sta fp_src1
        lda #>ec384_t2
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<ec384_t5
        sta fp_dst
        lda #>ec384_t5
        sta fp_dst+1
        jsr ec_mulp_384         ; t5 = M*(S-X3)

        ; t4 = Y1^4 = t3^2
        lda #<ec384_t3
        sta fp_src1
        lda #>ec384_t3
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr ec_sqrp_384         ; t4 = Y1^4

        ; 8*Y1^4: t6 = 2*t4, t4 = 2*t6, t6 = 2*t4
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<ec384_t6
        sta fp_dst
        lda #>ec384_t6
        sta fp_dst+1
        jsr fp_mod_add_384      ; t6 = 2*Y1^4

        lda #<ec384_t6
        sta fp_src1
        lda #>ec384_t6
        sta fp_src1+1
        lda #<ec384_t6
        sta fp_src2
        lda #>ec384_t6
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr fp_mod_add_384      ; t4 = 4*Y1^4

        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<ec384_t6
        sta fp_dst
        lda #>ec384_t6
        sta fp_dst+1
        jsr fp_mod_add_384      ; t6 = 8*Y1^4

        ; Y3 = t5 - t6
        lda #<ec384_t5
        sta fp_src1
        lda #>ec384_t5
        sta fp_src1+1
        lda #<ec384_t6
        sta fp_src2
        lda #>ec384_t6
        sta fp_src2+1
        lda #<(ec384_p3+48)
        sta fp_dst
        lda #>(ec384_p3+48)
        sta fp_dst+1
        jsr fp_mod_sub_384      ; Y3 = M*(S-X3) - 8*Y1^4

        ; Z3 = 2*Y1*Z1
        ; t1 = Y1*Z1
        lda #<(ec384_p1+48)
        sta fp_src1
        lda #>(ec384_p1+48)
        sta fp_src1+1
        lda #<(ec384_p1+96)
        sta fp_src2
        lda #>(ec384_p1+96)
        sta fp_src2+1
        lda #<ec384_t1
        sta fp_dst
        lda #>ec384_t1
        sta fp_dst+1
        jsr ec_mulp_384         ; t1 = Y1*Z1

        ; Z3 = 2*t1
        lda #<ec384_t1
        sta fp_src1
        lda #>ec384_t1
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<(ec384_p3+96)
        sta fp_dst
        lda #>(ec384_p3+96)
        sta fp_dst+1
        jsr fp_mod_add_384      ; Z3 = 2*Y1*Z1

        rts

; =============================================================================
; ec_point_add_384: ec384_p3 = ec384_p1 + ec384_p2
; P1 is Jacobian (X1,Y1,Z1). P2 is AFFINE (X2,Y2, Z2 assumed 1).
;
;   U2 = X2*Z1^2,  S2 = Y2*Z1^3
;   H = U2 - X1,   R = S2 - Y1
;   If H==0: if R==0 -> double, else -> infinity
;   X3 = R^2 - H^3 - 2*X1*H^2
;   Y3 = R*(X1*H^2 - X3) - Y1*H^3
;   Z3 = H*Z1
; =============================================================================
ec_point_add_384:
        ; If P1 is infinity (Z1==0): result = P2 with Z=1
        lda #<(ec384_p1+96)
        sta fp_src1
        lda #>(ec384_p1+96)
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @add384_p1ok

        ; Copy P2 X to P3 X
        ldy #47
@add384_cpx:
        lda ec384_p2,y
        sta ec384_p3,y
        dey
        bpl @add384_cpx
        ; Copy P2 Y to P3 Y
        ldy #47
@add384_cpy:
        lda ec384_p2+48,y
        sta ec384_p3+48,y
        dey
        bpl @add384_cpy
        ; Set Z = 1 (little-endian: byte 0 = 1, rest = 0)
        ldy #47
        lda #0
@add384_clz:
        sta ec384_p3+96,y
        dey
        bpl @add384_clz
        lda #1
        sta ec384_p3+96         ; Z byte 0 = 1 (LSB in little-endian)
        rts

@add384_p1ok:
        jsr ec_set_modp_384

        ; t1 = Z1^2
        lda #<(ec384_p1+96)
        sta fp_src1
        lda #>(ec384_p1+96)
        sta fp_src1+1
        lda #<(ec384_p1+96)
        sta fp_src2
        lda #>(ec384_p1+96)
        sta fp_src2+1
        lda #<ec384_t1
        sta fp_dst
        lda #>ec384_t1
        sta fp_dst+1
        jsr ec_sqrp_384         ; t1 = Z1^2

        ; t2 = X2*Z1^2 = U2
        lda #<ec384_p2
        sta fp_src1
        lda #>ec384_p2
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t2
        sta fp_dst
        lda #>ec384_t2
        sta fp_dst+1
        jsr ec_mulp_384         ; t2 = U2

        ; t3 = Z1^3 = Z1*t1
        lda #<(ec384_p1+96)
        sta fp_src1
        lda #>(ec384_p1+96)
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr ec_mulp_384         ; t3 = Z1^3

        ; t4 = Y2*Z1^3 = S2
        lda #<(ec384_p2+48)
        sta fp_src1
        lda #>(ec384_p2+48)
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr ec_mulp_384         ; t4 = S2

        ; H = U2 - X1 = t2 - X1 -> t1
        lda #<ec384_t2
        sta fp_src1
        lda #>ec384_t2
        sta fp_src1+1
        lda #<ec384_p1
        sta fp_src2
        lda #>ec384_p1
        sta fp_src2+1
        lda #<ec384_t1
        sta fp_dst
        lda #>ec384_t1
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t1 = H = U2 - X1

        ; R = S2 - Y1 = t4 - Y1 -> t2
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        lda #<(ec384_p1+48)
        sta fp_src2
        lda #>(ec384_p1+48)
        sta fp_src2+1
        lda #<ec384_t2
        sta fp_dst
        lda #>ec384_t2
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t2 = R = S2 - Y1

        ; Check H == 0
        lda #<ec384_t1
        sta fp_src1
        lda #>ec384_t1
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @add384_h_nonzero

        ; H == 0: check R
        lda #<ec384_t2
        sta fp_src1
        lda #>ec384_t2
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @add384_set_inf
        ; H==0, R==0: points are equal, double P1
        jmp ec_point_double_384

@add384_set_inf:
        ; H==0, R!=0: inverse points, result = infinity
        ; Count down through $00 via BNE (BPL would fail on $8F bit 7).
        ldy #144
        lda #0
@add384_sinf:
        dey
        sta ec384_p3,y
        bne @add384_sinf
        rts

@add384_h_nonzero:
        ; t3 = H^2
        lda #<ec384_t1
        sta fp_src1
        lda #>ec384_t1
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr ec_sqrp_384         ; t3 = H^2

        ; t4 = H^3 = H*H^2
        lda #<ec384_t1
        sta fp_src1
        lda #>ec384_t1
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr ec_mulp_384         ; t4 = H^3

        ; t5 = X1*H^2
        lda #<ec384_p1
        sta fp_src1
        lda #>ec384_p1
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_t5
        sta fp_dst
        lda #>ec384_t5
        sta fp_dst+1
        jsr ec_mulp_384         ; t5 = X1*H^2

        ; X3 = R^2 - H^3 - 2*X1*H^2
        ; t3 = R^2
        lda #<ec384_t2
        sta fp_src1
        lda #>ec384_t2
        sta fp_src1+1
        lda #<ec384_t2
        sta fp_src2
        lda #>ec384_t2
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr ec_sqrp_384         ; t3 = R^2

        ; t3 = R^2 - H^3
        lda #<ec384_t3
        sta fp_src1
        lda #>ec384_t3
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t3 = R^2 - H^3

        ; t6 = 2*X1*H^2
        lda #<ec384_t5
        sta fp_src1
        lda #>ec384_t5
        sta fp_src1+1
        lda #<ec384_t5
        sta fp_src2
        lda #>ec384_t5
        sta fp_src2+1
        lda #<ec384_t6
        sta fp_dst
        lda #>ec384_t6
        sta fp_dst+1
        jsr fp_mod_add_384      ; t6 = 2*X1*H^2

        ; X3 = t3 - t6
        lda #<ec384_t3
        sta fp_src1
        lda #>ec384_t3
        sta fp_src1+1
        lda #<ec384_t6
        sta fp_src2
        lda #>ec384_t6
        sta fp_src2+1
        lda #<ec384_p3
        sta fp_dst
        lda #>ec384_p3
        sta fp_dst+1
        jsr fp_mod_sub_384      ; X3

        ; Y3 = R*(X1*H^2 - X3) - Y1*H^3
        ; t3 = X1*H^2 - X3 = t5 - X3
        lda #<ec384_t5
        sta fp_src1
        lda #>ec384_t5
        sta fp_src1+1
        lda #<ec384_p3
        sta fp_src2
        lda #>ec384_p3
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t3 = X1*H^2 - X3

        ; t5 = R * t3
        lda #<ec384_t2
        sta fp_src1
        lda #>ec384_t2
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_t5
        sta fp_dst
        lda #>ec384_t5
        sta fp_dst+1
        jsr ec_mulp_384         ; t5 = R*(X1*H^2 - X3)

        ; t6 = Y1*H^3
        lda #<(ec384_p1+48)
        sta fp_src1
        lda #>(ec384_p1+48)
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<ec384_t6
        sta fp_dst
        lda #>ec384_t6
        sta fp_dst+1
        jsr ec_mulp_384         ; t6 = Y1*H^3

        ; Y3 = t5 - t6
        lda #<ec384_t5
        sta fp_src1
        lda #>ec384_t5
        sta fp_src1+1
        lda #<ec384_t6
        sta fp_src2
        lda #>ec384_t6
        sta fp_src2+1
        lda #<(ec384_p3+48)
        sta fp_dst
        lda #>(ec384_p3+48)
        sta fp_dst+1
        jsr fp_mod_sub_384      ; Y3

        ; Z3 = H*Z1 = t1*Z1
        lda #<ec384_t1
        sta fp_src1
        lda #>ec384_t1
        sta fp_src1+1
        lda #<(ec384_p1+96)
        sta fp_src2
        lda #>(ec384_p1+96)
        sta fp_src2+1
        lda #<(ec384_p3+96)
        sta fp_dst
        lda #>(ec384_p3+96)
        sta fp_dst+1
        jsr ec_mulp_384         ; Z3 = H*Z1

        rts

; =============================================================================
; ec_point_add_jj_384: ec384_p3 = ec384_p1 + ec384_p2 (full Jacobian + Jacobian)
;
; P-384 analogue of ec_point_add_jj. Both P1 and P2 are 144-byte Jacobian
; points (X@0..47, Y@48..95, Z@96..143). Formula: Bernstein-Lange add-2007-bl
; (11M + 5S + ~10 add/sub) -- see src/points256.s ec_point_add_jj for the
; full op-by-op derivation. Edge cases identical to the 32-byte variant.
;
; Scratch slot map (peak 7 simultaneously live):
;   t1 = Z1Z1                 t5 = S1
;   t2 = Z2Z2 / J             t6 = S2 / (S2 - S1) / r
;   t3 = U1                   jj_tmp = scratch (Y1*Z2, Y2*Z1, I, ...)
;   t4 = U2 / H / V
;
; Loop hazards (see CLAUDE.md "Known issues"):
;   * 144-byte copies use X-counter countdown (ldx #144 / dex / bne) because
;     LDA ...,y inside the loop clobbers Z; BNE must test the DEX-set N/Z,
;     not the loaded byte. Also bit 7 of 143 ($8F) is set so ldy #143 / bpl
;     never branches on iteration 0 (the original BPL infinity-fill bug).
;   * 144-byte infinity-zero uses count-down-through-0 / BNE.
; =============================================================================
ec_point_add_jj_384:
        ; If P1 is infinity (Z1 == 0) -> ec_p3 := P2 verbatim (144-byte copy).
        lda #<(ec384_p1+96)
        sta fp_src1
        lda #>(ec384_p1+96)
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @jj384_p1ok
        ldx #144
        ldy #0
@jj384_cp_p2:
        lda ec384_p2,y
        sta ec384_p3,y
        iny
        dex
        bne @jj384_cp_p2
        rts

@jj384_p1ok:
        ; If P2 is infinity (Z2 == 0) -> ec_p3 := P1 verbatim.
        lda #<(ec384_p2+96)
        sta fp_src1
        lda #>(ec384_p2+96)
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @jj384_p2ok
        ldx #144
        ldy #0
@jj384_cp_p1:
        lda ec384_p1,y
        sta ec384_p3,y
        iny
        dex
        bne @jj384_cp_p1
        rts

@jj384_p2ok:
        jsr ec_set_modp_384

        ; t1 = Z1^2
        lda #<(ec384_p1+96)
        sta fp_src1
        lda #>(ec384_p1+96)
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_dst
        lda #>ec384_t1
        sta fp_dst+1
        jsr ec_sqrp_384

        ; t2 = Z2^2
        lda #<(ec384_p2+96)
        sta fp_src1
        lda #>(ec384_p2+96)
        sta fp_src1+1
        lda #<ec384_t2
        sta fp_dst
        lda #>ec384_t2
        sta fp_dst+1
        jsr ec_sqrp_384

        ; t3 = U1 = X1 * Z2Z2
        lda #<ec384_p1
        sta fp_src1
        lda #>ec384_p1
        sta fp_src1+1
        lda #<ec384_t2
        sta fp_src2
        lda #>ec384_t2
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr ec_mulp_384

        ; t4 = U2 = X2 * Z1Z1
        lda #<ec384_p2
        sta fp_src1
        lda #>ec384_p2
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr ec_mulp_384

        ; jj_tmp = Y1 * Z2
        lda #<(ec384_p1+48)
        sta fp_src1
        lda #>(ec384_p1+48)
        sta fp_src1+1
        lda #<(ec384_p2+96)
        sta fp_src2
        lda #>(ec384_p2+96)
        sta fp_src2+1
        lda #<ec384_jj_tmp
        sta fp_dst
        lda #>ec384_jj_tmp
        sta fp_dst+1
        jsr ec_mulp_384

        ; t5 = S1 = (Y1*Z2) * Z2Z2 = jj_tmp * t2
        lda #<ec384_jj_tmp
        sta fp_src1
        lda #>ec384_jj_tmp
        sta fp_src1+1
        lda #<ec384_t2
        sta fp_src2
        lda #>ec384_t2
        sta fp_src2+1
        lda #<ec384_t5
        sta fp_dst
        lda #>ec384_t5
        sta fp_dst+1
        jsr ec_mulp_384

        ; jj_tmp = Y2 * Z1
        lda #<(ec384_p2+48)
        sta fp_src1
        lda #>(ec384_p2+48)
        sta fp_src1+1
        lda #<(ec384_p1+96)
        sta fp_src2
        lda #>(ec384_p1+96)
        sta fp_src2+1
        lda #<ec384_jj_tmp
        sta fp_dst
        lda #>ec384_jj_tmp
        sta fp_dst+1
        jsr ec_mulp_384

        ; t6 = S2 = (Y2*Z1) * Z1Z1 = jj_tmp * t1
        lda #<ec384_jj_tmp
        sta fp_src1
        lda #>ec384_jj_tmp
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t6
        sta fp_dst
        lda #>ec384_t6
        sta fp_dst+1
        jsr ec_mulp_384

        ; t4 = H = U2 - U1
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr fp_mod_sub_384

        ; t6 = S2 - S1
        lda #<ec384_t6
        sta fp_src1
        lda #>ec384_t6
        sta fp_src1+1
        lda #<ec384_t5
        sta fp_src2
        lda #>ec384_t5
        sta fp_src2+1
        lda #<ec384_t6
        sta fp_dst
        lda #>ec384_t6
        sta fp_dst+1
        jsr fp_mod_sub_384

        ; Check H == 0
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @jj384_h_nonzero

        ; H == 0. Check (S2 - S1).
        lda #<ec384_t6
        sta fp_src1
        lda #>ec384_t6
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @jj384_set_inf
        jmp ec_point_double_384

@jj384_set_inf:
        ; H==0, S2!=S1: result = infinity (zero 144 B of ec384_p3).
        ; Count-down-through-0 / BNE: ldy #143 / bpl would never branch on
        ; iteration 0 (bit 7 of $8F set). Original BPL infinity-fill bug.
        ldy #144
        lda #0
@jj384_sinf:
        dey
        sta ec384_p3,y
        bne @jj384_sinf
        rts

@jj384_h_nonzero:
        ; t6 = r = 2*(S2 - S1)
        lda #<ec384_t6
        sta fp_src1
        lda #>ec384_t6
        sta fp_src1+1
        lda #<ec384_t6
        sta fp_src2
        lda #>ec384_t6
        sta fp_src2+1
        lda #<ec384_t6
        sta fp_dst
        lda #>ec384_t6
        sta fp_dst+1
        jsr fp_mod_add_384

        ; --- Z3 first (uses Z1Z1=t1, Z2Z2=t2, H=t4, then frees them).
        ; jj_tmp = Z1 + Z2
        lda #<(ec384_p1+96)
        sta fp_src1
        lda #>(ec384_p1+96)
        sta fp_src1+1
        lda #<(ec384_p2+96)
        sta fp_src2
        lda #>(ec384_p2+96)
        sta fp_src2+1
        lda #<ec384_jj_tmp
        sta fp_dst
        lda #>ec384_jj_tmp
        sta fp_dst+1
        jsr fp_mod_add_384

        ; jj_tmp = (Z1+Z2)^2
        lda #<ec384_jj_tmp
        sta fp_src1
        lda #>ec384_jj_tmp
        sta fp_src1+1
        lda #<ec384_jj_tmp
        sta fp_dst
        lda #>ec384_jj_tmp
        sta fp_dst+1
        jsr ec_sqrp_384

        ; jj_tmp = (Z1+Z2)^2 - Z1Z1
        lda #<ec384_jj_tmp
        sta fp_src1
        lda #>ec384_jj_tmp
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_jj_tmp
        sta fp_dst
        lda #>ec384_jj_tmp
        sta fp_dst+1
        jsr fp_mod_sub_384

        ; jj_tmp = jj_tmp - Z2Z2  (== 2 Z1 Z2)
        lda #<ec384_jj_tmp
        sta fp_src1
        lda #>ec384_jj_tmp
        sta fp_src1+1
        lda #<ec384_t2
        sta fp_src2
        lda #>ec384_t2
        sta fp_src2+1
        lda #<ec384_jj_tmp
        sta fp_dst
        lda #>ec384_jj_tmp
        sta fp_dst+1
        jsr fp_mod_sub_384

        ; ec_p3+96 = Z3 = jj_tmp * H
        lda #<ec384_jj_tmp
        sta fp_src1
        lda #>ec384_jj_tmp
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<(ec384_p3+96)
        sta fp_dst
        lda #>(ec384_p3+96)
        sta fp_dst+1
        jsr ec_mulp_384

        ; --- I = (2H)^2 (t1 free, use it)
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<ec384_t1
        sta fp_dst
        lda #>ec384_t1
        sta fp_dst+1
        jsr fp_mod_add_384

        ; t1 = I = (2H)^2
        lda #<ec384_t1
        sta fp_src1
        lda #>ec384_t1
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_dst
        lda #>ec384_t1
        sta fp_dst+1
        jsr ec_sqrp_384

        ; t2 = J = H * I (t2 free; was Z2Z2)
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
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

        ; t4 = V = U1 * I (reuses H slot)
        lda #<ec384_t3
        sta fp_src1
        lda #>ec384_t3
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t4
        sta fp_dst
        lda #>ec384_t4
        sta fp_dst+1
        jsr ec_mulp_384

        ; jj_tmp = r^2
        lda #<ec384_t6
        sta fp_src1
        lda #>ec384_t6
        sta fp_src1+1
        lda #<ec384_jj_tmp
        sta fp_dst
        lda #>ec384_jj_tmp
        sta fp_dst+1
        jsr ec_sqrp_384

        ; jj_tmp = r^2 - J
        lda #<ec384_jj_tmp
        sta fp_src1
        lda #>ec384_jj_tmp
        sta fp_src1+1
        lda #<ec384_t2
        sta fp_src2
        lda #>ec384_t2
        sta fp_src2+1
        lda #<ec384_jj_tmp
        sta fp_dst
        lda #>ec384_jj_tmp
        sta fp_dst+1
        jsr fp_mod_sub_384

        ; t3 = 2V (reuses U1 slot, now free)
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        lda #<ec384_t4
        sta fp_src2
        lda #>ec384_t4
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr fp_mod_add_384

        ; ec384_p3 = X3 = jj_tmp - 2V
        lda #<ec384_jj_tmp
        sta fp_src1
        lda #>ec384_jj_tmp
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_p3
        sta fp_dst
        lda #>ec384_p3
        sta fp_dst+1
        jsr fp_mod_sub_384

        ; jj_tmp = V - X3
        lda #<ec384_t4
        sta fp_src1
        lda #>ec384_t4
        sta fp_src1+1
        lda #<ec384_p3
        sta fp_src2
        lda #>ec384_p3
        sta fp_src2+1
        lda #<ec384_jj_tmp
        sta fp_dst
        lda #>ec384_jj_tmp
        sta fp_dst+1
        jsr fp_mod_sub_384

        ; jj_tmp = r * (V - X3)
        lda #<ec384_t6
        sta fp_src1
        lda #>ec384_t6
        sta fp_src1+1
        lda #<ec384_jj_tmp
        sta fp_src2
        lda #>ec384_jj_tmp
        sta fp_src2+1
        lda #<ec384_jj_tmp
        sta fp_dst
        lda #>ec384_jj_tmp
        sta fp_dst+1
        jsr ec_mulp_384

        ; t3 = S1 * J
        lda #<ec384_t5
        sta fp_src1
        lda #>ec384_t5
        sta fp_src1+1
        lda #<ec384_t2
        sta fp_src2
        lda #>ec384_t2
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr ec_mulp_384

        ; t3 = 2*S1*J
        lda #<ec384_t3
        sta fp_src1
        lda #>ec384_t3
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr fp_mod_add_384

        ; ec384_p3+48 = Y3 = jj_tmp - 2*S1*J
        lda #<ec384_jj_tmp
        sta fp_src1
        lda #>ec384_jj_tmp
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<(ec384_p3+48)
        sta fp_dst
        lda #>(ec384_p3+48)
        sta fp_dst+1
        jsr fp_mod_sub_384

        rts

; =============================================================================
; Wave 7a: Lim-Lee 8-way fixed-base comb for P-384 (h=8, a=48).
;
; Precompute: ec_precompute_384 builds anchors A_p = 2^(48*(p-1))*G for
; p = 1..8 and then T[j] (j=1..255) = sum over set bits of j of the
; corresponding anchors, stored as affine (X||Y, 96 bytes) in REU bank 2
; offset $4000, 256 * 96 = 24576 bytes.
;
; Index convention (IMPORTANT -- must match ec_scalar_mul_384):
;   bit p (value 1<<p) of j corresponds to anchor A_{p+1}, which is the
;   contribution of sub-scalar K_p. K_0 is the least significant 48-bit
;   chunk; K_7 is the most significant.
;
; Scalar mul: splits the 384-bit scalar into K7||...||K0 (6 bytes each),
; then runs 48 iterations. At iteration i (bit = 47..0) we form
;     idx = sum over p=0..7 of bit_i(K_p) << p
; double R and (if idx != 0) add T[idx]. The first non-zero idx seeds R.
; =============================================================================

; =============================================================================
; ec_precompute_384: Build the P-384 Lim-Lee comb table in REU bank 2
; at offset $4000. 256 * 96 = 24576 bytes. Slot 0 is never fetched.
; Uses 336 ec_point_double_384's (48*7 for seven anchor chains) plus
; 762 mixed adds (sum of (popcount(j)-1) for j=1..255) and 255 J->A
; conversions (table entries).
; =============================================================================
ec_precompute_384:
        jsr ec_set_modp_384

        ; ----- A1 = G affine: store directly into ec_anchor1_384_x/y. -----
        ldy #47
@cmp384_a1x:
        lda ec_gx384,y
        sta ec_anchor1_384_x,y
        dey
        bpl @cmp384_a1x
        ldy #47
@cmp384_a1y:
        lda ec_gy384,y
        sta ec_anchor1_384_y,y
        dey
        bpl @cmp384_a1y

        ; ----- Build A2..A8: each via 48 doublings from the previous. -----
        jsr @cmp384_load_p1_g           ; ec384_p1 = G (Jacobian, Z=1)

        ; A2 = 2^48 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa2x:
        lda ec384_affine_x,y
        sta ec_anchor2_384_x,y
        dey
        bpl @cmp384_sa2x
        ldy #47
@cmp384_sa2y:
        lda ec384_affine_y,y
        sta ec_anchor2_384_y,y
        dey
        bpl @cmp384_sa2y

        ; A3 = 2^96 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa3x:
        lda ec384_affine_x,y
        sta ec_anchor3_384_x,y
        dey
        bpl @cmp384_sa3x
        ldy #47
@cmp384_sa3y:
        lda ec384_affine_y,y
        sta ec_anchor3_384_y,y
        dey
        bpl @cmp384_sa3y

        ; A4 = 2^144 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa4x:
        lda ec384_affine_x,y
        sta ec_anchor4_384_x,y
        dey
        bpl @cmp384_sa4x
        ldy #47
@cmp384_sa4y:
        lda ec384_affine_y,y
        sta ec_anchor4_384_y,y
        dey
        bpl @cmp384_sa4y

        ; A5 = 2^192 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa5x:
        lda ec384_affine_x,y
        sta ec_anchor5_384_x,y
        dey
        bpl @cmp384_sa5x
        ldy #47
@cmp384_sa5y:
        lda ec384_affine_y,y
        sta ec_anchor5_384_y,y
        dey
        bpl @cmp384_sa5y

        ; A6 = 2^240 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa6x:
        lda ec384_affine_x,y
        sta ec_anchor6_384_x,y
        dey
        bpl @cmp384_sa6x
        ldy #47
@cmp384_sa6y:
        lda ec384_affine_y,y
        sta ec_anchor6_384_y,y
        dey
        bpl @cmp384_sa6y

        ; A7 = 2^288 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa7x:
        lda ec384_affine_x,y
        sta ec_anchor7_384_x,y
        dey
        bpl @cmp384_sa7x
        ldy #47
@cmp384_sa7y:
        lda ec384_affine_y,y
        sta ec_anchor7_384_y,y
        dey
        bpl @cmp384_sa7y

        ; A8 = 2^336 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa8x:
        lda ec384_affine_x,y
        sta ec_anchor8_384_x,y
        dey
        bpl @cmp384_sa8x
        ldy #47
@cmp384_sa8y:
        lda ec384_affine_y,y
        sta ec_anchor8_384_y,y
        dey
        bpl @cmp384_sa8y

        ; ----- Build T[j] for j = 1..255 by subset-sum over 8 anchors. -----
        lda #1
        sta ec384_precomp_i
@cmp384_tloop:
        lda #0
        sta cm384_seeded
        lda ec384_precomp_i
        and #$01
        beq @cmp384_tj_b1
        lda #0
        jsr @cmp384_accum_anchor
@cmp384_tj_b1:
        lda ec384_precomp_i
        and #$02
        beq @cmp384_tj_b2
        lda #1
        jsr @cmp384_accum_anchor
@cmp384_tj_b2:
        lda ec384_precomp_i
        and #$04
        beq @cmp384_tj_b3
        lda #2
        jsr @cmp384_accum_anchor
@cmp384_tj_b3:
        lda ec384_precomp_i
        and #$08
        beq @cmp384_tj_b4
        lda #3
        jsr @cmp384_accum_anchor
@cmp384_tj_b4:
        lda ec384_precomp_i
        and #$10
        beq @cmp384_tj_b5
        lda #4
        jsr @cmp384_accum_anchor
@cmp384_tj_b5:
        lda ec384_precomp_i
        and #$20
        beq @cmp384_tj_b6
        lda #5
        jsr @cmp384_accum_anchor
@cmp384_tj_b6:
        lda ec384_precomp_i
        and #$40
        beq @cmp384_tj_b7
        lda #6
        jsr @cmp384_accum_anchor
@cmp384_tj_b7:
        lda ec384_precomp_i
        and #$80
        beq @cmp384_tj_done
        lda #7
        jsr @cmp384_accum_anchor
@cmp384_tj_done:
        ; ec384_p1 holds T[j] in Jacobian. Convert and stash.
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ; Copy affine to ec384_p2 (stash helper reads ec384_p2).
        ldy #47
@cmp384_tj_cpx:
        lda ec384_affine_x,y
        sta ec384_p2,y
        dey
        bpl @cmp384_tj_cpx
        ldy #47
@cmp384_tj_cpy:
        lda ec384_affine_y,y
        sta ec384_p2+48,y
        dey
        bpl @cmp384_tj_cpy
        jsr sm384w_stash_p2
        inc ec384_precomp_i
        beq @cmp384_tdone               ; wraps 255->0 -> done
        jmp @cmp384_tloop
@cmp384_tdone:
        rts

; --- Internal helper: load ec384_p1 = G as Jacobian (Z=1). ---
@cmp384_load_p1_g:
        ldy #47
@cmp384_lpg_x:
        lda ec_gx384,y
        sta ec384_p1,y
        dey
        bpl @cmp384_lpg_x
        ldy #47
@cmp384_lpg_y:
        lda ec_gy384,y
        sta ec384_p1+48,y
        dey
        bpl @cmp384_lpg_y
        ldy #47
        lda #0
@cmp384_lpg_z:
        sta ec384_p1+96,y
        dey
        bpl @cmp384_lpg_z
        lda #1
        sta ec384_p1+96
        rts

; --- ec384_p1 = 2^A * ec384_p1 (A successive doublings). A in 1..255. ---
@cmp384_double_p1_n:
        sta ec384_sc_mask
@cmp384_dpn_loop:
        jsr ec_point_double_384
        ldy #0
@cmp384_dpn_cp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne @cmp384_dpn_cp
        dec ec384_sc_mask
        bne @cmp384_dpn_loop
        rts

; --- Copy ec384_p1 -> ec384_p3 (144 bytes). ---
@cmp384_p1_to_p3:
        ldy #0
@cmp384_pp3_cp:
        lda ec384_p1,y
        sta ec384_p3,y
        iny
        cpy #144
        bne @cmp384_pp3_cp
        rts

; --- Accumulate anchor[A] into ec384_p1 (Jacobian).
; If cm_seeded == 0 : copy anchor as ec384_p1 with Z=1, cm_seeded = 1.
; Else               : copy anchor into ec384_p2, call ec_point_add_384,
;                      copy ec384_p3 -> ec384_p1. A in 0..7.
@cmp384_accum_anchor:
        sta cm384_anch_idx
        lda cm384_seeded
        bne @cmp384_acc_add
        lda cm384_anch_idx
        jsr @cmp384_load_anchor_p1
        lda #1
        sta cm384_seeded
        rts
@cmp384_acc_add:
        lda cm384_anch_idx
        jsr @cmp384_load_anchor_p2
        jsr ec_point_add_384
        ldy #0
@cmp384_acc_cp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne @cmp384_acc_cp
        rts

; --- Load anchor[A] into ec384_p1 (Jacobian, Z=1). A in 0..7. ---
@cmp384_load_anchor_p1:
        asl
        tax
        lda @cmp384_anchor_tbl,x
        sta zp_ptr1
        lda @cmp384_anchor_tbl+1,x
        sta zp_ptr1+1
        ; Copy 48 X bytes from (zp_ptr1) to ec384_p1.
        ldy #47
@cmp384_lap1_x:
        lda (zp_ptr1),y
        sta ec384_p1,y
        dey
        bpl @cmp384_lap1_x
        ; Advance pointer by 48 to Y coordinate.
        lda zp_ptr1
        clc
        adc #48
        sta zp_ptr1
        bcc :+
        inc zp_ptr1+1
:
        ldy #47
@cmp384_lap1_y:
        lda (zp_ptr1),y
        sta ec384_p1+48,y
        dey
        bpl @cmp384_lap1_y
        ldy #47
        lda #0
@cmp384_lap1_z:
        sta ec384_p1+96,y
        dey
        bpl @cmp384_lap1_z
        lda #1
        sta ec384_p1+96
        rts

; --- Load anchor[A] into ec384_p2 (affine X,Y). A in 0..7. ---
@cmp384_load_anchor_p2:
        asl
        tax
        lda @cmp384_anchor_tbl,x
        sta zp_ptr1
        lda @cmp384_anchor_tbl+1,x
        sta zp_ptr1+1
        ldy #47
@cmp384_lap2_x:
        lda (zp_ptr1),y
        sta ec384_p2,y
        dey
        bpl @cmp384_lap2_x
        lda zp_ptr1
        clc
        adc #48
        sta zp_ptr1
        bcc :+
        inc zp_ptr1+1
:
        ldy #47
@cmp384_lap2_y:
        lda (zp_ptr1),y
        sta ec384_p2+48,y
        dey
        bpl @cmp384_lap2_y
        rts

@cmp384_anchor_tbl:
        .word ec_anchor1_384_x
        .word ec_anchor2_384_x
        .word ec_anchor3_384_x
        .word ec_anchor4_384_x
        .word ec_anchor5_384_x
        .word ec_anchor6_384_x
        .word ec_anchor7_384_x
        .word ec_anchor8_384_x

; =============================================================================
; ec_scalar_mul_384: ec384_p3 = k * G using an 8-way Lim-Lee fixed-base comb.
;
; k is a 48-byte scalar pointed to by (ec_scalar_ptr), BIG-ENDIAN. Split into
; K7||...||K0, each 48 bits (6 bytes). Uses the precompute table built by
; ec_precompute_384 in REU bank 2 offset $4000 (256 entries * 96 bytes).
;
; Index convention (matches ec_precompute_384):
;   idx bit p corresponds to sub-scalar K_p (bit p in j toggles anchor A_{p+1}).
; For iter bit b = 47..0:
;     idx = sum over p=0..7 of bit_b(K_p) << p
;     R = 2*R; if idx != 0: R += T[idx]   (first idx!=0 seeds R).
;
; Cost: 48 doublings + ~48 mixed adds (vs 96 doublings + ~90 adds for h=4).
; REQUIRES: ec_precompute_384 must have been called first.
; =============================================================================
ec_scalar_mul_384:
        ; --- Defensive REU register init (issue #33-class defence;
        ; see c64-x25519 commit 817f525). The per-row DMA in fp_mul_384/
        ; fp_sqr_384 trusts reu_reu_lo / reu_addr_ctrl remain 0 from
        ; reu_mul_init. Defence-in-depth at the public surface.
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        ; --- Transpose 48-byte BE scalar -> cm_k_384 little-endian ---
        ; cm_k_384[0..5] = K0 (LSBs), cm_k_384[6..11] = K1, ..., cm_k_384[42..47] = K7.
        ldy #47                 ; BE source index
        ldx #0                  ; LE destination index
@cm384_xpose:
        lda (ec_scalar_ptr),y
        sta cm_k_384,x
        inx
        dey
        bpl @cm384_xpose

        ; --- Init state ---
        lda #5
        sta cm384_byte_off      ; bit 47 of each K_p lives in cm_k_384[5 + 6*p]
        lda #$80
        sta cm384_bit_mask
        lda #48
        sta cm384_loop_ctr
        lda #1
        sta cm384_r_inf

        jsr ec_set_modp_384

@cm384_loop:
        ; --- Double R (skip if still infinity) ---
        lda cm384_r_inf
        bne @cm384_skip_double
        jsr ec_point_double_384
        ldy #0
@cm384_dcp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne @cm384_dcp
@cm384_skip_double:

        ; --- Extract idx (8 bits) from current bit position, K7..K0 ---
        lda #0
        sta cm384_idx
        ldx cm384_byte_off

        lda cm_k_384+42,x       ; K7
        and cm384_bit_mask
        beq @cm384_b7z
        lda #$80
        ora cm384_idx
        sta cm384_idx
@cm384_b7z:
        lda cm_k_384+36,x       ; K6
        and cm384_bit_mask
        beq @cm384_b6z
        lda #$40
        ora cm384_idx
        sta cm384_idx
@cm384_b6z:
        lda cm_k_384+30,x       ; K5
        and cm384_bit_mask
        beq @cm384_b5z
        lda #$20
        ora cm384_idx
        sta cm384_idx
@cm384_b5z:
        lda cm_k_384+24,x       ; K4
        and cm384_bit_mask
        beq @cm384_b4z
        lda #$10
        ora cm384_idx
        sta cm384_idx
@cm384_b4z:
        lda cm_k_384+18,x       ; K3
        and cm384_bit_mask
        beq @cm384_b3z
        lda #$08
        ora cm384_idx
        sta cm384_idx
@cm384_b3z:
        lda cm_k_384+12,x       ; K2
        and cm384_bit_mask
        beq @cm384_b2z
        lda #$04
        ora cm384_idx
        sta cm384_idx
@cm384_b2z:
        lda cm_k_384+6,x        ; K1
        and cm384_bit_mask
        beq @cm384_b1z
        lda #$02
        ora cm384_idx
        sta cm384_idx
@cm384_b1z:
        lda cm_k_384+0,x        ; K0
        and cm384_bit_mask
        beq @cm384_b0z
        lda #$01
        ora cm384_idx
        sta cm384_idx
@cm384_b0z:

        ; --- Advance bit position ---
        lsr cm384_bit_mask
        bne @cm384_after_advance
        lda #$80
        sta cm384_bit_mask
        dec cm384_byte_off
@cm384_after_advance:

        ; --- If idx == 0, no addition this iter ---
        lda cm384_idx
        beq @cm384_after_add

        ; --- Fetch T[idx] affine into ec384_p2 ---
        lda cm384_idx
        jsr sm384w_fetch_to_p2

        ; --- If R was infinity, seed R = T[idx] and clear flag ---
        lda cm384_r_inf
        beq @cm384_real_add
        ldy #47
@cm384_seed_x:
        lda ec384_p2,y
        sta ec384_p1,y
        dey
        bpl @cm384_seed_x
        ldy #47
@cm384_seed_y:
        lda ec384_p2+48,y
        sta ec384_p1+48,y
        dey
        bpl @cm384_seed_y
        ldy #47
        lda #0
@cm384_seed_z:
        sta ec384_p1+96,y
        dey
        bpl @cm384_seed_z
        lda #1
        sta ec384_p1+96
        lda #0
        sta cm384_r_inf
        jmp @cm384_after_add

@cm384_real_add:
        jsr ec_point_add_384
        ldy #0
@cm384_acp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne @cm384_acp

@cm384_after_add:
        dec cm384_loop_ctr
        beq @cm384_done
        jmp @cm384_loop

@cm384_done:
        ; --- If R is still infinity, return all-zero point. ---
        lda cm384_r_inf
        beq @cm384_copy_out
        ldy #0
        lda #0
@cm384_zinf:
        sta ec384_p3,y
        iny
        cpy #144
        bne @cm384_zinf
        rts

@cm384_copy_out:
        ldy #0
@cm384_finc:
        lda ec384_p1,y
        sta ec384_p3,y
        iny
        cpy #144
        bne @cm384_finc
        rts

; --- Comb scalar-mul state vars (384-specific to avoid linker clash with points256) ---
cm384_byte_off:  .byte 0
cm384_bit_mask:  .byte 0
cm384_loop_ctr:  .byte 0
cm384_idx:       .byte 0
cm384_r_inf:     .byte 0
cm384_seeded:    .byte 0         ; precompute helper
cm384_anch_idx:  .byte 0         ; precompute helper

; -----------------------------------------------------------------------------
; sm384w_stash_p2: Stash ec384_p2 (96 bytes affine) to REU bank 2
; Input: ec384_precomp_i = table index (0..15)
; REU offset = $0400 + index * 96
; -----------------------------------------------------------------------------
sm384w_stash_p2:
        jsr sm384w_calc_reu_offset

        lda #<ec384_p2
        sta reu_c64_lo
        lda #>ec384_p2
        sta reu_c64_hi
        lda #96
        sta reu_len_lo
        lda #0
        sta reu_len_hi
        sta reu_addr_ctrl
        lda #%10110000           ; execute + autoload + STASH
        sta reu_command

        jsr sm384w_restore_reu
        rts

; -----------------------------------------------------------------------------
; sm384w_fetch_to_p2: Fetch T[A] affine (96 bytes) from REU into ec384_p2
; Input: A = table index (0..15)
; -----------------------------------------------------------------------------
sm384w_fetch_to_p2:
        sta ec384_precomp_i
        jsr sm384w_calc_reu_offset

        lda #<ec384_p2
        sta reu_c64_lo
        lda #>ec384_p2
        sta reu_c64_hi
        lda #96
        sta reu_len_lo
        lda #0
        sta reu_len_hi
        sta reu_addr_ctrl
        lda #%10110001           ; execute + autoload + FETCH
        sta reu_command

        jsr sm384w_restore_reu
        rts

; -----------------------------------------------------------------------------
; sm384w_calc_reu_offset: Set REU address registers for table index
; Input: ec384_precomp_i = index (0..255)
; Offset = $4000 + index * 96 = $4000 + index*64 + index*32  (16-bit result)
; Wave 7a: h=8 requires 16-bit table index * 96; max offset 255*96 = 24480,
; plus $4000 base = $9FA0, fits in 16 bits.
; -----------------------------------------------------------------------------
sm384w_calc_reu_offset:
        lda ec384_precomp_i
        asl
        asl
        asl
        asl
        asl
        sta zp_tmp1              ; low byte of i*32 (top 3 bits of i lost here)
        lda ec384_precomp_i
        lsr
        lsr
        lsr                      ; high byte of i*32
        sta zp_tmp2

        ; i*64 = (i*32)*2
        lda zp_tmp1
        asl
        sta reu_reu_lo
        lda zp_tmp2
        rol
        sta reu_reu_hi

        ; + i*32 -> i*96
        lda reu_reu_lo
        clc
        adc zp_tmp1
        sta reu_reu_lo
        lda reu_reu_hi
        adc zp_tmp2
        ; + $4000 base
        clc
        adc #$40
        sta reu_reu_hi

        lda #PRECOMP_REU_BANK
        sta reu_reu_bank
        rts

; -----------------------------------------------------------------------------
; sm384w_restore_reu: Restore REU registers for multiply table access
; -----------------------------------------------------------------------------
sm384w_restore_reu:
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


; =============================================================================
; ec_scalar_mul_var_384: variable-base scalar multiplication (left-to-right
;   double-and-add over 384 bits; non-constant-time, for ECDSA verify).
; Input:  ec_scalar_ptr -> 48-byte BE scalar
;         ec_base384_x, ec_base384_y -> 48-byte LE affine base point
; Output: ec384_p3 (Jacobian, 144 B)
; NOT re-entrant. Serialize with all other field/point ops.
; 144-byte Jacobian copies use the countdown-from-144/BNE pattern because
; LDY #143 / BPL never branches on the first iteration (bit 7 of $8F set).
; =============================================================================
ec_scalar_mul_var_384:
        ; --- Defensive REU register init (issue #33-class defence;
        ; see ec_scalar_mul_384 above and c64-x25519 commit 817f525).
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        jsr ec_set_modp_384

        ; Transpose BE scalar into LE internal buffer var384_k.
        ;   var384_k[0]  = scalar[47]  (LSB)
        ;   var384_k[47] = scalar[0]   (MSB)
        ldy #47
        ldx #0
@v384_xpose:
        lda (ec_scalar_ptr),y
        sta var384_k,x
        inx
        dey
        bpl @v384_xpose

        ; Init walking state. Bit 383 is var384_k[47] bit 7.
        lda #47
        sta var384_byte_off
        lda #$80
        sta var384_bit_mask
        ; 384 iterations encoded as hi=2/lo=$80.
        ; Trace: iter 128 decrements hi 2→1 (not done); iters 129..384 count
        ; lo $FF..$01; iter 384 decrements hi 1→0 and exits. 128+256 = 384.
        lda #$80
        sta var384_loop_ctr_lo
        lda #2
        sta var384_loop_ctr_hi
        lda #1
        sta var384_r_inf        ; R = infinity

@v384_loop:
        ; --- Double R unless infinity ---
        lda var384_r_inf
        bne @v384_skip_double
        jsr ec_point_double_384
        ; 144-byte copy ec384_p3 -> ec384_p1. Can't use the countdown+BNE
        ; idiom from @v384_zinf because LDA here clobbers the Z flag the
        ; BNE would test. Use a separate byte counter (X) so termination
        ; is independent of the data.
        ldx #144
        ldy #0
@v384_dcp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        dex
        bne @v384_dcp
@v384_skip_double:

        ; --- Test current bit of scalar ---
        ldx var384_byte_off
        lda var384_k,x
        and var384_bit_mask
        beq @v384_bit_is_zero

        ; Bit set: stage P2 = (base_x, base_y) for the (possibly) coming add.
        ldy #47
@v384_cpbx:
        lda ec_base384_x,y
        sta ec384_p2,y
        dey
        bpl @v384_cpbx
        ldy #47
@v384_cpby:
        lda ec_base384_y,y
        sta ec384_p2+48,y
        dey
        bpl @v384_cpby

        lda var384_r_inf
        beq @v384_real_add

        ; First set bit: seed R = (base_x, base_y, 1).
        ldy #47
@v384_seedx:
        lda ec_base384_x,y
        sta ec384_p1,y
        dey
        bpl @v384_seedx
        ldy #47
@v384_seedy:
        lda ec_base384_y,y
        sta ec384_p1+48,y
        dey
        bpl @v384_seedy
        ; Z = 1 (LE: byte 0 = 1, rest = 0)
        ldy #47
        lda #0
@v384_seedz:
        sta ec384_p1+96,y
        dey
        bpl @v384_seedz
        lda #1
        sta ec384_p1+96
        lda #0
        sta var384_r_inf
        jmp @v384_bit_done

@v384_real_add:
        jsr ec_point_add_384
        ; 144-byte copy ec384_p3 -> ec384_p1 (see @v384_dcp note).
        ldx #144
        ldy #0
@v384_acp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        dex
        bne @v384_acp

@v384_bit_is_zero:
@v384_bit_done:
        ; --- Advance to next-lower bit ---
        lsr var384_bit_mask
        bne @v384_after_advance
        lda #$80
        sta var384_bit_mask
        dec var384_byte_off
@v384_after_advance:

        ; --- 384-iteration counter (hi=1/lo=$80 decrementing to 0) ---
        dec var384_loop_ctr_lo
        bne @v384_loop_trampoline
        dec var384_loop_ctr_hi
        bne @v384_loop_trampoline
        jmp @v384_loop_done
@v384_loop_trampoline:
        jmp @v384_loop

@v384_loop_done:
        ; --- Done. If R still infinity, return zero; else copy ec384_p1 -> ec384_p3. ---
        lda var384_r_inf
        beq @v384_copy_out
        ldy #144
        lda #0
@v384_zinf:
        dey
        sta ec384_p3,y
        bne @v384_zinf          ; Y counts 143..1; final iter stores byte 0
        rts

@v384_copy_out:
        ; 144-byte copy ec384_p1 -> ec384_p3 (see @v384_dcp note).
        ldx #144
        ldy #0
@v384_finc:
        lda ec384_p1,y
        sta ec384_p3,y
        iny
        dex
        bne @v384_finc
        rts

; --- ec_scalar_mul_var_384 state vars (locally scoped; distinct from var_*) ---
var384_k:           .res 48
var384_byte_off:    .byte 0
var384_bit_mask:    .byte 0
var384_loop_ctr_lo: .byte 0
var384_loop_ctr_hi: .byte 0
var384_r_inf:       .byte 0

; =============================================================================
; ec_jacobian_to_affine_384: convert ec384_p3 (Jacobian) to affine (x,y)
; Result: ec384_affine_x, ec384_affine_y (48 bytes each)
; Computes x = X/Z^2, y = Y/Z^3 using modular inverse.
; =============================================================================
ec_jacobian_to_affine_384:
        jsr ec_set_modp_384

        ; Compute Z^(-1)
        lda #<(ec384_p3+96)
        sta fp_src1
        lda #>(ec384_p3+96)
        sta fp_src1+1
        jsr fp_mod_inv_384      ; fp384_r0 = Z^(-1)

        ; Copy Z^(-1) to ec384_t1
        ldy #47
@jta384_czi:
        lda fp384_r0,y
        sta ec384_t1,y
        dey
        bpl @jta384_czi

        ; t2 = Z^(-2) = Z^(-1) * Z^(-1)
        lda #<ec384_t1
        sta fp_src1
        lda #>ec384_t1
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t2
        sta fp_dst
        lda #>ec384_t2
        sta fp_dst+1
        jsr ec_mulp_384         ; t2 = Z^(-2)

        ; t3 = Z^(-3) = Z^(-2) * Z^(-1)
        lda #<ec384_t2
        sta fp_src1
        lda #>ec384_t2
        sta fp_src1+1
        lda #<ec384_t1
        sta fp_src2
        lda #>ec384_t1
        sta fp_src2+1
        lda #<ec384_t3
        sta fp_dst
        lda #>ec384_t3
        sta fp_dst+1
        jsr ec_mulp_384         ; t3 = Z^(-3)

        ; x = X * Z^(-2)
        lda #<ec384_p3
        sta fp_src1
        lda #>ec384_p3
        sta fp_src1+1
        lda #<ec384_t2
        sta fp_src2
        lda #>ec384_t2
        sta fp_src2+1
        lda #<ec384_affine_x
        sta fp_dst
        lda #>ec384_affine_x
        sta fp_dst+1
        jsr ec_mulp_384         ; affine_x = X*Z^(-2)

        ; y = Y * Z^(-3)
        lda #<(ec384_p3+48)
        sta fp_src1
        lda #>(ec384_p3+48)
        sta fp_src1+1
        lda #<ec384_t3
        sta fp_src2
        lda #>ec384_t3
        sta fp_src2+1
        lda #<ec384_affine_y
        sta fp_dst
        lda #>ec384_affine_y
        sta fp_dst+1
        jsr ec_mulp_384         ; affine_y = Y*Z^(-3)

        rts
