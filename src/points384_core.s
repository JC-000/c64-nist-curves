.setcpu "6502"

; =============================================================================
; points384_core.s - P-384 point operations (Jacobian coordinates), core path.
;
; Hosts the operations needed by ECDSA verify (variable-base) but NOT the
; Lim-Lee fixed-base comb: ec_point_double_384, ec_point_add_384 (mixed
; J+affine), ec_point_add_jj_384 (full J+J), ec_scalar_mul_var_384
; (variable-base double-and-add, non-CT), ec_jacobian_to_affine_384. The
; comb (ec_precompute_384 + ec_scalar_mul_384 + sm384w_* helpers) lives in
; points384_comb.s so the lib-p384-verify minimal archive can exclude it.
;
; Split from src/points384.s as part of #40 (SPEC §6).
;
; All field elements are LITTLE-ENDIAN (byte 0 = LSB).
; Point layout: X = offset 0..47, Y = offset 48..95, Z = offset 96..143
; Point at infinity: Z = 0
; =============================================================================

.segment "LIB_NISTCURVES_P384_CODE"

; --- Exports ---
.export ec_point_double_384, ec_point_add_384, ec_point_add_jj_384
.export ec_scalar_mul_var_384
.export ec_jacobian_to_affine_384

; --- ZP imports ---
.importzp fp_src1, fp_src2, fp_dst, ec_scalar_ptr

; --- fp384 imports ---
.import fp_is_zero_384

; --- mod384 imports ---
.import ec_set_modp_384, ec_mulp_384, ec_sqrp_384
.import fp_mod_add_384, fp_mod_sub_384, fp_mod_inv_384

; --- data imports ---
.import ec384_p1, ec384_p2, ec384_p3
.import ec384_t1, ec384_t2, ec384_t3, ec384_t4, ec384_t5, ec384_t6, ec384_jj_tmp
.import ec384_affine_x, ec384_affine_y
.import fp384_r0
.import ec_base384_x, ec_base384_y

; --- constants imports ---
.import reu_reu_lo, reu_addr_ctrl


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
