.setcpu "6502"

; =============================================================================
; points256_core.s - P-256 point operations (Jacobian coordinates), core path.
;
; Hosts the operations needed by ECDSA verify (variable-base) but NOT the
; Lim-Lee fixed-base comb: ec_point_double, ec_point_add (mixed J+affine),
; ec_point_add_jj (full J+J), ec_scalar_mul_var (variable-base double-and-
; add, non-CT), ec_jacobian_to_affine. The comb (ec_precompute_256 +
; ec_scalar_mul + sm256_reu_* helpers) lives in points256_comb.s so the
; lib-p256-verify minimal archive can exclude it.
;
; Split from src/points256.s as part of #40 (SPEC §6).
;
; All field elements are LITTLE-ENDIAN (byte 0 = LSB).
; Point layout: X = offset 0..31, Y = offset 32..63, Z = offset 64..95
; Point at infinity: Z = 0
; =============================================================================

.segment "LIB_NISTCURVES_P256_CODE"

; --- Exports ---
.export ec_point_double, ec_point_add, ec_point_add_jj
.export ec_scalar_mul_var
.export ec_jacobian_to_affine

; --- ZP imports ---
.importzp fp_src1, fp_src2, fp_dst, ec_scalar_ptr

; --- fp256 imports ---
.import fp_is_zero

; --- mod256 imports ---
.import ec_set_modp, ec_mulp, ec_sqrp
.import fp_mod_add, fp_mod_sub, fp_mod_inv

; --- data imports ---
.import ec_p1, ec_p2, ec_p3
.import ec_t1, ec_t2, ec_t3, ec_t4, ec_t5, ec_t6, ec_jj_tmp
.import ec_affine_x, ec_affine_y
.import fp_r0
.import ec_base_x, ec_base_y

; --- constants imports ---
.import reu_reu_lo, reu_addr_ctrl

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
; ec_point_add_jj: ec_p3 = ec_p1 + ec_p2 (full Jacobian + Jacobian)
;
; Both P1 and P2 are Jacobian (X,Y,Z each 32 bytes); unlike ec_point_add
; above (which is a mixed Jacobian+affine add and treats Z2 as implicitly
; 1), this routine reads Z2 from ec_p2+64. Formula: Bernstein-Lange
; add-2007-bl (11M + 5S + ~10 add/sub):
;
;   Z1Z1 = Z1^2
;   Z2Z2 = Z2^2
;   U1   = X1 * Z2Z2
;   U2   = X2 * Z1Z1
;   S1   = Y1 * Z2 * Z2Z2
;   S2   = Y2 * Z1 * Z1Z1
;   H    = U2 - U1
;   I    = (2H)^2
;   J    = H * I
;   r    = 2 * (S2 - S1)
;   V    = U1 * I
;   X3   = r^2 - J - 2*V
;   Y3   = r*(V - X3) - 2*S1*J
;   Z3   = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
;
; Edge cases handled:
;   * P1 = infinity (Z1=0) -> ec_p3 := P2
;   * P2 = infinity (Z2=0) -> ec_p3 := P1
;   * P1 == P2 (H==0 and r==0)  -> tail-call ec_point_double on P1
;   * P1 == -P2 (H==0 and r!=0) -> ec_p3 := infinity
;   * Both infinity -> ec_p3 := P2 (which is also infinity)
;
; Scratch slot map (peak 7 simultaneously live):
;   t1 = Z1Z1                 t5 = S1
;   t2 = Z2Z2 / J             t6 = S2 / (S2 - S1) / r
;   t3 = U1                   jj_tmp = scratch (Y1*Z2, Y2*Z1, I, ...)
;   t4 = U2 / H / V
;
; Output: ec_p3 (Jacobian).
; =============================================================================
ec_point_add_jj:
        ; If P1 is infinity (Z1==0): result = P2 (verbatim copy, 96 B).
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        jsr fp_is_zero
        bne @jj_p1ok
        ; Copy ec_p2 -> ec_p3 (96 B). ldy #95 / dey / bpl is safe (95 = $5F,
        ; bit 7 clear) AND BPL tests N from DEY, not from the LDA byte (no
        ; LDA-clobbers-Z hazard here because BPL reads N, which DEY just set).
        ldy #95
@jj_cp_p2:
        lda ec_p2,y
        sta ec_p3,y
        dey
        bpl @jj_cp_p2
        rts

@jj_p1ok:
        ; If P2 is infinity (Z2==0): result = P1.
        lda #<(ec_p2+64)
        sta fp_src1
        lda #>(ec_p2+64)
        sta fp_src1+1
        jsr fp_is_zero
        bne @jj_p2ok
        ldy #95
@jj_cp_p1:
        lda ec_p1,y
        sta ec_p3,y
        dey
        bpl @jj_cp_p1
        rts

@jj_p2ok:
        jsr ec_set_modp

        ; t1 = Z1^2
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr ec_sqrp

        ; t2 = Z2^2
        lda #<(ec_p2+64)
        sta fp_src1
        lda #>(ec_p2+64)
        sta fp_src1+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr ec_sqrp

        ; t3 = U1 = X1 * Z2Z2 = X1 * t2
        lda #<ec_p1
        sta fp_src1
        lda #>ec_p1
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_mulp

        ; t4 = U2 = X2 * Z1Z1 = X2 * t1
        lda #<ec_p2
        sta fp_src1
        lda #>ec_p2
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp

        ; jj_tmp = Y1 * Z2
        lda #<(ec_p1+32)
        sta fp_src1
        lda #>(ec_p1+32)
        sta fp_src1+1
        lda #<(ec_p2+64)
        sta fp_src2
        lda #>(ec_p2+64)
        sta fp_src2+1
        lda #<ec_jj_tmp
        sta fp_dst
        lda #>ec_jj_tmp
        sta fp_dst+1
        jsr ec_mulp

        ; t5 = S1 = (Y1*Z2) * Z2Z2 = jj_tmp * t2
        lda #<ec_jj_tmp
        sta fp_src1
        lda #>ec_jj_tmp
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr ec_mulp

        ; jj_tmp = Y2 * Z1
        lda #<(ec_p2+32)
        sta fp_src1
        lda #>(ec_p2+32)
        sta fp_src1+1
        lda #<(ec_p1+64)
        sta fp_src2
        lda #>(ec_p1+64)
        sta fp_src2+1
        lda #<ec_jj_tmp
        sta fp_dst
        lda #>ec_jj_tmp
        sta fp_dst+1
        jsr ec_mulp

        ; t6 = S2 = (Y2*Z1) * Z1Z1 = jj_tmp * t1
        lda #<ec_jj_tmp
        sta fp_src1
        lda #>ec_jj_tmp
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr ec_mulp

        ; t4 = H = U2 - U1 = t4 - t3
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr fp_mod_sub

        ; t6 = S2 - S1 = t6 - t5
        lda #<ec_t6
        sta fp_src1
        lda #>ec_t6
        sta fp_src1+1
        lda #<ec_t5
        sta fp_src2
        lda #>ec_t5
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr fp_mod_sub          ; t6 = S2 - S1

        ; Check H == 0.
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        jsr fp_is_zero
        bne @jj_h_nonzero

        ; H == 0. Check (S2 - S1). If also 0 -> double; else -> infinity.
        lda #<ec_t6
        sta fp_src1
        lda #>ec_t6
        sta fp_src1+1
        jsr fp_is_zero
        bne @jj_set_inf
        ; Same projective point (H==0 && r==0): double P1.
        jmp ec_point_double

@jj_set_inf:
        ; H==0, S2!=S1: P1 == -P2, result = infinity (zero all of ec_p3).
        ldy #95
        lda #0
@jj_sinf:
        sta ec_p3,y
        dey
        bpl @jj_sinf
        rts

@jj_h_nonzero:
        ; t6 = r = 2 * (S2 - S1) = t6 + t6 (mod p)
        lda #<ec_t6
        sta fp_src1
        lda #>ec_t6
        sta fp_src1+1
        lda #<ec_t6
        sta fp_src2
        lda #>ec_t6
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr fp_mod_add

        ; --- Z3 first (uses Z1Z1=t1, Z2Z2=t2, H=t4, then frees them).
        ; jj_tmp = Z1 + Z2
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        lda #<(ec_p2+64)
        sta fp_src2
        lda #>(ec_p2+64)
        sta fp_src2+1
        lda #<ec_jj_tmp
        sta fp_dst
        lda #>ec_jj_tmp
        sta fp_dst+1
        jsr fp_mod_add

        ; jj_tmp = (Z1+Z2)^2
        lda #<ec_jj_tmp
        sta fp_src1
        lda #>ec_jj_tmp
        sta fp_src1+1
        lda #<ec_jj_tmp
        sta fp_dst
        lda #>ec_jj_tmp
        sta fp_dst+1
        jsr ec_sqrp

        ; jj_tmp = (Z1+Z2)^2 - Z1Z1 = jj_tmp - t1
        lda #<ec_jj_tmp
        sta fp_src1
        lda #>ec_jj_tmp
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_jj_tmp
        sta fp_dst
        lda #>ec_jj_tmp
        sta fp_dst+1
        jsr fp_mod_sub

        ; jj_tmp = jj_tmp - Z2Z2 = jj_tmp - t2    (== 2 Z1 Z2)
        lda #<ec_jj_tmp
        sta fp_src1
        lda #>ec_jj_tmp
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_jj_tmp
        sta fp_dst
        lda #>ec_jj_tmp
        sta fp_dst+1
        jsr fp_mod_sub

        ; ec_p3+64 = Z3 = (...) * H = jj_tmp * t4
        lda #<ec_jj_tmp
        sta fp_src1
        lda #>ec_jj_tmp
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<(ec_p3+64)
        sta fp_dst
        lda #>(ec_p3+64)
        sta fp_dst+1
        jsr ec_mulp             ; Z3 written.  t1, t2 are now free.

        ; --- I = (2H)^2 (t1 free, use it)
        ; t1 = 2H = H + H
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr fp_mod_add

        ; t1 = I = (2H)^2
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr ec_sqrp

        ; --- J = H * I (use t2, which is free)
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr ec_mulp             ; t2 = J. H (t4) is no longer needed; reuse it for V.

        ; --- V = U1 * I = t3 * t1 -> t4
        lda #<ec_t3
        sta fp_src1
        lda #>ec_t3
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = V. U1 (t3) is no longer needed.

        ; --- X3 = r^2 - J - 2*V
        ; jj_tmp = r^2 = t6^2
        lda #<ec_t6
        sta fp_src1
        lda #>ec_t6
        sta fp_src1+1
        lda #<ec_jj_tmp
        sta fp_dst
        lda #>ec_jj_tmp
        sta fp_dst+1
        jsr ec_sqrp

        ; jj_tmp = r^2 - J = jj_tmp - t2
        lda #<ec_jj_tmp
        sta fp_src1
        lda #>ec_jj_tmp
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_jj_tmp
        sta fp_dst
        lda #>ec_jj_tmp
        sta fp_dst+1
        jsr fp_mod_sub

        ; t3 = 2V = V + V = t4 + t4
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr fp_mod_add

        ; ec_p3 = X3 = jj_tmp - 2V = jj_tmp - t3
        lda #<ec_jj_tmp
        sta fp_src1
        lda #>ec_jj_tmp
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_p3
        sta fp_dst
        lda #>ec_p3
        sta fp_dst+1
        jsr fp_mod_sub          ; X3 written.

        ; --- Y3 = r*(V - X3) - 2*S1*J
        ; jj_tmp = V - X3 = t4 - ec_p3
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_p3
        sta fp_src2
        lda #>ec_p3
        sta fp_src2+1
        lda #<ec_jj_tmp
        sta fp_dst
        lda #>ec_jj_tmp
        sta fp_dst+1
        jsr fp_mod_sub

        ; jj_tmp = r * (V - X3) = t6 * jj_tmp
        lda #<ec_t6
        sta fp_src1
        lda #>ec_t6
        sta fp_src1+1
        lda #<ec_jj_tmp
        sta fp_src2
        lda #>ec_jj_tmp
        sta fp_src2+1
        lda #<ec_jj_tmp
        sta fp_dst
        lda #>ec_jj_tmp
        sta fp_dst+1
        jsr ec_mulp

        ; t3 = S1 * J = t5 * t2
        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_mulp

        ; t3 = 2*S1*J = t3 + t3
        lda #<ec_t3
        sta fp_src1
        lda #>ec_t3
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr fp_mod_add

        ; ec_p3+32 = Y3 = jj_tmp - 2*S1*J = jj_tmp - t3
        lda #<ec_jj_tmp
        sta fp_src1
        lda #>ec_jj_tmp
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<(ec_p3+32)
        sta fp_dst
        lda #>(ec_p3+32)
        sta fp_dst+1
        jsr fp_mod_sub

        rts
; =============================================================================
; ec_scalar_mul_var: variable-base scalar multiplication (left-to-right
;   double-and-add over 256 bits; non-constant-time, for ECDSA verify).
; Input:  ec_scalar_ptr -> 32-byte BE scalar
;         ec_base_x, ec_base_y -> 32-byte LE affine base point
; Output: ec_p3 (Jacobian, 96 B)
; NOT re-entrant. Serialize with all other field/point ops.
; =============================================================================
ec_scalar_mul_var:
        ; --- Defensive REU register init (issue #33-class defence;
        ; see ec_scalar_mul above and c64-x25519 commit 817f525).
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        jsr ec_set_modp

        ; Transpose BE scalar into LE internal buffer var_k.
        ;   var_k[0]  = scalar[31]  (LSB)
        ;   var_k[31] = scalar[0]   (MSB)
        ldy #31
        ldx #0
@vxpose:
        lda (ec_scalar_ptr),y
        sta var_k,x
        inx
        dey
        bpl @vxpose

        ; Init walking state. Bit 255 is var_k[31] bit 7.
        lda #31
        sta var_byte_off
        lda #$80
        sta var_bit_mask
        lda #0
        sta var_loop_ctr_lo     ; 256 iterations encoded as hi=1/lo=0
        lda #1
        sta var_loop_ctr_hi
        lda #1
        sta var_r_inf           ; R = infinity

@v_loop:
        ; --- Double R unless infinity ---
        lda var_r_inf
        bne @v_skip_double
        jsr ec_point_double
        ldy #95
@v_dcp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl @v_dcp
@v_skip_double:

        ; --- Test current bit of scalar ---
        ldx var_byte_off
        lda var_k,x
        and var_bit_mask
        beq @v_bit_is_zero

        ; Bit set: need to add base point to R.
        ; Stage P2 = (base_x, base_y) for the (possibly) coming add.
        ldy #31
@v_cpbx:
        lda ec_base_x,y
        sta ec_p2,y
        dey
        bpl @v_cpbx
        ldy #31
@v_cpby:
        lda ec_base_y,y
        sta ec_p2+32,y
        dey
        bpl @v_cpby

        lda var_r_inf
        beq @v_real_add

        ; First set bit: seed R = (base_x, base_y, 1).
        ldy #31
@v_seedx:
        lda ec_base_x,y
        sta ec_p1,y
        dey
        bpl @v_seedx
        ldy #31
@v_seedy:
        lda ec_base_y,y
        sta ec_p1+32,y
        dey
        bpl @v_seedy
        ; Z = 1 (LE: byte 0 = 1, rest = 0)
        ldy #31
        lda #0
@v_seedz:
        sta ec_p1+64,y
        dey
        bpl @v_seedz
        lda #1
        sta ec_p1+64
        lda #0
        sta var_r_inf
        jmp @v_bit_done

@v_real_add:
        jsr ec_point_add
        ldy #95
@v_acp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl @v_acp

@v_bit_is_zero:
@v_bit_done:
        ; --- Advance to next-lower bit ---
        lsr var_bit_mask
        bne @v_after_advance
        lda #$80
        sta var_bit_mask
        dec var_byte_off
@v_after_advance:

        ; --- 256-iteration counter (hi=1/lo=0 decrementing to 0) ---
        dec var_loop_ctr_lo
        bne @v_loop_trampoline
        dec var_loop_ctr_hi
        bne @v_loop_trampoline
        jmp @v_loop_done
@v_loop_trampoline:
        jmp @v_loop

@v_loop_done:
        ; --- Done. If R still infinity, return zero; else copy ec_p1 -> ec_p3. ---
        lda var_r_inf
        beq @v_copy_out
        ldy #95
        lda #0
@v_zinf:
        sta ec_p3,y
        dey
        bpl @v_zinf
        rts

@v_copy_out:
        ldy #95
@v_finc:
        lda ec_p1,y
        sta ec_p3,y
        dey
        bpl @v_finc
        rts

; --- ec_scalar_mul_var state vars (locally scoped; distinct from cm_*) ---
var_k:           .res 32
var_byte_off:    .byte 0
var_bit_mask:    .byte 0
var_loop_ctr_lo: .byte 0
var_loop_ctr_hi: .byte 0
var_r_inf:       .byte 0

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
