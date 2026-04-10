; =============================================================================
; points384.asm - P-384 point operations (Jacobian coordinates)
; ec_point_double_384, ec_point_add_384, ec_scalar_mul_384,
; ec_jacobian_to_affine_384
;
; All field elements are LITTLE-ENDIAN (byte 0 = LSB).
; Point layout: X = offset 0..47, Y = offset 48..95, Z = offset 96..143
; Point at infinity: Z = 0
; =============================================================================

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
        bne .dbl384_notinf
        ; Result = infinity (zero all of ec384_p3)
        ldy #143
        lda #0
.dbl384_ci:
        sta ec384_p3,y
        dey
        bpl .dbl384_ci
        rts

.dbl384_notinf:
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
        jsr ec_mulp_384         ; t1 = Z1^2

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
        jsr ec_mulp_384         ; t3 = Y1^2

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
        jsr ec_mulp_384         ; t4 = M^2

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
        jsr ec_mulp_384         ; t4 = Y1^4

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
        bne .add384_p1ok

        ; Copy P2 X to P3 X
        ldy #47
.add384_cpx:
        lda ec384_p2,y
        sta ec384_p3,y
        dey
        bpl .add384_cpx
        ; Copy P2 Y to P3 Y
        ldy #47
.add384_cpy:
        lda ec384_p2+48,y
        sta ec384_p3+48,y
        dey
        bpl .add384_cpy
        ; Set Z = 1 (little-endian: byte 0 = 1, rest = 0)
        ldy #47
        lda #0
.add384_clz:
        sta ec384_p3+96,y
        dey
        bpl .add384_clz
        lda #1
        sta ec384_p3+96         ; Z byte 0 = 1 (LSB in little-endian)
        rts

.add384_p1ok:
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
        jsr ec_mulp_384         ; t1 = Z1^2

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
        bne .add384_h_nonzero

        ; H == 0: check R
        lda #<ec384_t2
        sta fp_src1
        lda #>ec384_t2
        sta fp_src1+1
        jsr fp_is_zero_384
        bne .add384_set_inf
        ; H==0, R==0: points are equal, double P1
        jmp ec_point_double_384

.add384_set_inf:
        ; H==0, R!=0: inverse points, result = infinity
        ldy #143
        lda #0
.add384_sinf:
        sta ec384_p3,y
        dey
        bpl .add384_sinf
        rts

.add384_h_nonzero:
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
        jsr ec_mulp_384         ; t3 = H^2

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
        jsr ec_mulp_384         ; t3 = R^2

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
; ec_scalar_mul_384: ec384_p3 = k * G
; k is a 48-byte scalar pointed to by (ec_scalar_ptr), BIG-ENDIAN byte order.
; Uses 4-bit windowed method with precomputed table in REU bank 2.
;
; Precompute: T[0..15] stored as AFFINE (96 bytes each) in REU bank 2.
;   T[0] = zeros (point at infinity)
;   T[1] = G (known affine)
;   T[i] = (i-1)*G + G computed via Jacobian add, then converted to affine
; Main loop: process scalar as 96 nibbles (4 bits each), MSB first.
;   Skip leading zero nibbles, load first nonzero T[n].
;   For each subsequent nibble: 4x double, then add T[n] if n != 0.
;
; Cost: 384 doubles + ~90 adds + 14 adds + 14 inversions (precompute)
; vs old: 384 doubles + ~192 adds. Net savings ~74 seconds.
; =============================================================================

; REU bank for precomputed table
PRECOMP_REU_BANK = 2

; =============================================================================
; ec_precompute_384: Build wNAF-5 table T[0..7] = (2j+1)*G for j=0..7,
;   i.e. { G, 3G, 5G, 7G, 9G, 11G, 13G, 15G }, stored as 96-byte affine
;   entries in REU bank 2 offset $0400. Also caches affine 2G in
;   ec_aff2g_384_{x,y}.
; =============================================================================
ec_precompute_384:
        ; --- Stash T[0] = G affine from the curve generator ---
        ldy #47
.sm384w_t0x:
        lda ec_gx384,y
        sta ec384_p2,y
        dey
        bpl .sm384w_t0x
        ldy #47
.sm384w_t0y:
        lda ec_gy384,y
        sta ec384_p2+48,y
        dey
        bpl .sm384w_t0y
        lda #0
        sta ec384_precomp_i
        jsr .sm384w_stash_p2

        ; --- Compute 2G: ec384_p1 = G as Jacobian, double, convert to affine ---
        ldy #47
.sm384w_g1x:
        lda ec_gx384,y
        sta ec384_p1,y
        dey
        bpl .sm384w_g1x
        ldy #47
.sm384w_g1y:
        lda ec_gy384,y
        sta ec384_p1+48,y
        dey
        bpl .sm384w_g1y
        ldy #47
        lda #0
.sm384w_g1z:
        sta ec384_p1+96,y
        dey
        bpl .sm384w_g1z
        lda #1
        sta ec384_p1+96

        jsr ec_set_modp_384
        jsr ec_point_double_384
        jsr ec_jacobian_to_affine_384

        ; Save 2G affine persistently
        ldy #47
.sm384w_s2gx:
        lda ec384_affine_x,y
        sta ec_aff2g_384_x,y
        dey
        bpl .sm384w_s2gx
        ldy #47
.sm384w_s2gy:
        lda ec384_affine_y,y
        sta ec_aff2g_384_y,y
        dey
        bpl .sm384w_s2gy

        ; --- Running Jacobian accumulator = T[0] = G ---
        ldy #47
.sm384w_a0x:
        lda ec_gx384,y
        sta ec384_p1,y
        dey
        bpl .sm384w_a0x
        ldy #47
.sm384w_a0y:
        lda ec_gy384,y
        sta ec384_p1+48,y
        dey
        bpl .sm384w_a0y
        ldy #47
        lda #0
.sm384w_a0z:
        sta ec384_p1+96,y
        dey
        bpl .sm384w_a0z
        lda #1
        sta ec384_p1+96

        ; --- T[j] = T[j-1] + 2G for j = 1..7 ---
        lda #1
        sta ec384_precomp_i

.sm384w_precomp_loop:
        ; Load 2G affine into ec384_p2
        ldy #47
.sm384w_ld2gx:
        lda ec_aff2g_384_x,y
        sta ec384_p2,y
        dey
        bpl .sm384w_ld2gx
        ldy #47
.sm384w_ld2gy:
        lda ec_aff2g_384_y,y
        sta ec384_p2+48,y
        dey
        bpl .sm384w_ld2gy

        ; ec384_p3 = ec384_p1 + ec384_p2 = T[j-1] + 2G
        jsr ec_point_add_384

        ; Copy ec384_p3 Jacobian -> ec384_p1 (next running accumulator)
        ldy #0
.sm384w_cp_acc:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne .sm384w_cp_acc

        ; Convert ec384_p3 -> affine
        jsr ec_jacobian_to_affine_384

        ; Copy affine to ec384_p2 for stashing
        ldy #47
.sm384w_cpax:
        lda ec384_affine_x,y
        sta ec384_p2,y
        dey
        bpl .sm384w_cpax
        ldy #47
.sm384w_cpay:
        lda ec384_affine_y,y
        sta ec384_p2+48,y
        dey
        bpl .sm384w_cpay

        jsr .sm384w_stash_p2

        inc ec384_precomp_i
        lda ec384_precomp_i
        cmp #8
        bne .sm384w_precomp_loop

        rts

; =============================================================================
; ec_scalar_mul_384: ec384_p3 = k * G
; k is a 48-byte scalar pointed to by (ec_scalar_ptr), BIG-ENDIAN byte order.
; Uses 4-bit windowed method with precomputed table in REU bank 2.
; REQUIRES: ec_precompute_384 must have been called first.
; =============================================================================
ec_scalar_mul_384:
        ; --- Recode scalar into wNAF-5 digits (shared recoder from points256) ---
        lda #48                  ; P-384 scalar length in bytes
        jsr ec_naf_recode

        ; If length == 0 -> result is infinity
        lda ec_naf_len
        ora ec_naf_len+1
        bne .sm384n_have
        jmp .sm384w_all_zero

.sm384n_have:
        jsr ec_set_modp_384

        lda ec_naf_len
        sec
        sbc #1
        sta .sm384n_idx_lo
        lda ec_naf_len+1
        sbc #0
        sta .sm384n_idx_hi

        jsr .sm384n_load_top     ; ec384_p1 = (top digit) * G (Jacobian, Z=1)

.sm384n_main:
        lda .sm384n_idx_lo
        ora .sm384n_idx_hi
        bne .sm384n_decr
        jmp .sm384n_done
.sm384n_decr:
        lda .sm384n_idx_lo
        bne .sm384n_dec_lo
        dec .sm384n_idx_hi
.sm384n_dec_lo:
        dec .sm384n_idx_lo

        ; Double R once
        jsr ec_point_double_384
        ldy #0
.sm384n_dcp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne .sm384n_dcp

        jsr .sm384n_get_digit
        beq .sm384n_main

        sta .sm384n_dig_tmp
        bmi .sm384n_neg
        lsr
        jsr .sm384w_fetch_to_p2
        jmp .sm384n_do_add
.sm384n_neg:
        lda #0
        sec
        sbc .sm384n_dig_tmp
        lsr
        jsr .sm384w_fetch_to_p2
        ; Negate Y in ec384_p2: ec384_p2+48 = p384 - ec384_p2+48
        lda #<ec_p384
        sta fp_src1
        lda #>ec_p384
        sta fp_src1+1
        lda #<(ec384_p2+48)
        sta fp_src2
        lda #>(ec384_p2+48)
        sta fp_src2+1
        lda #<(ec384_p2+48)
        sta fp_dst
        lda #>(ec384_p2+48)
        sta fp_dst+1
        jsr fp_mod_sub_384
.sm384n_do_add:
        jsr ec_point_add_384
        ldy #0
.sm384n_acp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne .sm384n_acp
        jmp .sm384n_main

.sm384n_done:
        ldy #0
.sm384n_fin:
        lda ec384_p1,y
        sta ec384_p3,y
        iny
        cpy #144
        bne .sm384n_fin
        rts

.sm384w_all_zero:
        ldy #0
        lda #0
.sm384w_czr:
        sta ec384_p3,y
        iny
        cpy #144
        bne .sm384w_czr
        rts

; --- Load top wNAF digit into ec384_p1 as Jacobian (Z=1) ---
.sm384n_load_top:
        jsr .sm384n_get_digit
        sta .sm384n_dig_tmp
        bmi .sm384n_lt_neg
        lsr
        jsr .sm384w_fetch_to_p2
        jmp .sm384n_lt_cp
.sm384n_lt_neg:
        lda #0
        sec
        sbc .sm384n_dig_tmp
        lsr
        jsr .sm384w_fetch_to_p2
        lda #<ec_p384
        sta fp_src1
        lda #>ec_p384
        sta fp_src1+1
        lda #<(ec384_p2+48)
        sta fp_src2
        lda #>(ec384_p2+48)
        sta fp_src2+1
        lda #<(ec384_p2+48)
        sta fp_dst
        lda #>(ec384_p2+48)
        sta fp_dst+1
        jsr fp_mod_sub_384
.sm384n_lt_cp:
        ; Copy ec384_p2 (affine X,Y) to ec384_p1 with Z=1
        ldy #47
.sm384n_lx:
        lda ec384_p2,y
        sta ec384_p1,y
        dey
        bpl .sm384n_lx
        ldy #47
.sm384n_ly:
        lda ec384_p2+48,y
        sta ec384_p1+48,y
        dey
        bpl .sm384n_ly
        ldy #47
        lda #0
.sm384n_lz:
        sta ec384_p1+96,y
        dey
        bpl .sm384n_lz
        lda #1
        sta ec384_p1+96
        rts

; --- Fetch signed digit at index .sm384n_idx_{lo,hi} into A ---
.sm384n_get_digit:
        lda .sm384n_idx_lo
        clc
        adc #<ec_naf_digits
        sta zp_ptr1
        lda .sm384n_idx_hi
        adc #>ec_naf_digits
        sta zp_ptr1+1
        ldy #0
        lda (zp_ptr1),y
        rts

.sm384n_idx_lo: !byte 0
.sm384n_idx_hi: !byte 0
.sm384n_dig_tmp: !byte 0

; -----------------------------------------------------------------------------
; .sm384w_stash_p2: Stash ec384_p2 (96 bytes affine) to REU bank 2
; Input: ec384_precomp_i = table index (0..15)
; REU offset = index * 96
; -----------------------------------------------------------------------------
.sm384w_stash_p2:
        jsr .sm384w_calc_reu_offset

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

        jsr .sm384w_restore_reu
        rts

; -----------------------------------------------------------------------------
; .sm384w_fetch_to_p2: Fetch T[A] affine (96 bytes) from REU into ec384_p2
; Input: A = table index (0..15)
; -----------------------------------------------------------------------------
.sm384w_fetch_to_p2:
        sta ec384_precomp_i
        jsr .sm384w_calc_reu_offset

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

        jsr .sm384w_restore_reu
        rts

; -----------------------------------------------------------------------------
; .sm384w_calc_reu_offset: Set REU address registers for table index
; Input: ec384_precomp_i = index (0..15)
; Offset = index * 96 = index * 64 + index * 32
; -----------------------------------------------------------------------------
.sm384w_calc_reu_offset:
        lda ec384_precomp_i
        ; i * 32: shift left 5
        asl
        asl
        asl
        asl
        asl
        sta zp_tmp1              ; low byte of i*32
        lda ec384_precomp_i
        lsr
        lsr
        lsr                      ; high byte of i*32 (i>>3)
        sta zp_tmp2

        ; i * 64 = (i*32) * 2
        lda zp_tmp1
        asl
        sta reu_reu_lo
        lda zp_tmp2
        rol
        sta reu_reu_hi

        ; + i*32
        lda reu_reu_lo
        clc
        adc zp_tmp1
        sta reu_reu_lo
        lda reu_reu_hi
        adc zp_tmp2
        ; Add $0400 base offset so P-384 table doesn't overlap P-256 table
        clc
        adc #$04
        sta reu_reu_hi

        lda #PRECOMP_REU_BANK
        sta reu_reu_bank
        rts

; -----------------------------------------------------------------------------
; .sm384w_restore_reu: Restore REU registers for multiply table access
; -----------------------------------------------------------------------------
.sm384w_restore_reu:
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
.jta384_czi:
        lda fp384_r0,y
        sta ec384_t1,y
        dey
        bpl .jta384_czi

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
