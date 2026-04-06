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
; ec_precompute_384: Build T[0..15] = i*G as affine, stash to REU bank 2.
; Called once at init. REU layout: bank 2 offset $0400, 16 slots * 96 bytes.
; =============================================================================
ec_precompute_384:
        ; --- T[0] = point at infinity (96 zero bytes) ---
        ldy #95
        lda #0
.sm384w_clr0:
        sta ec384_p2,y
        dey
        bpl .sm384w_clr0
        lda #0
        sta ec384_precomp_i
        jsr .sm384w_stash_p2     ; stash 96 zero bytes as T[0]

        ; --- T[1] = G (already affine, store directly) ---
        ldy #47
.sm384w_t1gx:
        lda ec_gx384,y
        sta ec384_p2,y
        dey
        bpl .sm384w_t1gx
        ldy #47
.sm384w_t1gy:
        lda ec_gy384,y
        sta ec384_p2+48,y
        dey
        bpl .sm384w_t1gy
        lda #1
        sta ec384_precomp_i
        jsr .sm384w_stash_p2     ; stash G affine as T[1]

        ; --- Set up ec384_p1 = G as Jacobian (Z=1) for building T[2..15] ---
        ldy #47
.sm384w_j1x:
        lda ec_gx384,y
        sta ec384_p1,y
        dey
        bpl .sm384w_j1x
        ldy #47
.sm384w_j1y:
        lda ec_gy384,y
        sta ec384_p1+48,y
        dey
        bpl .sm384w_j1y
        ldy #47
        lda #0
.sm384w_j1z:
        sta ec384_p1+96,y
        dey
        bpl .sm384w_j1z
        lda #1
        sta ec384_p1+96          ; Z=1 little-endian

        ; ec384_p2 already has G affine from T[1] setup above.
        ; ec_point_add_384 reads P1=Jacobian, P2=affine(X,Y only).

        ; Set modular arithmetic to use P-384 prime
        jsr ec_set_modp_384

        ; --- T[i] = T[i-1] + G for i=2..15 ---
        ; ec384_p1 holds T[i-1] as Jacobian.
        ; ec384_p2 holds G affine (constant throughout precompute).
        lda #2
        sta ec384_precomp_i

.sm384w_precomp_loop:
        ; ec384_p3 = ec384_p1 + ec384_p2 (= T[i-1] + G) as Jacobian
        jsr ec_point_add_384

        ; Convert ec384_p3 (Jacobian) to affine
        jsr ec_jacobian_to_affine_384
        ; Result in ec384_affine_x, ec384_affine_y

        ; Copy affine coords into ec384_p2 for stashing
        ; (We'll restore G into ec384_p2 after stash)
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

        ; Stash affine T[i] to REU
        jsr .sm384w_stash_p2

        ; Copy ec384_p3 (Jacobian T[i]) -> ec384_p1 for next iteration
        ldy #0
.sm384w_cp_pre:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne .sm384w_cp_pre

        ; Restore G affine into ec384_p2 for next add
        ldy #47
.sm384w_rg_x:
        lda ec_gx384,y
        sta ec384_p2,y
        dey
        bpl .sm384w_rg_x
        ldy #47
.sm384w_rg_y:
        lda ec_gy384,y
        sta ec384_p2+48,y
        dey
        bpl .sm384w_rg_y

        inc ec384_precomp_i
        lda ec384_precomp_i
        cmp #16
        bne .sm384w_precomp_loop

        rts

; =============================================================================
; ec_scalar_mul_384: ec384_p3 = k * G
; k is a 48-byte scalar pointed to by (ec_scalar_ptr), BIG-ENDIAN byte order.
; Uses 4-bit windowed method with precomputed table in REU bank 2.
; REQUIRES: ec_precompute_384 must have been called first.
; =============================================================================
ec_scalar_mul_384:
        ; =====================================================================
        ; Main loop - process 96 nibbles of k, MSB first
        ; =====================================================================

        lda #0
        sta ec384_sc_byte        ; byte index into scalar (0..47)
        sta ec384_sc_half        ; 0=high nibble, 1=low nibble

        ; Find first nonzero nibble (skip leading zeros)
.sm384w_skip_zero:
        jsr .sm384w_get_nibble
        bne .sm384w_found_first

        jsr .sm384w_advance_nibble
        bcc .sm384w_skip_zero
        ; All nibbles zero -> result is point at infinity
        jmp .sm384w_all_zero

.sm384w_found_first:
        ; A = first nonzero nibble value (1..15)
        ; Fetch T[A] affine from REU into ec384_p2
        jsr .sm384w_fetch_to_p2
        ; Set ec384_p1 = T[A] as Jacobian with Z=1
        ldy #47
.sm384w_init_x:
        lda ec384_p2,y
        sta ec384_p1,y
        dey
        bpl .sm384w_init_x
        ldy #47
.sm384w_init_y:
        lda ec384_p2+48,y
        sta ec384_p1+48,y
        dey
        bpl .sm384w_init_y
        ldy #47
        lda #0
.sm384w_init_z:
        sta ec384_p1+96,y
        dey
        bpl .sm384w_init_z
        lda #1
        sta ec384_p1+96          ; Z=1

        ; Advance past first nibble
        jsr .sm384w_advance_nibble
        bcs .sm384w_finish       ; last nibble -> done

.sm384w_main_loop:
        ; Double R (in ec384_p1) four times
        jsr .sm384w_double4

        ; Extract current nibble
        jsr .sm384w_get_nibble
        beq .sm384w_no_add       ; skip add if nibble is 0

        ; Fetch T[nibble] affine from REU into ec384_p2
        jsr .sm384w_fetch_to_p2
        ; ec384_p3 = ec384_p1 + ec384_p2
        jsr ec_point_add_384
        ; Copy ec384_p3 -> ec384_p1
        ldy #0
.sm384w_cp_add:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne .sm384w_cp_add

.sm384w_no_add:
        jsr .sm384w_advance_nibble
        bcc .sm384w_main_loop

.sm384w_finish:
        ; Copy ec384_p1 -> ec384_p3 (result)
        ldy #0
.sm384w_cfin:
        lda ec384_p1,y
        sta ec384_p3,y
        iny
        cpy #144
        bne .sm384w_cfin
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

; -----------------------------------------------------------------------------
; .sm384w_double4: Double ec384_p1 four times (ec384_p1 = 16*ec384_p1)
; -----------------------------------------------------------------------------
.sm384w_double4:
        ldx #4
.sm384w_d4_loop:
        txa
        pha
        jsr ec_point_double_384  ; ec384_p3 = 2*ec384_p1
        ldy #0
.sm384w_d4_cp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne .sm384w_d4_cp
        pla
        tax
        dex
        bne .sm384w_d4_loop
        rts

; -----------------------------------------------------------------------------
; .sm384w_get_nibble: Extract current nibble from scalar k
; Output: A = nibble value (0..15)
; -----------------------------------------------------------------------------
.sm384w_get_nibble:
        ldy ec384_sc_byte
        lda (ec_scalar_ptr),y
        ldy ec384_sc_half
        bne .sm384w_low_nib
        lsr
        lsr
        lsr
        lsr
        rts
.sm384w_low_nib:
        and #$0f
        rts

; -----------------------------------------------------------------------------
; .sm384w_advance_nibble: Move to next nibble
; Output: C=1 if past last nibble (done), C=0 otherwise
; -----------------------------------------------------------------------------
.sm384w_advance_nibble:
        lda ec384_sc_half
        bne .sm384w_next_byte
        lda #1
        sta ec384_sc_half
        clc
        rts
.sm384w_next_byte:
        lda #0
        sta ec384_sc_half
        inc ec384_sc_byte
        lda ec384_sc_byte
        cmp #48
        beq .sm384w_adv_done
        clc
        rts
.sm384w_adv_done:
        sec
        rts

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
