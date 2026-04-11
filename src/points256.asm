; =============================================================================
; points256.asm - P-256 point operations (Jacobian coordinates)
; ec_point_double, ec_point_add, ec_scalar_mul, ec_jacobian_to_affine
;
; All field elements are LITTLE-ENDIAN (byte 0 = LSB).
; Point layout: X = offset 0..31, Y = offset 32..63, Z = offset 64..95
; Point at infinity: Z = 0
; =============================================================================

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
        bne .dbl_notinf
        ; Result = infinity (zero all of ec_p3)
        ldy #95
        lda #0
.dbl_ci:
        sta ec_p3,y
        dey
        bpl .dbl_ci
        rts

.dbl_notinf:
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
        bne .add_p1ok

        ; Copy P2 X to P3 X
        ldy #31
.add_cpx:
        lda ec_p2,y
        sta ec_p3,y
        dey
        bpl .add_cpx
        ; Copy P2 Y to P3 Y
        ldy #31
.add_cpy:
        lda ec_p2+32,y
        sta ec_p3+32,y
        dey
        bpl .add_cpy
        ; Set Z = 1 (little-endian: byte 0 = 1, rest = 0)
        ldy #31
        lda #0
.add_clz:
        sta ec_p3+64,y
        dey
        bpl .add_clz
        lda #1
        sta ec_p3+64            ; Z byte 0 = 1 (LSB in little-endian)
        rts

.add_p1ok:
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
        bne .add_h_nonzero

        ; H == 0: check R
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        jsr fp_is_zero
        bne .add_set_inf
        ; H==0, R==0: points are equal, double P1
        jmp ec_point_double

.add_set_inf:
        ; H==0, R!=0: inverse points, result = infinity
        ldy #95
        lda #0
.add_sinf:
        sta ec_p3,y
        dey
        bpl .add_sinf
        rts

.add_h_nonzero:
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
.sm_reu_stash_affine:
        sta .sm_reu_idx
        jsr .sm_calc_offset_64  ; compute .sm_reu_off_lo/hi = idx * 64
        lda #<ec_affine_x
        sta reu_c64_lo
        lda #>ec_affine_x
        sta reu_c64_hi
        lda .sm_reu_off_lo
        sta reu_reu_lo
        lda .sm_reu_off_hi
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
        jmp .sm_reu_restore

; --- REU DMA: fetch 64 bytes (affine X,Y) from REU table slot to ec_p2 ---
; Input: A = table index (1..15)
.sm_reu_fetch_affine:
        sta .sm_reu_idx
        jsr .sm_calc_offset_64
        lda #<ec_p2
        sta reu_c64_lo
        lda #>ec_p2
        sta reu_c64_hi
        lda .sm_reu_off_lo
        sta reu_reu_lo
        lda .sm_reu_off_hi
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
        jmp .sm_reu_restore

; --- REU DMA: fetch 96 bytes (Jacobian) from REU temp area to ec_p1 ---
; REU bank 2 offset $0800 + idx*96 for Jacobian temp storage
; Input: A = table index (0..15)
.sm_reu_fetch_jac:
        sta .sm_reu_idx
        jsr .sm_calc_offset_96  ; compute offset = idx * 96
        ; Add $0800 base offset for Jacobian temp area
        lda .sm_reu_off_lo
        clc
        adc #0
        sta .sm_reu_off_lo
        lda .sm_reu_off_hi
        adc #$08
        sta .sm_reu_off_hi
        lda #<ec_p1
        sta reu_c64_lo
        lda #>ec_p1
        sta reu_c64_hi
        lda .sm_reu_off_lo
        sta reu_reu_lo
        lda .sm_reu_off_hi
        sta reu_reu_hi
        lda #2
        sta reu_reu_bank
        lda #96
        sta reu_len_lo
        lda #0
        sta reu_len_hi
        sta reu_addr_ctrl
        lda #$B1                ; execute + autoload + FETCH
        sta reu_command
        jmp .sm_reu_restore

; --- REU DMA: stash 96 bytes (Jacobian) from ec_p3 to REU temp area ---
; Input: A = table index (0..15)
.sm_reu_stash_jac:
        sta .sm_reu_idx
        jsr .sm_calc_offset_96
        lda .sm_reu_off_lo
        clc
        adc #0
        sta .sm_reu_off_lo
        lda .sm_reu_off_hi
        adc #$08
        sta .sm_reu_off_hi
        lda #<ec_p3
        sta reu_c64_lo
        lda #>ec_p3
        sta reu_c64_hi
        lda .sm_reu_off_lo
        sta reu_reu_lo
        lda .sm_reu_off_hi
        sta reu_reu_hi
        lda #2
        sta reu_reu_bank
        lda #96
        sta reu_len_lo
        lda #0
        sta reu_len_hi
        sta reu_addr_ctrl
        lda #$B0                ; execute + autoload + STASH
        sta reu_command
        jmp .sm_reu_restore

; --- Calculate offset = idx * 64 ---
.sm_calc_offset_64:
        lda .sm_reu_idx
        asl                     ; *2
        asl                     ; *4
        asl                     ; *8
        asl                     ; *16
        asl                     ; *32
        asl                     ; *64
        sta .sm_reu_off_lo
        lda .sm_reu_idx
        lsr                     ; idx/2 = high byte of idx*64 (partial)
        lsr
        sta .sm_reu_off_hi
        rts

; --- Calculate offset = idx * 96 = idx*64 + idx*32 ---
.sm_calc_offset_96:
        lda .sm_reu_idx
        asl                     ; *2
        asl                     ; *4
        asl                     ; *8
        asl                     ; *16
        asl                     ; *32
        sta .sm_reu_off_lo      ; low byte of idx*32
        lda .sm_reu_idx
        lsr
        lsr
        lsr                     ; high byte of idx*32
        sta .sm_reu_off_hi
        ; idx*64 = idx*32 * 2
        lda .sm_reu_off_lo
        asl
        sta .sm_reu_tmp
        lda .sm_reu_off_hi
        rol
        sta .sm_reu_tmp+1
        ; offset = idx*32 + idx*64
        lda .sm_reu_off_lo
        clc
        adc .sm_reu_tmp
        sta .sm_reu_off_lo
        lda .sm_reu_off_hi
        adc .sm_reu_tmp+1
        sta .sm_reu_off_hi
        rts

; --- Restore mul-table REU registers after point DMA ---
.sm_reu_restore:
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
.sm_reu_idx:    !byte 0
.sm_reu_off_lo: !byte 0
.sm_reu_off_hi: !byte 0
.sm_reu_tmp:    !word 0
.sm_nibble_val: !byte 0         ; current nibble value

; =============================================================================
; ec_precompute_256: Build Lim-Lee 4-way fixed-base comb table for P-256.
;
; Comb parameters: h = 4 sub-scalars, a = 64 bits each (h*a = 256).
; Anchors:
;   A1 = G               (= 2^0   * G)
;   A2 = 2^64  * G       (64 doublings of A1)
;   A3 = 2^128 * G       (128 doublings of A1, i.e. 64 doublings of A2)
;   A4 = 2^192 * G       (192 doublings of A1, i.e. 64 doublings of A3)
; Table T[j] for j in 1..15:
;   T[j] = ((j>>0)&1)*A1 + ((j>>1)&1)*A2 + ((j>>2)&1)*A3 + ((j>>3)&1)*A4
; Bit p of j corresponds to sub-scalar K_p (this exact convention is also
; used by ec_scalar_mul -- see the index extraction code there).
; T[0] is the identity and is never fetched.
;
; Storage: 16 slots * 64-byte affine (X,Y) in REU bank 2 offset $0000..$03FF.
; Slot 0 is left as whatever junk; the main loop guards against fetching it.
;
; This routine is called once at init.  It uses 192 ec_point_doubles to
; build the four anchors plus 26 mixed ec_point_adds (sum of |T[j]|-1 over
; j=1..15) and 19 jacobian_to_affine conversions (4 anchors + 15 table
; entries that have at least one set bit).  No Montgomery-batched inversion
; is used in v1.
; =============================================================================
ec_precompute_256:
        jsr ec_set_modp

        ; ----- A1 = G affine: store directly into ec_anchor1_x/y. -----
        ldy #31
.cmp_a1x:
        lda ec_gx256,y
        sta ec_anchor1_x,y
        dey
        bpl .cmp_a1x
        ldy #31
.cmp_a1y:
        lda ec_gy256,y
        sta ec_anchor1_y,y
        dey
        bpl .cmp_a1y

        ; ----- Build A2 = 2^64 * G via 64 doublings of G. -----
        ; Initialise ec_p1 = G (Jacobian, Z=1).
        jsr .cmp_load_p1_g
        lda #64
        jsr .cmp_double_p1_n
        ; ec_p1 holds 2^64 * G in Jacobian -- copy to ec_p3 then convert.
        jsr .cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        ldy #31
.cmp_sa2x:
        lda ec_affine_x,y
        sta ec_anchor2_x,y
        dey
        bpl .cmp_sa2x
        ldy #31
.cmp_sa2y:
        lda ec_affine_y,y
        sta ec_anchor2_y,y
        dey
        bpl .cmp_sa2y

        ; ----- Build A3 = 2^128 * G via 64 more doublings. -----
        lda #64
        jsr .cmp_double_p1_n
        jsr .cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        ldy #31
.cmp_sa3x:
        lda ec_affine_x,y
        sta ec_anchor3_x,y
        dey
        bpl .cmp_sa3x
        ldy #31
.cmp_sa3y:
        lda ec_affine_y,y
        sta ec_anchor3_y,y
        dey
        bpl .cmp_sa3y

        ; ----- Build A4 = 2^192 * G via 64 more doublings. -----
        lda #64
        jsr .cmp_double_p1_n
        jsr .cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        ldy #31
.cmp_sa4x:
        lda ec_affine_x,y
        sta ec_anchor4_x,y
        dey
        bpl .cmp_sa4x
        ldy #31
.cmp_sa4y:
        lda ec_affine_y,y
        sta ec_anchor4_y,y
        dey
        bpl .cmp_sa4y

        ; ----- Build T[j] for j = 1..15 by subset-sum. -----
        lda #1
        sta ec_sc_byte                  ; j counter
.cmp_tloop:
        ; ec_p1 starts uninitialised this iteration. We use cm_seeded
        ; flag: 0 = next set bit copies anchor into ec_p1 (with Z=1),
        ; 1 = subsequent set bits load anchor as affine ec_p2 and add.
        lda #0
        sta cm_seeded
        ; Test bit 0 (A1)
        lda ec_sc_byte
        and #1
        beq .cmp_tj_b1
        lda #0                          ; anchor index 0
        jsr .cmp_accum_anchor
.cmp_tj_b1:
        lda ec_sc_byte
        and #2
        beq .cmp_tj_b2
        lda #1
        jsr .cmp_accum_anchor
.cmp_tj_b2:
        lda ec_sc_byte
        and #4
        beq .cmp_tj_b3
        lda #2
        jsr .cmp_accum_anchor
.cmp_tj_b3:
        lda ec_sc_byte
        and #8
        beq .cmp_tj_done
        lda #3
        jsr .cmp_accum_anchor
.cmp_tj_done:
        ; ec_p1 holds T[j] in Jacobian. Convert to affine and stash.
        jsr .cmp_p1_to_p3
        jsr ec_jacobian_to_affine
        lda ec_sc_byte
        jsr .sm_reu_stash_affine
        inc ec_sc_byte
        lda ec_sc_byte
        cmp #16
        bne .cmp_tloop
        rts

; --- Internal helper: load ec_p1 = G as Jacobian (Z=1). ---
.cmp_load_p1_g:
        ldy #31
.cmp_lpg_x:
        lda ec_gx256,y
        sta ec_p1,y
        dey
        bpl .cmp_lpg_x
        ldy #31
.cmp_lpg_y:
        lda ec_gy256,y
        sta ec_p1+32,y
        dey
        bpl .cmp_lpg_y
        ldy #31
        lda #0
.cmp_lpg_z:
        sta ec_p1+64,y
        dey
        bpl .cmp_lpg_z
        lda #1
        sta ec_p1+64
        rts

; --- Internal helper: ec_p1 = 2^A * ec_p1 (A successive doublings). ---
; A in 1..255 (uses ec_sc_mask as counter so as not to clobber ec_sc_byte).
.cmp_double_p1_n:
        sta ec_sc_mask
.cmp_dpn_loop:
        jsr ec_point_double
        ldy #95
.cmp_dpn_cp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .cmp_dpn_cp
        dec ec_sc_mask
        bne .cmp_dpn_loop
        rts

; --- Internal helper: copy ec_p1 -> ec_p3 (96 bytes). ---
.cmp_p1_to_p3:
        ldy #95
.cmp_pp3_cp:
        lda ec_p1,y
        sta ec_p3,y
        dey
        bpl .cmp_pp3_cp
        rts

; --- Internal helper: accumulate anchor[A] into ec_p1 (Jacobian). ---
; If cm_seeded == 0: copy anchor into ec_p1 with Z=1, set cm_seeded=1.
; Else: copy anchor into ec_p2 (affine), call ec_point_add, copy ec_p3->ec_p1.
; A in 0..3 (anchor index).
.cmp_accum_anchor:
        sta cm_anch_idx
        lda cm_seeded
        bne .cmp_acc_add
        ; Seed: ec_p1 = anchor (Z=1)
        lda cm_anch_idx
        jsr .cmp_load_anchor_p1
        lda #1
        sta cm_seeded
        rts
.cmp_acc_add:
        lda cm_anch_idx
        jsr .cmp_load_anchor_p2
        jsr ec_point_add
        ldy #95
.cmp_acc_cp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .cmp_acc_cp
        rts

; --- Load anchor[A] into ec_p1 (Jacobian, Z=1). A in 0..3. ---
.cmp_load_anchor_p1:
        asl
        tax
        lda .cmp_anchor_tbl,x
        sta zp_ptr1
        lda .cmp_anchor_tbl+1,x
        sta zp_ptr1+1
        ; Copy 32 X bytes from (zp_ptr1) to ec_p1
        ldy #31
.cmp_lap1_x:
        lda (zp_ptr1),y
        sta ec_p1,y
        dey
        bpl .cmp_lap1_x
        ; Advance pointer by 32 to Y coordinate
        lda zp_ptr1
        clc
        adc #32
        sta zp_ptr1
        bcc +
        inc zp_ptr1+1
+
        ldy #31
.cmp_lap1_y:
        lda (zp_ptr1),y
        sta ec_p1+32,y
        dey
        bpl .cmp_lap1_y
        ldy #31
        lda #0
.cmp_lap1_z:
        sta ec_p1+64,y
        dey
        bpl .cmp_lap1_z
        lda #1
        sta ec_p1+64
        rts

; --- Load anchor[A] into ec_p2 (affine X,Y; Z slot unused). A in 0..3. ---
.cmp_load_anchor_p2:
        asl
        tax
        lda .cmp_anchor_tbl,x
        sta zp_ptr1
        lda .cmp_anchor_tbl+1,x
        sta zp_ptr1+1
        ldy #31
.cmp_lap2_x:
        lda (zp_ptr1),y
        sta ec_p2,y
        dey
        bpl .cmp_lap2_x
        lda zp_ptr1
        clc
        adc #32
        sta zp_ptr1
        bcc +
        inc zp_ptr1+1
+
        ldy #31
.cmp_lap2_y:
        lda (zp_ptr1),y
        sta ec_p2+32,y
        dey
        bpl .cmp_lap2_y
        rts

; --- Anchor X-base address table (Y is anchor_x + 32, contiguous in data). ---
.cmp_anchor_tbl:
        !word ec_anchor1_x
        !word ec_anchor2_x
        !word ec_anchor3_x
        !word ec_anchor4_x
        ; --- Stash T[0] = G affine directly from curve generator ---
        ldy #31
.sm_t0x:
        lda ec_gx256,y
        sta ec_affine_x,y
        dey
        bpl .sm_t0x
        ldy #31
.sm_t0y:
        lda ec_gy256,y
        sta ec_affine_y,y
        dey
        bpl .sm_t0y
        lda #0
        jsr .sm_reu_stash_affine ; stash T[0] = G

        ; --- Compute 2G: set ec_p1 = G as Jacobian (Z=1), double into ec_p3,
        ;     then convert ec_p3 -> affine and save to ec_aff2g_256_{x,y}.
        ldy #31
.sm_g1x:
        lda ec_gx256,y
        sta ec_p1,y
        dey
        bpl .sm_g1x
        ldy #31
.sm_g1y:
        lda ec_gy256,y
        sta ec_p1+32,y
        dey
        bpl .sm_g1y
        ldy #31
        lda #0
.sm_g1z:
        sta ec_p1+64,y
        dey
        bpl .sm_g1z
        lda #1
        sta ec_p1+64             ; Z = 1 little-endian

        jsr ec_set_modp
        jsr ec_point_double      ; ec_p3 = 2G (Jacobian)
        jsr ec_jacobian_to_affine ; ec_affine_x/y = 2G affine

        ; Save 2G affine to persistent scratch (ec_affine_x/y is clobbered
        ; by every subsequent jacobian_to_affine).
        ldy #31
.sm_s2gx:
        lda ec_affine_x,y
        sta ec_aff2g_256_x,y
        dey
        bpl .sm_s2gx
        ldy #31
.sm_s2gy:
        lda ec_affine_y,y
        sta ec_aff2g_256_y,y
        dey
        bpl .sm_s2gy

        ; --- Set ec_p1 = G Jacobian (running accumulator = T[0] = G) ---
        ldy #31
.sm_a0x:
        lda ec_gx256,y
        sta ec_p1,y
        dey
        bpl .sm_a0x
        ldy #31
.sm_a0y:
        lda ec_gy256,y
        sta ec_p1+32,y
        dey
        bpl .sm_a0y
        ldy #31
        lda #0
.sm_a0z:
        sta ec_p1+64,y
        dey
        bpl .sm_a0z
        lda #1
        sta ec_p1+64

        ; --- T[j] = T[j-1] + 2G for j = 1..7 ---
        ; ec_p1 holds running Jacobian accumulator.
        ; ec_p2 holds 2G affine (reload each iter; ec_point_add may clobber).
        lda #1
        sta ec_sc_byte           ; precompute j counter

.sm_precomp:
        ; Load 2G affine into ec_p2
        ldy #31
.sm_ld2gx:
        lda ec_aff2g_256_x,y
        sta ec_p2,y
        dey
        bpl .sm_ld2gx
        ldy #31
.sm_ld2gy:
        lda ec_aff2g_256_y,y
        sta ec_p2+32,y
        dey
        bpl .sm_ld2gy

        ; ec_p3 = ec_p1 + ec_p2 = T[j-1] + 2G
        jsr ec_point_add

        ; Copy ec_p3 -> ec_p1 (new running Jacobian accumulator)
        ldy #95
.sm_cpj:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .sm_cpj

        ; Convert ec_p3 Jacobian to affine -> ec_affine_x, ec_affine_y
        jsr ec_jacobian_to_affine

        ; Stash affine to REU slot j
        lda ec_sc_byte
        jsr .sm_reu_stash_affine

        inc ec_sc_byte
        lda ec_sc_byte
        cmp #8
        bne .sm_precomp

        rts

; =============================================================================
; ec_scalar_mul: ec_p3 = k * G using a 4-way Lim-Lee fixed-base comb.
;
; k is a 32-byte scalar pointed to by (ec_scalar_ptr), BIG-ENDIAN byte order.
; The 256-bit scalar is split into K3||K2||K1||K0 (each 64 bits, K0 = least
; significant). The comb table T[1..15] in REU bank 2 offset $0000 holds
;     T[j] = ((j>>0)&1)*A1 + ((j>>1)&1)*A2 + ((j>>2)&1)*A3 + ((j>>3)&1)*A4
; where A_p = 2^(64*p) * G. Bit p of j corresponds to sub-scalar K_p.
;
; For each iteration b = 63 downto 0:
;   - double R
;   - idx = (bit_b(K3)<<3) | (bit_b(K2)<<2) | (bit_b(K1)<<1) | bit_b(K0)
;   - if idx != 0: R += T[idx] (mixed Jacobian + affine add)
; The first iteration in which idx != 0 seeds R = T[idx] directly (R was
; the point at infinity); we track this with cm_r_inf.
;
; Cost: 64 doublings + ~60 mixed adds (vs 256 doublings + ~51 adds for
; wNAF-5 baseline).
;
; Result in ec_p3 (Jacobian).
; REQUIRES: ec_precompute_256 must have been called first.
; =============================================================================
ec_scalar_mul:
        ; --- Transpose 32-byte BE scalar -> cm_k little-endian ---
        ; cm_k[i] = scalar[31 - i]; cm_k[0..7]=K0 (LSBs), cm_k[24..31]=K3 (MSBs).
        ldy #31                 ; BE source index
        ldx #0                  ; LE destination index
.cm_xpose:
        lda (ec_scalar_ptr),y
        sta cm_k,x
        inx
        dey
        bpl .cm_xpose

        ; --- Init state ---
        lda #7
        sta cm_byte_off         ; bit 63 lives in cm_k[7] for each K_p
        lda #$80
        sta cm_bit_mask         ; bit 7 = bit 63 of K_p
        lda #64
        sta cm_loop_ctr
        lda #1
        sta cm_r_inf            ; R starts at the point at infinity

        jsr ec_set_modp

.cm_loop:
        ; --- Double R (skip if R is still infinity) ---
        lda cm_r_inf
        bne .cm_skip_double
        jsr ec_point_double
        ldy #95
.cm_dcp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .cm_dcp
.cm_skip_double:

        ; --- Extract idx from current bit position ---
        lda #0
        sta cm_idx
        ldx cm_byte_off

        lda cm_k+24,x           ; K3
        and cm_bit_mask
        beq .cm_b3z
        lda #8
        ora cm_idx
        sta cm_idx
.cm_b3z:
        lda cm_k+16,x           ; K2
        and cm_bit_mask
        beq .cm_b2z
        lda #4
        ora cm_idx
        sta cm_idx
.cm_b2z:
        lda cm_k+8,x            ; K1
        and cm_bit_mask
        beq .cm_b1z
        lda #2
        ora cm_idx
        sta cm_idx
.cm_b1z:
        lda cm_k+0,x            ; K0
        and cm_bit_mask
        beq .cm_b0z
        lda #1
        ora cm_idx
        sta cm_idx
.cm_b0z:

        ; --- Advance bit position (next-lower bit) ---
        lsr cm_bit_mask
        bne .cm_after_advance
        lda #$80
        sta cm_bit_mask
        dec cm_byte_off
.cm_after_advance:

        ; --- If idx == 0, no addition this iteration ---
        lda cm_idx
        beq .cm_after_add

        ; --- Fetch T[idx] (affine) into ec_p2 ---
        lda cm_idx
        jsr .sm_reu_fetch_affine

        ; --- If R was infinity, seed R = T[idx] (Z=1) and clear flag ---
        lda cm_r_inf
        beq .cm_real_add
        ldy #31
.cm_seed_x:
        lda ec_p2,y
        sta ec_p1,y
        dey
        bpl .cm_seed_x
        ldy #31
.cm_seed_y:
        lda ec_p2+32,y
        sta ec_p1+32,y
        dey
        bpl .cm_seed_y
        ldy #31
        lda #0
.cm_seed_z:
        sta ec_p1+64,y
        dey
        bpl .cm_seed_z
        lda #1
        sta ec_p1+64
        lda #0
        sta cm_r_inf
        jmp .cm_after_add

.cm_real_add:
        jsr ec_point_add
        ldy #95
.cm_acp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .cm_acp

.cm_after_add:
        dec cm_loop_ctr
        beq .cm_done
        jmp .cm_loop

.cm_done:
        ; --- If R is still infinity, return all-zero point. ---
        lda cm_r_inf
        beq .cm_copy_out
        ldy #95
        lda #0
.cm_zinf:
        sta ec_p3,y
        dey
        bpl .cm_zinf
        rts

.cm_copy_out:
        ; --- Final result currently lives in ec_p1; copy to ec_p3. ---
        ldy #95
.cm_finc:
        lda ec_p1,y
        sta ec_p3,y
        dey
        bpl .cm_finc
        rts

; --- Comb scalar-mul state vars ---
cm_byte_off:    !byte 0
cm_bit_mask:    !byte 0
cm_loop_ctr:    !byte 0
cm_idx:         !byte 0
cm_r_inf:       !byte 0
cm_seeded:      !byte 0         ; precompute helper
cm_anch_idx:    !byte 0         ; precompute helper

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
.jta_czi:
        lda fp_r0,y
        sta ec_t1,y
        dey
        bpl .jta_czi

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
