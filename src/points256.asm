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
        jsr ec_mulp             ; t1 = Z1^2

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
        jsr ec_mulp             ; t3 = Y1^2

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
        jsr ec_mulp             ; t4 = M^2

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
        jsr ec_mulp             ; t4 = Y1^4

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
        jsr ec_mulp             ; t1 = Z1^2

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
        jsr ec_mulp             ; t3 = H^2

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
        jsr ec_mulp             ; t3 = R^2

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
; ec_precompute_256: Build T[0..15] = i*G as affine, stash to REU bank 2.
; Called once at init. T[0] is never fetched (nibble=0 skips addition).
; REU layout: bank 2 offset $0000, 16 slots * 64 bytes = 1024 bytes.
; Also uses bank 2 offset $0800 for temporary Jacobian storage during build.
; =============================================================================
ec_precompute_256:
        ; T[1] = G (already affine). Store Gx,Gy directly.
        ldy #31
.sm_t1x:
        lda ec_gx256,y
        sta ec_affine_x,y
        dey
        bpl .sm_t1x
        ldy #31
.sm_t1y:
        lda ec_gy256,y
        sta ec_affine_y,y
        dey
        bpl .sm_t1y
        lda #1
        jsr .sm_reu_stash_affine ; stash T[1] affine

        ; Also store T[1] as Jacobian (Z=1) in temp area for precompute chain
        ldy #31
.sm_t1jx:
        lda ec_gx256,y
        sta ec_p3,y
        dey
        bpl .sm_t1jx
        ldy #31
.sm_t1jy:
        lda ec_gy256,y
        sta ec_p3+32,y
        dey
        bpl .sm_t1jy
        ldy #31
        lda #0
.sm_t1jz:
        sta ec_p3+64,y
        dey
        bpl .sm_t1jz
        lda #1
        sta ec_p3+64
        lda #1
        jsr .sm_reu_stash_jac   ; stash T[1] Jacobian to temp area

        ; Load G into ec_p2 (affine, stays constant for all precompute adds)
        ldy #31
.sm_lg2x:
        lda ec_gx256,y
        sta ec_p2,y
        dey
        bpl .sm_lg2x
        ldy #31
.sm_lg2y:
        lda ec_gy256,y
        sta ec_p2+32,y
        dey
        bpl .sm_lg2y

        ; Set modular arithmetic to use P-256 prime
        jsr ec_set_modp

        ; T[i] = T[i-1] + G for i = 2..15
        ; For each: fetch T[i-1] Jacobian -> ec_p1, add G -> ec_p3,
        ; convert ec_p3 to affine, stash affine to REU, stash Jacobian too.
        lda #2
        sta ec_sc_byte          ; precompute counter

.sm_precomp:
        ; Fetch T[i-1] Jacobian from REU temp area into ec_p1
        lda ec_sc_byte
        sec
        sbc #1
        jsr .sm_reu_fetch_jac   ; ec_p1 = T[i-1] Jacobian

        ; ec_p3 = ec_p1 + ec_p2 (T[i-1] + G)
        jsr ec_point_add

        ; Stash Jacobian ec_p3 to temp area for next iteration
        lda ec_sc_byte
        jsr .sm_reu_stash_jac

        ; Convert ec_p3 Jacobian to affine -> ec_affine_x, ec_affine_y
        jsr ec_jacobian_to_affine

        ; Stash affine point to REU
        lda ec_sc_byte
        jsr .sm_reu_stash_affine

        ; Re-load G into ec_p2 (ec_point_add/ec_jacobian_to_affine may clobber)
        ldy #31
.sm_rlgx:
        lda ec_gx256,y
        sta ec_p2,y
        dey
        bpl .sm_rlgx
        ldy #31
.sm_rlgy:
        lda ec_gy256,y
        sta ec_p2+32,y
        dey
        bpl .sm_rlgy

        inc ec_sc_byte
        lda ec_sc_byte
        cmp #16
        bne .sm_precomp

        rts

; =============================================================================
; ec_scalar_mul: ec_p3 = k * G
; k is a 32-byte scalar pointed to by (ec_scalar_ptr), BIG-ENDIAN byte order.
; Uses 4-bit windowed method with precomputed table T[0..15] in REU bank 2.
; Each T[i] = i*G stored as 64-byte AFFINE point (X,Y).
; T[0] is never fetched (nibble=0 skips addition).
; Result in ec_p3 (Jacobian).
; REQUIRES: ec_precompute_256 must have been called first.
; =============================================================================
ec_scalar_mul:
        ; =====================================================================
        ; Windowed scalar multiply - process 64 nibbles MSB first
        ; =====================================================================

        ; Find first nonzero nibble (skip leading zeros)
        lda #0
        sta ec_sc_byte          ; nibble index (0..63)

.sm_find_nz:
        jsr .sm_get_nibble      ; A = current nibble value
        bne .sm_found_nz
        inc ec_sc_byte
        lda ec_sc_byte
        cmp #64
        bne .sm_find_nz

        ; All nibbles zero -> result is infinity
        ldy #95
        lda #0
.sm_zinf:
        sta ec_p3,y
        dey
        bpl .sm_zinf
        rts

.sm_found_nz:
        ; A = first nonzero nibble value (1..15)
        ; Initialize R = T[A] as Jacobian in ec_p1
        ; T[A] is stored as affine. Load into ec_p1 with Z=1.
        sta .sm_nibble_val

        ; Fetch affine T[A] into ec_p2 (we'll copy to ec_p1)
        lda .sm_nibble_val
        jsr .sm_reu_fetch_affine ; ec_p2 = T[A] affine (X,Y)

        ; Copy affine to ec_p1 as Jacobian (Z=1)
        ldy #31
.sm_init_x:
        lda ec_p2,y
        sta ec_p1,y
        dey
        bpl .sm_init_x
        ldy #31
.sm_init_y:
        lda ec_p2+32,y
        sta ec_p1+32,y
        dey
        bpl .sm_init_y
        ldy #31
        lda #0
.sm_init_z:
        sta ec_p1+64,y
        dey
        bpl .sm_init_z
        lda #1
        sta ec_p1+64            ; Z = 1 (little-endian)

        ; Process remaining nibbles
        inc ec_sc_byte

.sm_nib_loop:
        lda ec_sc_byte
        cmp #64
        beq .sm_nib_done

        ; Double R four times: R = 2^4 * R
        jsr ec_point_double     ; ec_p3 = 2*ec_p1
        ldy #95
.sm_d1:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .sm_d1

        jsr ec_point_double
        ldy #95
.sm_d2:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .sm_d2

        jsr ec_point_double
        ldy #95
.sm_d3:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .sm_d3

        jsr ec_point_double
        ldy #95
.sm_d4:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .sm_d4

        ; Extract current nibble
        jsr .sm_get_nibble      ; A = nibble value
        beq .sm_nib_skip        ; nibble == 0, skip add

        ; Fetch T[nibble] affine into ec_p2
        jsr .sm_reu_fetch_affine

        ; ec_p3 = ec_p1 + ec_p2 (R + T[nibble])
        jsr ec_point_add

        ; Copy ec_p3 -> ec_p1
        ldy #95
.sm_nib_cp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .sm_nib_cp

.sm_nib_skip:
        inc ec_sc_byte
        jmp .sm_nib_loop

.sm_nib_done:
        ; Result is in ec_p1; copy to ec_p3
        ldy #95
.sm_cfin:
        lda ec_p1,y
        sta ec_p3,y
        dey
        bpl .sm_cfin
        rts

; --- Extract nibble at index ec_sc_byte from scalar ---
; Scalar is big-endian at (ec_scalar_ptr).
; Nibble 2j = high nibble of byte j, nibble 2j+1 = low nibble.
; Returns nibble value in A (0..15). Preserves ec_sc_byte.
.sm_get_nibble:
        lda ec_sc_byte
        lsr                     ; byte index = nibble/2
        tay
        lda ec_sc_byte
        and #1
        bne .sm_gn_lo
        ; High nibble (even nibble index)
        lda (ec_scalar_ptr),y
        lsr
        lsr
        lsr
        lsr
        rts
.sm_gn_lo:
        ; Low nibble (odd nibble index)
        lda (ec_scalar_ptr),y
        and #$0F
        rts

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
