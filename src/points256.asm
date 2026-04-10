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
; ec_precompute_256: Build wNAF-5 table T[0..7] of odd multiples of G.
;   T[j] = (2j+1)*G for j in 0..7, i.e. { G, 3G, 5G, 7G, 9G, 11G, 13G, 15G }.
; Stored as 64-byte AFFINE (X,Y) entries in REU bank 2 offset $0000.
; Also precomputes affine 2G into ec_aff2g_256_{x,y} (not stashed to REU).
; Called once at init.
; =============================================================================
ec_precompute_256:
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
; ec_scalar_mul: ec_p3 = k * G using width-5 wNAF with table T[0..7].
; k is a 32-byte scalar pointed to by (ec_scalar_ptr), BIG-ENDIAN byte order.
; Table T[j] = (2j+1)*G for j=0..7, stored as 64-byte affine (X,Y) in REU
; bank 2 offset $0000. Result in ec_p3 (Jacobian).
; REQUIRES: ec_precompute_256 must have been called first.
; =============================================================================
ec_scalar_mul:
        ; Recode scalar into signed wNAF-5 digits (ec_naf_digits / ec_naf_len).
        lda #32                 ; P-256 scalar length in bytes
        jsr ec_naf_recode

        ; If length == 0 -> result is infinity.
        lda ec_naf_len
        ora ec_naf_len+1
        bne .smn_have_digits
        ldy #95
        lda #0
.smn_zinf:
        sta ec_p3,y
        dey
        bpl .smn_zinf
        rts

.smn_have_digits:
        jsr ec_set_modp

        ; Index = len - 1 (points at most significant digit).
        ; Digits fit in <= 257 for P-256 so we need a 16-bit cursor.
        lda ec_naf_len
        sec
        sbc #1
        sta .smn_idx_lo
        lda ec_naf_len+1
        sbc #0
        sta .smn_idx_hi

        ; --- Load most significant digit. It is guaranteed nonzero ---
        ; (the recoder loop stops as soon as k==0, so the last emitted
        ;  digit is always from the final odd-residue step).
        jsr .smn_load_digit_to_p1 ; set ec_p1 = digit * G (Jacobian, Z=1)

.smn_main_loop:
        ; Move to next (lower) digit. If idx == 0, we're done with the top
        ; digit already; check by examining lo/hi before decrementing.
        lda .smn_idx_lo
        ora .smn_idx_hi
        bne .smn_decr
        jmp .smn_done
.smn_decr:
        lda .smn_idx_lo
        bne .smn_dec_lo
        dec .smn_idx_hi
.smn_dec_lo:
        dec .smn_idx_lo

        ; --- Double R once (R = 2*ec_p1, result in ec_p3, copy back) ---
        jsr ec_point_double
        ldy #95
.smn_dcp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .smn_dcp

        ; --- Fetch current digit; if zero, skip add ---
        jsr .smn_get_digit      ; A = signed digit byte
        beq .smn_main_loop

        ; Nonzero digit: load |d| entry into ec_p2; negate Y in place if d<0.
        sta .smn_dig_tmp
        bmi .smn_neg
        ; Positive: table index = (d - 1) / 2
        lsr                     ; clears bit0 (d is odd), shifts divide
        jsr .sm_reu_fetch_affine ; ec_p2 = T[idx]
        jmp .smn_do_add
.smn_neg:
        ; Negative: fetch T[(|d| - 1) / 2] = T[(-d - 1)/2], then negate Y.
        lda #0
        sec
        sbc .smn_dig_tmp        ; A = -d = |d| (d is in -15..-1)
        lsr                     ; A = (|d|-1)/2  (|d| is odd)
        jsr .sm_reu_fetch_affine
        ; Negate Y: ec_p2+32 = p256 - ec_p2+32
        lda #<ec_p256
        sta fp_src1
        lda #>ec_p256
        sta fp_src1+1
        lda #<(ec_p2+32)
        sta fp_src2
        lda #>(ec_p2+32)
        sta fp_src2+1
        lda #<(ec_p2+32)
        sta fp_dst
        lda #>(ec_p2+32)
        sta fp_dst+1
        jsr fp_mod_sub          ; ec_p2+32 = p - ec_p2+32

.smn_do_add:
        jsr ec_point_add        ; ec_p3 = ec_p1 + ec_p2
        ldy #95
.smn_acp:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .smn_acp
        jmp .smn_main_loop

.smn_done:
        ldy #95
.smn_cfin:
        lda ec_p1,y
        sta ec_p3,y
        dey
        bpl .smn_cfin
        rts

; --- Load T[|d|/2] into ec_p1 as Jacobian (Z=1), negating Y if d<0 ---
; Input: current digit at ec_naf_digits[.smn_idx_lo/hi] is the leading
;        nonzero digit (odd, -15..15).
.smn_load_digit_to_p1:
        jsr .smn_get_digit      ; A = signed digit
        sta .smn_dig_tmp
        bmi .smn_ldn
        lsr
        jsr .sm_reu_fetch_affine ; ec_p2 = T[idx]
        jmp .smn_ldcopy
.smn_ldn:
        lda #0
        sec
        sbc .smn_dig_tmp
        lsr
        jsr .sm_reu_fetch_affine
        ; Negate Y in ec_p2
        lda #<ec_p256
        sta fp_src1
        lda #>ec_p256
        sta fp_src1+1
        lda #<(ec_p2+32)
        sta fp_src2
        lda #>(ec_p2+32)
        sta fp_src2+1
        lda #<(ec_p2+32)
        sta fp_dst
        lda #>(ec_p2+32)
        sta fp_dst+1
        jsr fp_mod_sub
.smn_ldcopy:
        ; Copy ec_p2 (affine X,Y) to ec_p1 with Z=1
        ldy #31
.smn_lx:
        lda ec_p2,y
        sta ec_p1,y
        dey
        bpl .smn_lx
        ldy #31
.smn_ly:
        lda ec_p2+32,y
        sta ec_p1+32,y
        dey
        bpl .smn_ly
        ldy #31
        lda #0
.smn_lz:
        sta ec_p1+64,y
        dey
        bpl .smn_lz
        lda #1
        sta ec_p1+64
        rts

; --- Fetch signed digit at index .smn_idx_{lo,hi} into A ---
.smn_get_digit:
        lda .smn_idx_lo
        clc
        adc #<ec_naf_digits
        sta zp_ptr1
        lda .smn_idx_hi
        adc #>ec_naf_digits
        sta zp_ptr1+1
        ldy #0
        lda (zp_ptr1),y
        rts

.smn_idx_lo:    !byte 0
.smn_idx_hi:    !byte 0
.smn_dig_tmp:   !byte 0

; =============================================================================
; ec_naf_recode: Recode (ec_scalar_ptr) big-endian scalar into width-5 wNAF.
; Input:   A = scalar length in bytes (32 for P-256, 48 for P-384)
;          (ec_scalar_ptr) -> scalar (BE)
; Output:  ec_naf_k, ec_naf_digits, ec_naf_len populated.
;
; Algorithm:
;   while k != 0:
;     if k & 1:
;       d = k mod 32  (low 5 bits, 0..31)
;       if d >= 16: d -= 32         -> now d in {-15,-13,...,-1}
;       k -= d (signed)
;     else: d = 0
;     emit d; shift k right by 1
;
; Working buffer ec_naf_k is (length+1) bytes little-endian with one byte
; of headroom for a carry produced when adding (32-d) for a negative d.
; =============================================================================
ec_naf_recode:
        sta .nr_nkb             ; key length (32 or 48)
        ; Copy BE scalar -> ec_naf_k little-endian.
        ; For i in 0..nkb-1: ec_naf_k[i] = scalar[nkb-1-i]
        ; We use Y as the BE source index counting DOWN from nkb-1 to 0,
        ; and .nr_dsti as the LE destination index counting UP.
        lda #0
        sta .nr_dsti
        ldy .nr_nkb
        dey                     ; Y = nkb - 1
.nr_copy:
        lda (ec_scalar_ptr),y
        sty .nr_ysave
        ldy .nr_dsti
        sta ec_naf_k,y
        inc .nr_dsti
        ldy .nr_ysave
        dey
        bpl .nr_copy
        ; Zero the headroom byte at ec_naf_k[nkb]
        ldy .nr_nkb
        lda #0
        sta ec_naf_k,y

        ; Zero output length
        lda #0
        sta ec_naf_len
        sta ec_naf_len+1

        ; nkbhr = nkb + 1 (bytes to scan/shift)
        lda .nr_nkb
        clc
        adc #1
        sta .nr_nkbhr

.nr_main:
        ; k == 0?  scan ec_naf_k[0..nkbhr-1]
        ldy .nr_nkbhr
        dey
.nr_scan:
        lda ec_naf_k,y
        bne .nr_nonzero
        dey
        bpl .nr_scan
        ; k is zero -> done
        rts

.nr_nonzero:
        ; Check bit 0 of k (i.e. ec_naf_k[0])
        lda ec_naf_k
        and #1
        bne .nr_odd
        jmp .nr_emit_zero
.nr_odd:
        ; Odd. d = ec_naf_k[0] & 0x1F
        lda ec_naf_k
        and #$1F
        sta .nr_dig
        cmp #16
        bcc .nr_pos_sub         ; d < 16 -> positive

        ; d >= 16: effective signed digit = d - 32 (negative). To clear the
        ; low 5 bits of k we add (32 - d) to k (unsigned ripple carry).
        lda #32
        sec
        sbc .nr_dig             ; A = 32 - d  (1..16)
        sta .nr_addv
        ldy #0
        clc
        lda ec_naf_k
        adc .nr_addv
        sta ec_naf_k
.nr_add_rip:
        bcc .nr_add_done
        iny
        cpy .nr_nkbhr
        beq .nr_add_done
        lda ec_naf_k,y
        adc #0
        sta ec_naf_k,y
        jmp .nr_add_rip
.nr_add_done:
        ; Store signed digit = d - 32 (as byte, two's complement negative)
        lda .nr_dig
        sec
        sbc #32
        jmp .nr_store_digit

.nr_pos_sub:
        ; d < 16: subtract d from k (unsigned ripple borrow).
        ldy #0
        lda ec_naf_k
        sec
        sbc .nr_dig
        sta ec_naf_k
.nr_sub_rip:
        bcs .nr_sub_done
        iny
        cpy .nr_nkbhr
        beq .nr_sub_done
        lda ec_naf_k,y
        sbc #0
        sta ec_naf_k,y
        jmp .nr_sub_rip
.nr_sub_done:
        lda .nr_dig             ; positive digit

.nr_store_digit:
        ; Store A at ec_naf_digits[ec_naf_len], then len++ and shift k right.
        ldy ec_naf_len+1
        beq .nr_store_lo
        ; high page: use base + $0100
        sta .nr_sd_ptr_lo
        lda ec_naf_len
        tay
        lda .nr_sd_ptr_lo
        sta ec_naf_digits+$100,y
        jmp .nr_after_store
.nr_store_lo:
        ldy ec_naf_len
        sta ec_naf_digits,y
.nr_after_store:
        inc ec_naf_len
        bne .nr_shift
        inc ec_naf_len+1

.nr_shift:
        ; k >>= 1 (nkbhr-byte LE right shift)
        ldy .nr_nkbhr
        dey
        clc
.nr_sh_loop:
        lda ec_naf_k,y
        ror
        sta ec_naf_k,y
        dey
        bpl .nr_sh_loop
        jmp .nr_main

.nr_emit_zero:
        lda #0
        jmp .nr_store_digit

.nr_nkb:        !byte 0
.nr_nkbhr:      !byte 0
.nr_dsti:       !byte 0
.nr_ysave:      !byte 0
.nr_dig:        !byte 0
.nr_addv:       !byte 0
.nr_sd_ptr_lo:  !byte 0

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
