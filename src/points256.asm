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
; Uses double-and-add with the base point G (affine).
; Result in ec_p3 (Jacobian).
; =============================================================================
ec_scalar_mul:
        ; Initialize ec_p1 = point at infinity (Z=0)
        ldy #95
        lda #0
.sm_clr:
        sta ec_p1,y
        dey
        bpl .sm_clr

        ; Load G into ec_p2 (affine)
        ldy #31
.sm_cgx:
        lda ec_gx256,y
        sta ec_p2,y
        dey
        bpl .sm_cgx
        ldy #31
.sm_cgy:
        lda ec_gy256,y
        sta ec_p2+32,y
        dey
        bpl .sm_cgy

        ; Process 256 bits of k, MSB first (big-endian byte order)
        lda #0
        sta ec_sc_byte          ; byte index 0..31
        lda #$80
        sta ec_sc_mask          ; bit mask (MSB first)

.sm_bitloop:
        ; Double: ec_p1 = 2*ec_p1 (via ec_p3)
        jsr ec_point_double     ; ec_p3 = 2*ec_p1
        ; Copy ec_p3 -> ec_p1
        ldy #95
.sm_cp1:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .sm_cp1

        ; Test bit of k
        ldy ec_sc_byte
        lda (ec_scalar_ptr),y
        and ec_sc_mask
        beq .sm_nobit

        ; Add: ec_p1 = ec_p1 + ec_p2 (via ec_p3)
        jsr ec_point_add        ; ec_p3 = ec_p1 + G
        ; Copy ec_p3 -> ec_p1
        ldy #95
.sm_cp2:
        lda ec_p3,y
        sta ec_p1,y
        dey
        bpl .sm_cp2

.sm_nobit:
        ; Advance to next bit
        lsr ec_sc_mask
        bne .sm_bitloop
        ; Next byte
        lda #$80
        sta ec_sc_mask
        inc ec_sc_byte
        lda ec_sc_byte
        cmp #32
        beq .sm_done
        jmp .sm_bitloop

.sm_done:
        ; Result is in ec_p1; copy to ec_p3
        ldy #95
.sm_cfin:
        lda ec_p1,y
        sta ec_p3,y
        dey
        bpl .sm_cfin
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
