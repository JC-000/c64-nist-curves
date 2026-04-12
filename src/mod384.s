.setcpu "6502"

; =============================================================================
; mod384.s - Modular operations for P-384, including Solinas fast reduction
;
; All field elements stored LITTLE-ENDIAN: byte 0 = LSB, byte 47 = MSB.
; =============================================================================

; --- Imports: ZP ---
.importzp fp_src1, fp_src2, fp_dst, fp_misc, fp_carry

; --- Imports: fp384 ---
.import fp_add_384, fp_sub_384, fp_cmp_384, fp_copy_384, fp_zero_384
.import fp_mul_384, fp_sqr_384, fp_is_zero_384, fp_rshift1_384

; --- Imports: data ---
.import fp384_wide, fp384_r0
.import fp384_inv_u, fp384_inv_v, fp384_inv_x1, fp384_inv_x2

; --- Exports ---
.export ec_p384, ec_n384
.export fp_mod_add_384, fp_mod_sub_384, fp_mod_reduce384
.export fp_mod_mul_384, fp_mod_sqr_384, fp_mod_inv_384, fp_chk_one_384
.export ec_set_modp_384, ec_set_modn_384, ec_mulp_384, ec_sqrp_384

.segment "CODE"

; =============================================================================
; P-384 prime and group order constants (little-endian)
; =============================================================================

; P-384 prime: p = 2^384 - 2^128 - 2^96 + 2^32 - 1
ec_p384:
        .byte $FF,$FF,$FF,$FF,$00,$00,$00,$00  ; bytes 0-7   (w0=FFFFFFFF, w1=00000000)
        .byte $00,$00,$00,$00,$FF,$FF,$FF,$FF  ; bytes 8-15  (w2=00000000, w3=FFFFFFFF)
        .byte $FE,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 16-23 (w4=FFFFFFFE, w5=FFFFFFFF)
        .byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 24-31 (w6=FFFFFFFF, w7=FFFFFFFF)
        .byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 32-39 (w8=FFFFFFFF, w9=FFFFFFFF)
        .byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 40-47 (w10=FFFFFFFF, w11=FFFFFFFF)

; P-384 group order n (little-endian, verified in Python)
ec_n384:
        .byte $73,$29,$C5,$CC,$6A,$19,$EC,$EC  ; bytes 0-7
        .byte $7A,$A7,$B0,$48,$B2,$0D,$1A,$58  ; bytes 8-15
        .byte $DF,$2D,$37,$F4,$81,$4D,$63,$C7  ; bytes 16-23
        .byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 24-31
        .byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 32-39
        .byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 40-47

; =============================================================================
; fp_mod_add_384 - (fp_dst) = ((fp_src1) + (fp_src2)) mod (fp_misc)
; =============================================================================
fp_mod_add_384:
        jsr fp_add_384
        lda fp_carry
        bne @reduce

        ; Compare dst with modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_cmp_384
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
        bcc @done

@reduce:
        ; dst -= modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_sub_384
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
@done:
        rts

; =============================================================================
; fp_mod_sub_384 - (fp_dst) = ((fp_src1) - (fp_src2)) mod (fp_misc)
; =============================================================================
fp_mod_sub_384:
        jsr fp_sub_384
        lda fp_carry
        beq @done

        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_add_384
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
@done:
        rts

; =============================================================================
; fp_mod_reduce384 - Solinas fast reduction for P-384
;
; Reduces 768-bit fp384_wide mod P-384 prime -> fp384_r0 (48 bytes, LE)
;
; P-384 prime: p = 2^384 - 2^128 - 2^96 + 2^32 - 1
; =============================================================================

; Optimized accumulator model:
;   A = low byte of running signed 16-bit sum
;   Y = high byte of running signed 16-bit sum
;   X = current output byte index (0..47), preserved across dispatch.

.macro sol384_add_byte off
        .local skip
        clc
        adc fp384_wide + off
        bcc skip
        iny
skip:
.endmacro

; Add 2*fp384_wide[off] - implemented as two chained add_byte's
.macro sol384_add2_byte off
        .local skip1
        .local skip2
        clc
        adc fp384_wide + off
        bcc skip1
        iny
skip1:  clc
        adc fp384_wide + off
        bcc skip2
        iny
skip2:
.endmacro

.macro sol384_sub_byte off
        .local skip
        sec
        sbc fp384_wide + off
        bcs skip
        dey
skip:
.endmacro

fp_mod_reduce384:
        ; A = running lo accumulator (carry from previous byte), Y = hi.
        ; Start at zero.
        lda #0
        tay
        ldx #0                          ; byte index

sol384_byte_loop:
        ; Add s1[x] = fp384_wide[x] (always present).
        clc
        adc fp384_wide,x
        bcc sol384_s1_done
        iny
sol384_s1_done:
        ; Dispatch to per-byte contribution routine via self-modifying JMP.
        sta sol384_lo_save              ; 4
        lda sol384_jmp_tbl_lo,x         ; 4
        sta sol384_dispatch+1           ; 4
        lda sol384_jmp_tbl_hi,x         ; 4
        sta sol384_dispatch+2           ; 4
        lda sol384_lo_save              ; 4  (A restored, X and Y untouched)
sol384_dispatch:
        jmp sol384_b0                   ; 3, operand rewritten above

        ; All per-byte routines jump back here.
sol384_after_contrib:
        sta fp384_r0,x                  ; store output byte
        tya                             ; A = old hi, sets N flag from old Y
        bpl sol384_pos                  ; branch BEFORE clobbering flags
        ldy #$ff                        ; negative: sign-extend high to $ff
        jmp sol384_cont
sol384_pos:
        ldy #$00                        ; non-negative: high = 0
sol384_cont:
        inx
        cpx #48
        bcs @byte_done
        jmp sol384_byte_loop

@byte_done:
        sta sol384_overflow
        sty sol384_overflow+1

@reduce_loop:
        lda sol384_overflow+1
        bmi @add_p

        ora sol384_overflow
        bne @sub_p

        ldy #47
@cmp_loop:
        lda fp384_r0,y
        cmp ec_p384,y
        bcc @reduction_done
        bne @sub_p
        dey
        bpl @cmp_loop

@sub_p:
        sec
        ldy #0
        ldx #48
@sub_p_loop:
        lda fp384_r0,y
        sbc ec_p384,y
        sta fp384_r0,y
        iny
        dex
        bne @sub_p_loop
        lda sol384_overflow
        sbc #0
        sta sol384_overflow
        lda sol384_overflow+1
        sbc #0
        sta sol384_overflow+1
        jmp @reduce_loop

@add_p:
        clc
        ldy #0
        ldx #48
@add_p_loop:
        lda fp384_r0,y
        adc ec_p384,y
        sta fp384_r0,y
        iny
        dex
        bne @add_p_loop
        lda sol384_overflow
        adc #0
        sta sol384_overflow
        lda sol384_overflow+1
        adc #0
        sta sol384_overflow+1
        jmp @reduce_loop

@reduction_done:
        rts

; Parallel lo/hi tables for self-modifying dispatch JMP.
sol384_jmp_tbl_lo:
        .byte <sol384_b0,  <sol384_b1,  <sol384_b2,  <sol384_b3
        .byte <sol384_b4,  <sol384_b5,  <sol384_b6,  <sol384_b7
        .byte <sol384_b8,  <sol384_b9,  <sol384_b10, <sol384_b11
        .byte <sol384_b12, <sol384_b13, <sol384_b14, <sol384_b15
        .byte <sol384_b16, <sol384_b17, <sol384_b18, <sol384_b19
        .byte <sol384_b20, <sol384_b21, <sol384_b22, <sol384_b23
        .byte <sol384_b24, <sol384_b25, <sol384_b26, <sol384_b27
        .byte <sol384_b28, <sol384_b29, <sol384_b30, <sol384_b31
        .byte <sol384_b32, <sol384_b33, <sol384_b34, <sol384_b35
        .byte <sol384_b36, <sol384_b37, <sol384_b38, <sol384_b39
        .byte <sol384_b40, <sol384_b41, <sol384_b42, <sol384_b43
        .byte <sol384_b44, <sol384_b45, <sol384_b46, <sol384_b47

sol384_jmp_tbl_hi:
        .byte >sol384_b0,  >sol384_b1,  >sol384_b2,  >sol384_b3
        .byte >sol384_b4,  >sol384_b5,  >sol384_b6,  >sol384_b7
        .byte >sol384_b8,  >sol384_b9,  >sol384_b10, >sol384_b11
        .byte >sol384_b12, >sol384_b13, >sol384_b14, >sol384_b15
        .byte >sol384_b16, >sol384_b17, >sol384_b18, >sol384_b19
        .byte >sol384_b20, >sol384_b21, >sol384_b22, >sol384_b23
        .byte >sol384_b24, >sol384_b25, >sol384_b26, >sol384_b27
        .byte >sol384_b28, >sol384_b29, >sol384_b30, >sol384_b31
        .byte >sol384_b32, >sol384_b33, >sol384_b34, >sol384_b35
        .byte >sol384_b36, >sol384_b37, >sol384_b38, >sol384_b39
        .byte >sol384_b40, >sol384_b41, >sol384_b42, >sol384_b43
        .byte >sol384_b44, >sol384_b45, >sol384_b46, >sol384_b47

sol384_b0:
        sol384_add_byte 48
        sol384_add_byte 80
        sol384_add_byte 84
        sol384_sub_byte 92
        jmp sol384_after_contrib

sol384_b1:
        sol384_add_byte 49
        sol384_add_byte 81
        sol384_add_byte 85
        sol384_sub_byte 93
        jmp sol384_after_contrib

sol384_b2:
        sol384_add_byte 50
        sol384_add_byte 82
        sol384_add_byte 86
        sol384_sub_byte 94
        jmp sol384_after_contrib

sol384_b3:
        sol384_add_byte 51
        sol384_add_byte 83
        sol384_add_byte 87
        sol384_sub_byte 95
        jmp sol384_after_contrib

sol384_b4:
        sol384_sub_byte 48
        sol384_add_byte 52
        sol384_sub_byte 80
        sol384_add_byte 88
        sol384_add_byte 92
        jmp sol384_after_contrib

sol384_b5:
        sol384_sub_byte 49
        sol384_add_byte 53
        sol384_sub_byte 81
        sol384_add_byte 89
        sol384_add_byte 93
        jmp sol384_after_contrib

sol384_b6:
        sol384_sub_byte 50
        sol384_add_byte 54
        sol384_sub_byte 82
        sol384_add_byte 90
        sol384_add_byte 94
        jmp sol384_after_contrib

sol384_b7:
        sol384_sub_byte 51
        sol384_add_byte 55
        sol384_sub_byte 83
        sol384_add_byte 91
        sol384_add_byte 95
        jmp sol384_after_contrib

sol384_b8:
        sol384_sub_byte 52
        sol384_add_byte 56
        sol384_sub_byte 84
        sol384_add_byte 92
        jmp sol384_after_contrib

sol384_b9:
        sol384_sub_byte 53
        sol384_add_byte 57
        sol384_sub_byte 85
        sol384_add_byte 93
        jmp sol384_after_contrib

sol384_b10:
        sol384_sub_byte 54
        sol384_add_byte 58
        sol384_sub_byte 86
        sol384_add_byte 94
        jmp sol384_after_contrib

sol384_b11:
        sol384_sub_byte 55
        sol384_add_byte 59
        sol384_sub_byte 87
        sol384_add_byte 95
        jmp sol384_after_contrib

sol384_b12:
        sol384_add_byte 48
        sol384_sub_byte 56
        sol384_add_byte 60
        sol384_add_byte 80
        sol384_add_byte 84
        sol384_sub_byte 88
        sol384_sub_byte 92
        jmp sol384_after_contrib

sol384_b13:
        sol384_add_byte 49
        sol384_sub_byte 57
        sol384_add_byte 61
        sol384_add_byte 81
        sol384_add_byte 85
        sol384_sub_byte 89
        sol384_sub_byte 93
        jmp sol384_after_contrib

sol384_b14:
        sol384_add_byte 50
        sol384_sub_byte 58
        sol384_add_byte 62
        sol384_add_byte 82
        sol384_add_byte 86
        sol384_sub_byte 90
        sol384_sub_byte 94
        jmp sol384_after_contrib

sol384_b15:
        sol384_add_byte 51
        sol384_sub_byte 59
        sol384_add_byte 63
        sol384_add_byte 83
        sol384_add_byte 87
        sol384_sub_byte 91
        sol384_sub_byte 95
        jmp sol384_after_contrib

sol384_b16:
        sol384_add_byte 48
        sol384_add_byte 52
        sol384_sub_byte 60
        sol384_add_byte 64
        sol384_add_byte 80
        sol384_add2_byte 84
        sol384_add_byte 88
        sol384_sub_byte 92
        sol384_sub_byte 92
        jmp sol384_after_contrib

sol384_b17:
        sol384_add_byte 49
        sol384_add_byte 53
        sol384_sub_byte 61
        sol384_add_byte 65
        sol384_add_byte 81
        sol384_add2_byte 85
        sol384_add_byte 89
        sol384_sub_byte 93
        sol384_sub_byte 93
        jmp sol384_after_contrib

sol384_b18:
        sol384_add_byte 50
        sol384_add_byte 54
        sol384_sub_byte 62
        sol384_add_byte 66
        sol384_add_byte 82
        sol384_add2_byte 86
        sol384_add_byte 90
        sol384_sub_byte 94
        sol384_sub_byte 94
        jmp sol384_after_contrib

sol384_b19:
        sol384_add_byte 51
        sol384_add_byte 55
        sol384_sub_byte 63
        sol384_add_byte 67
        sol384_add_byte 83
        sol384_add2_byte 87
        sol384_add_byte 91
        sol384_sub_byte 95
        sol384_sub_byte 95
        jmp sol384_after_contrib

sol384_b20:
        sol384_add_byte 52
        sol384_add_byte 56
        sol384_sub_byte 64
        sol384_add_byte 68
        sol384_add_byte 84
        sol384_add2_byte 88
        sol384_add_byte 92
        jmp sol384_after_contrib

sol384_b21:
        sol384_add_byte 53
        sol384_add_byte 57
        sol384_sub_byte 65
        sol384_add_byte 69
        sol384_add_byte 85
        sol384_add2_byte 89
        sol384_add_byte 93
        jmp sol384_after_contrib

sol384_b22:
        sol384_add_byte 54
        sol384_add_byte 58
        sol384_sub_byte 66
        sol384_add_byte 70
        sol384_add_byte 86
        sol384_add2_byte 90
        sol384_add_byte 94
        jmp sol384_after_contrib

sol384_b23:
        sol384_add_byte 55
        sol384_add_byte 59
        sol384_sub_byte 67
        sol384_add_byte 71
        sol384_add_byte 87
        sol384_add2_byte 91
        sol384_add_byte 95
        jmp sol384_after_contrib

sol384_b24:
        sol384_add_byte 56
        sol384_add_byte 60
        sol384_sub_byte 68
        sol384_add_byte 72
        sol384_add_byte 88
        sol384_add2_byte 92
        jmp sol384_after_contrib

sol384_b25:
        sol384_add_byte 57
        sol384_add_byte 61
        sol384_sub_byte 69
        sol384_add_byte 73
        sol384_add_byte 89
        sol384_add2_byte 93
        jmp sol384_after_contrib

sol384_b26:
        sol384_add_byte 58
        sol384_add_byte 62
        sol384_sub_byte 70
        sol384_add_byte 74
        sol384_add_byte 90
        sol384_add2_byte 94
        jmp sol384_after_contrib

sol384_b27:
        sol384_add_byte 59
        sol384_add_byte 63
        sol384_sub_byte 71
        sol384_add_byte 75
        sol384_add_byte 91
        sol384_add2_byte 95
        jmp sol384_after_contrib

sol384_b28:
        sol384_add_byte 60
        sol384_add_byte 64
        sol384_sub_byte 72
        sol384_add_byte 76
        sol384_add_byte 92
        jmp sol384_after_contrib

sol384_b29:
        sol384_add_byte 61
        sol384_add_byte 65
        sol384_sub_byte 73
        sol384_add_byte 77
        sol384_add_byte 93
        jmp sol384_after_contrib

sol384_b30:
        sol384_add_byte 62
        sol384_add_byte 66
        sol384_sub_byte 74
        sol384_add_byte 78
        sol384_add_byte 94
        jmp sol384_after_contrib

sol384_b31:
        sol384_add_byte 63
        sol384_add_byte 67
        sol384_sub_byte 75
        sol384_add_byte 79
        sol384_add_byte 95
        jmp sol384_after_contrib

sol384_b32:
        sol384_add_byte 64
        sol384_add_byte 68
        sol384_sub_byte 76
        sol384_add_byte 80
        jmp sol384_after_contrib

sol384_b33:
        sol384_add_byte 65
        sol384_add_byte 69
        sol384_sub_byte 77
        sol384_add_byte 81
        jmp sol384_after_contrib

sol384_b34:
        sol384_add_byte 66
        sol384_add_byte 70
        sol384_sub_byte 78
        sol384_add_byte 82
        jmp sol384_after_contrib

sol384_b35:
        sol384_add_byte 67
        sol384_add_byte 71
        sol384_sub_byte 79
        sol384_add_byte 83
        jmp sol384_after_contrib

sol384_b36:
        sol384_add_byte 68
        sol384_add_byte 72
        sol384_sub_byte 80
        sol384_add_byte 84
        jmp sol384_after_contrib

sol384_b37:
        sol384_add_byte 69
        sol384_add_byte 73
        sol384_sub_byte 81
        sol384_add_byte 85
        jmp sol384_after_contrib

sol384_b38:
        sol384_add_byte 70
        sol384_add_byte 74
        sol384_sub_byte 82
        sol384_add_byte 86
        jmp sol384_after_contrib

sol384_b39:
        sol384_add_byte 71
        sol384_add_byte 75
        sol384_sub_byte 83
        sol384_add_byte 87
        jmp sol384_after_contrib

sol384_b40:
        sol384_add_byte 72
        sol384_add_byte 76
        sol384_sub_byte 84
        sol384_add_byte 88
        jmp sol384_after_contrib

sol384_b41:
        sol384_add_byte 73
        sol384_add_byte 77
        sol384_sub_byte 85
        sol384_add_byte 89
        jmp sol384_after_contrib

sol384_b42:
        sol384_add_byte 74
        sol384_add_byte 78
        sol384_sub_byte 86
        sol384_add_byte 90
        jmp sol384_after_contrib

sol384_b43:
        sol384_add_byte 75
        sol384_add_byte 79
        sol384_sub_byte 87
        sol384_add_byte 91
        jmp sol384_after_contrib

sol384_b44:
        sol384_add_byte 76
        sol384_add_byte 80
        sol384_sub_byte 88
        sol384_add_byte 92
        jmp sol384_after_contrib

sol384_b45:
        sol384_add_byte 77
        sol384_add_byte 81
        sol384_sub_byte 89
        sol384_add_byte 93
        jmp sol384_after_contrib

sol384_b46:
        sol384_add_byte 78
        sol384_add_byte 82
        sol384_sub_byte 90
        sol384_add_byte 94
        jmp sol384_after_contrib

sol384_b47:
        sol384_add_byte 79
        sol384_add_byte 83
        sol384_sub_byte 91
        sol384_add_byte 95
        jmp sol384_after_contrib

sol384_lo_save:     .byte 0
sol384_idx_save:    .byte 0
sol384_overflow:    .word 0

; =============================================================================
; fp_mod_mul_384 - fp384_r0 = ((fp_src1) * (fp_src2)) mod p384
; =============================================================================
fp_mod_mul_384:
        jsr fp_mul_384
        jsr fp_mod_reduce384
        rts

; =============================================================================
; fp_mod_sqr_384 - fp384_r0 = ((fp_src1)^2) mod p384
; =============================================================================
fp_mod_sqr_384:
        jsr fp_sqr_384
        jsr fp_mod_reduce384
        rts

; =============================================================================
; fp_mod_inv_384 - fp384_r0 = (fp_src1)^(-1) mod (fp_misc)
; Binary extended GCD, 48-byte version.
; =============================================================================
fp_mod_inv_384:
        lda fp_dst
        pha
        lda fp_dst+1
        pha

        ; u = src1
        lda #<fp384_inv_u
        sta fp_dst
        lda #>fp384_inv_u
        sta fp_dst+1
        jsr fp_copy_384

        ; v = modulus
        lda fp_misc
        sta fp_src1
        lda fp_misc+1
        sta fp_src1+1
        lda #<fp384_inv_v
        sta fp_dst
        lda #>fp384_inv_v
        sta fp_dst+1
        jsr fp_copy_384

        ; x1 = 1
        lda #<fp384_inv_x1
        sta fp_dst
        lda #>fp384_inv_x1
        sta fp_dst+1
        jsr fp_zero_384
        lda #1
        sta fp384_inv_x1

        ; x2 = 0
        lda #<fp384_inv_x2
        sta fp_dst
        lda #>fp384_inv_x2
        sta fp_dst+1
        jsr fp_zero_384

        pla
        sta fp_dst+1
        pla
        sta fp_dst

@mainlp:
        lda #<fp384_inv_u
        sta fp_src1
        lda #>fp384_inv_u
        sta fp_src1+1
        jsr fp_chk_one_384
        bne :+
        jmp @u_one
:
        lda #<fp384_inv_v
        sta fp_src1
        lda #>fp384_inv_v
        sta fp_src1+1
        jsr fp_chk_one_384
        bne :+
        jmp @v_one
:

@halfu:
        lda fp384_inv_u
        and #1
        beq :+
        jmp @halfv
:

        ; Inlined 48-byte shift of fp384_inv_u, MSB-first ROR chain.
        clc
.repeat 48, i
        ror fp384_inv_u + (47 - i)
.endrepeat

        lda fp384_inv_x1
        and #1
        beq @x1ev_nocarry
        ; x1 += mod (in place) using absolute addressing for x1.
        clc
        ldy #0
        ldx #48
@x1addmod:
        lda fp384_inv_x1,y
        adc (fp_misc),y
        sta fp384_inv_x1,y
        iny
        dex
        bne @x1addmod
        lda #0
        adc #0
        lsr                     ; carry-out -> 6502 carry flag
        jmp @x1do_shift
@x1ev_nocarry:
        clc
@x1do_shift:
.repeat 48, i
        ror fp384_inv_x1 + (47 - i)
.endrepeat
        jmp @halfu

@halfv:
        lda fp384_inv_v
        and #1
        beq :+
        jmp @comp
:

        clc
.repeat 48, i
        ror fp384_inv_v + (47 - i)
.endrepeat

        lda fp384_inv_x2
        and #1
        beq @x2ev_nocarry
        clc
        ldy #0
        ldx #48
@x2addmod:
        lda fp384_inv_x2,y
        adc (fp_misc),y
        sta fp384_inv_x2,y
        iny
        dex
        bne @x2addmod
        lda #0
        adc #0
        lsr
        jmp @x2do_shift
@x2ev_nocarry:
        clc
@x2do_shift:
.repeat 48, i
        ror fp384_inv_x2 + (47 - i)
.endrepeat
        jmp @halfv

@comp:
        lda #<fp384_inv_u
        sta fp_src1
        lda #>fp384_inv_u
        sta fp_src1+1
        lda #<fp384_inv_v
        sta fp_src2
        lda #>fp384_inv_v
        sta fp_src2+1
        jsr fp_cmp_384
        bcc @vbig

        ; u >= v: u -= v, x1 -= x2 mod m
        lda #<fp384_inv_u
        sta fp_dst
        lda #>fp384_inv_u
        sta fp_dst+1
        jsr fp_sub_384

        lda #<fp384_inv_x1
        sta fp_src1
        lda #>fp384_inv_x1
        sta fp_src1+1
        lda #<fp384_inv_x2
        sta fp_src2
        lda #>fp384_inv_x2
        sta fp_src2+1
        lda #<fp384_inv_x1
        sta fp_dst
        lda #>fp384_inv_x1
        sta fp_dst+1
        jsr fp_mod_sub_384
        jmp @mainlp

@vbig:
        ; v -= u, x2 -= x1 mod m
        lda #<fp384_inv_v
        sta fp_src1
        lda #>fp384_inv_v
        sta fp_src1+1
        lda #<fp384_inv_u
        sta fp_src2
        lda #>fp384_inv_u
        sta fp_src2+1
        lda #<fp384_inv_v
        sta fp_dst
        lda #>fp384_inv_v
        sta fp_dst+1
        jsr fp_sub_384

        lda #<fp384_inv_x2
        sta fp_src1
        lda #>fp384_inv_x2
        sta fp_src1+1
        lda #<fp384_inv_x1
        sta fp_src2
        lda #>fp384_inv_x1
        sta fp_src2+1
        lda #<fp384_inv_x2
        sta fp_dst
        lda #>fp384_inv_x2
        sta fp_dst+1
        jsr fp_mod_sub_384
        jmp @mainlp

@u_one:
        ldy #47
@cu:
        lda fp384_inv_x1,y
        sta fp384_r0,y
        dey
        bpl @cu
        rts

@v_one:
        ldy #47
@cv:
        lda fp384_inv_x2,y
        sta fp384_r0,y
        dey
        bpl @cv
        rts

; =============================================================================
; fp_chk_one_384 - Set Z if (fp_src1) == 1
; =============================================================================
fp_chk_one_384:
        ldy #0
        lda (fp_src1),y
        cmp #1
        bne @no
        iny
@loop:
        lda (fp_src1),y
        bne @no
        iny
        cpy #48
        bne @loop
        lda #0
        rts
@no:
        lda #$ff
        rts

; =============================================================================
; ec_set_modp_384 - Set fp_misc to ec_p384
; =============================================================================
ec_set_modp_384:
        lda #<ec_p384
        sta fp_misc
        lda #>ec_p384
        sta fp_misc+1
        rts

; =============================================================================
; ec_set_modn_384 - Set fp_misc to ec_n384
; =============================================================================
ec_set_modn_384:
        lda #<ec_n384
        sta fp_misc
        lda #>ec_n384
        sta fp_misc+1
        rts

; =============================================================================
; ec_mulp_384 / ec_sqrp_384 - Modular multiply / square mod p384, copy result.
; =============================================================================
ec_mulp_384:
        jsr ec_set_modp_384
        jsr fp_mod_mul_384
        jmp ec_mulp384_copy_result

ec_sqrp_384:
        jsr ec_set_modp_384
        jsr fp_mod_sqr_384
ec_mulp384_copy_result:
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda #<fp384_r0
        sta fp_src1
        lda #>fp384_r0
        sta fp_src1+1
        jsr fp_copy_384
        pla
        sta fp_src1+1
        pla
        sta fp_src1
        rts
