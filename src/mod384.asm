; =============================================================================
; mod384.asm - Modular operations for P-384, including Solinas fast reduction
;
; All field elements stored LITTLE-ENDIAN: byte 0 = LSB, byte 47 = MSB.
; =============================================================================

; =============================================================================
; P-384 prime and group order constants (little-endian)
; =============================================================================

; P-384 prime: p = 2^384 - 2^128 - 2^96 + 2^32 - 1
; Verified in Python: p.to_bytes(48, 'little')
ec_p384:
        !byte $FF,$FF,$FF,$FF,$00,$00,$00,$00  ; bytes 0-7   (w0=FFFFFFFF, w1=00000000)
        !byte $00,$00,$00,$00,$FF,$FF,$FF,$FF  ; bytes 8-15  (w2=00000000, w3=FFFFFFFF)
        !byte $FE,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 16-23 (w4=FFFFFFFE, w5=FFFFFFFF)
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 24-31 (w6=FFFFFFFF, w7=FFFFFFFF)
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 32-39 (w8=FFFFFFFF, w9=FFFFFFFF)
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 40-47 (w10=FFFFFFFF, w11=FFFFFFFF)

; P-384 group order n (little-endian, verified in Python)
ec_n384:
        !byte $73,$29,$C5,$CC,$6A,$19,$EC,$EC  ; bytes 0-7
        !byte $7A,$A7,$B0,$48,$B2,$0D,$1A,$58  ; bytes 8-15
        !byte $DF,$2D,$37,$F4,$81,$4D,$63,$C7  ; bytes 16-23
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 24-31
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 32-39
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 40-47

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

!macro sol384_add_byte .off {
        clc
        lda sol384_sum_lo
        adc fp384_wide + .off
        sta sol384_sum_lo
        lda sol384_sum_hi
        adc #0
        sta sol384_sum_hi
}

!macro sol384_add2_byte .off {
        lda fp384_wide + .off
        asl
        php
        clc
        adc sol384_sum_lo
        sta sol384_sum_lo
        lda sol384_sum_hi
        adc #0
        sta sol384_sum_hi
        plp
        bcc .skip
        inc sol384_sum_hi
.skip:
}

!macro sol384_sub_byte .off {
        sec
        lda sol384_sum_lo
        sbc fp384_wide + .off
        sta sol384_sum_lo
        lda sol384_sum_hi
        sbc #0
        sta sol384_sum_hi
}

fp_mod_reduce384:
        lda #0
        sta sol384_acc_lo
        sta sol384_acc_hi

        ldx #0
@byte_loop:
        stx sol384_byte_idx

        lda sol384_acc_lo
        sta sol384_sum_lo
        lda sol384_acc_hi
        sta sol384_sum_hi

        ; --- Add s1[x] = fp384_wide[x] ---
        ldx sol384_byte_idx
        clc
        lda sol384_sum_lo
        adc fp384_wide,x
        sta sol384_sum_lo
        lda sol384_sum_hi
        adc #0
        sta sol384_sum_hi

        jsr sol384_add_contributions

        lda sol384_sum_lo
        ldx sol384_byte_idx
        sta fp384_r0,x
        lda sol384_sum_hi
        sta sol384_acc_lo
        bpl +
        lda #$ff
        sta sol384_acc_hi
        ldx sol384_byte_idx
        inx
        cpx #48
        bcs @byte_done
        jmp @byte_loop
+
        lda #0
        sta sol384_acc_hi
        ldx sol384_byte_idx
        inx
        cpx #48
        bcs @byte_done
        jmp @byte_loop

@byte_done:
        lda sol384_acc_lo
        sta sol384_overflow
        lda sol384_acc_hi
        sta sol384_overflow+1

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

sol384_add_contributions:
        lda sol384_byte_idx
        asl
        tax
        lda sol384_jmp_tbl,x
        sta sol384_jmp_addr
        lda sol384_jmp_tbl+1,x
        sta sol384_jmp_addr+1
        jmp (sol384_jmp_addr)

sol384_jmp_addr: !word 0

sol384_jmp_tbl:
        !word sol384_b0,  sol384_b1,  sol384_b2,  sol384_b3
        !word sol384_b4,  sol384_b5,  sol384_b6,  sol384_b7
        !word sol384_b8,  sol384_b9,  sol384_b10, sol384_b11
        !word sol384_b12, sol384_b13, sol384_b14, sol384_b15
        !word sol384_b16, sol384_b17, sol384_b18, sol384_b19
        !word sol384_b20, sol384_b21, sol384_b22, sol384_b23
        !word sol384_b24, sol384_b25, sol384_b26, sol384_b27
        !word sol384_b28, sol384_b29, sol384_b30, sol384_b31
        !word sol384_b32, sol384_b33, sol384_b34, sol384_b35
        !word sol384_b36, sol384_b37, sol384_b38, sol384_b39
        !word sol384_b40, sol384_b41, sol384_b42, sol384_b43
        !word sol384_b44, sol384_b45, sol384_b46, sol384_b47

sol384_b0:
        +sol384_add_byte 48
        +sol384_add_byte 80
        +sol384_add_byte 84
        +sol384_sub_byte 92
        rts

sol384_b1:
        +sol384_add_byte 49
        +sol384_add_byte 81
        +sol384_add_byte 85
        +sol384_sub_byte 93
        rts

sol384_b2:
        +sol384_add_byte 50
        +sol384_add_byte 82
        +sol384_add_byte 86
        +sol384_sub_byte 94
        rts

sol384_b3:
        +sol384_add_byte 51
        +sol384_add_byte 83
        +sol384_add_byte 87
        +sol384_sub_byte 95
        rts

sol384_b4:
        +sol384_sub_byte 48
        +sol384_add_byte 52
        +sol384_sub_byte 80
        +sol384_add_byte 88
        +sol384_add_byte 92
        rts

sol384_b5:
        +sol384_sub_byte 49
        +sol384_add_byte 53
        +sol384_sub_byte 81
        +sol384_add_byte 89
        +sol384_add_byte 93
        rts

sol384_b6:
        +sol384_sub_byte 50
        +sol384_add_byte 54
        +sol384_sub_byte 82
        +sol384_add_byte 90
        +sol384_add_byte 94
        rts

sol384_b7:
        +sol384_sub_byte 51
        +sol384_add_byte 55
        +sol384_sub_byte 83
        +sol384_add_byte 91
        +sol384_add_byte 95
        rts

sol384_b8:
        +sol384_sub_byte 52
        +sol384_add_byte 56
        +sol384_sub_byte 84
        +sol384_add_byte 92
        rts

sol384_b9:
        +sol384_sub_byte 53
        +sol384_add_byte 57
        +sol384_sub_byte 85
        +sol384_add_byte 93
        rts

sol384_b10:
        +sol384_sub_byte 54
        +sol384_add_byte 58
        +sol384_sub_byte 86
        +sol384_add_byte 94
        rts

sol384_b11:
        +sol384_sub_byte 55
        +sol384_add_byte 59
        +sol384_sub_byte 87
        +sol384_add_byte 95
        rts

sol384_b12:
        +sol384_add_byte 48
        +sol384_sub_byte 56
        +sol384_add_byte 60
        +sol384_add_byte 80
        +sol384_add_byte 84
        +sol384_sub_byte 88
        +sol384_sub_byte 92
        rts

sol384_b13:
        +sol384_add_byte 49
        +sol384_sub_byte 57
        +sol384_add_byte 61
        +sol384_add_byte 81
        +sol384_add_byte 85
        +sol384_sub_byte 89
        +sol384_sub_byte 93
        rts

sol384_b14:
        +sol384_add_byte 50
        +sol384_sub_byte 58
        +sol384_add_byte 62
        +sol384_add_byte 82
        +sol384_add_byte 86
        +sol384_sub_byte 90
        +sol384_sub_byte 94
        rts

sol384_b15:
        +sol384_add_byte 51
        +sol384_sub_byte 59
        +sol384_add_byte 63
        +sol384_add_byte 83
        +sol384_add_byte 87
        +sol384_sub_byte 91
        +sol384_sub_byte 95
        rts

sol384_b16:
        +sol384_add_byte 48
        +sol384_add_byte 52
        +sol384_sub_byte 60
        +sol384_add_byte 64
        +sol384_add_byte 80
        +sol384_add2_byte 84
        +sol384_add_byte 88
        +sol384_sub_byte 92
        +sol384_sub_byte 92
        rts

sol384_b17:
        +sol384_add_byte 49
        +sol384_add_byte 53
        +sol384_sub_byte 61
        +sol384_add_byte 65
        +sol384_add_byte 81
        +sol384_add2_byte 85
        +sol384_add_byte 89
        +sol384_sub_byte 93
        +sol384_sub_byte 93
        rts

sol384_b18:
        +sol384_add_byte 50
        +sol384_add_byte 54
        +sol384_sub_byte 62
        +sol384_add_byte 66
        +sol384_add_byte 82
        +sol384_add2_byte 86
        +sol384_add_byte 90
        +sol384_sub_byte 94
        +sol384_sub_byte 94
        rts

sol384_b19:
        +sol384_add_byte 51
        +sol384_add_byte 55
        +sol384_sub_byte 63
        +sol384_add_byte 67
        +sol384_add_byte 83
        +sol384_add2_byte 87
        +sol384_add_byte 91
        +sol384_sub_byte 95
        +sol384_sub_byte 95
        rts

sol384_b20:
        +sol384_add_byte 52
        +sol384_add_byte 56
        +sol384_sub_byte 64
        +sol384_add_byte 68
        +sol384_add_byte 84
        +sol384_add2_byte 88
        +sol384_add_byte 92
        rts

sol384_b21:
        +sol384_add_byte 53
        +sol384_add_byte 57
        +sol384_sub_byte 65
        +sol384_add_byte 69
        +sol384_add_byte 85
        +sol384_add2_byte 89
        +sol384_add_byte 93
        rts

sol384_b22:
        +sol384_add_byte 54
        +sol384_add_byte 58
        +sol384_sub_byte 66
        +sol384_add_byte 70
        +sol384_add_byte 86
        +sol384_add2_byte 90
        +sol384_add_byte 94
        rts

sol384_b23:
        +sol384_add_byte 55
        +sol384_add_byte 59
        +sol384_sub_byte 67
        +sol384_add_byte 71
        +sol384_add_byte 87
        +sol384_add2_byte 91
        +sol384_add_byte 95
        rts

sol384_b24:
        +sol384_add_byte 56
        +sol384_add_byte 60
        +sol384_sub_byte 68
        +sol384_add_byte 72
        +sol384_add_byte 88
        +sol384_add2_byte 92
        rts

sol384_b25:
        +sol384_add_byte 57
        +sol384_add_byte 61
        +sol384_sub_byte 69
        +sol384_add_byte 73
        +sol384_add_byte 89
        +sol384_add2_byte 93
        rts

sol384_b26:
        +sol384_add_byte 58
        +sol384_add_byte 62
        +sol384_sub_byte 70
        +sol384_add_byte 74
        +sol384_add_byte 90
        +sol384_add2_byte 94
        rts

sol384_b27:
        +sol384_add_byte 59
        +sol384_add_byte 63
        +sol384_sub_byte 71
        +sol384_add_byte 75
        +sol384_add_byte 91
        +sol384_add2_byte 95
        rts

sol384_b28:
        +sol384_add_byte 60
        +sol384_add_byte 64
        +sol384_sub_byte 72
        +sol384_add_byte 76
        +sol384_add_byte 92
        rts

sol384_b29:
        +sol384_add_byte 61
        +sol384_add_byte 65
        +sol384_sub_byte 73
        +sol384_add_byte 77
        +sol384_add_byte 93
        rts

sol384_b30:
        +sol384_add_byte 62
        +sol384_add_byte 66
        +sol384_sub_byte 74
        +sol384_add_byte 78
        +sol384_add_byte 94
        rts

sol384_b31:
        +sol384_add_byte 63
        +sol384_add_byte 67
        +sol384_sub_byte 75
        +sol384_add_byte 79
        +sol384_add_byte 95
        rts

sol384_b32:
        +sol384_add_byte 64
        +sol384_add_byte 68
        +sol384_sub_byte 76
        +sol384_add_byte 80
        rts

sol384_b33:
        +sol384_add_byte 65
        +sol384_add_byte 69
        +sol384_sub_byte 77
        +sol384_add_byte 81
        rts

sol384_b34:
        +sol384_add_byte 66
        +sol384_add_byte 70
        +sol384_sub_byte 78
        +sol384_add_byte 82
        rts

sol384_b35:
        +sol384_add_byte 67
        +sol384_add_byte 71
        +sol384_sub_byte 79
        +sol384_add_byte 83
        rts

sol384_b36:
        +sol384_add_byte 68
        +sol384_add_byte 72
        +sol384_sub_byte 80
        +sol384_add_byte 84
        rts

sol384_b37:
        +sol384_add_byte 69
        +sol384_add_byte 73
        +sol384_sub_byte 81
        +sol384_add_byte 85
        rts

sol384_b38:
        +sol384_add_byte 70
        +sol384_add_byte 74
        +sol384_sub_byte 82
        +sol384_add_byte 86
        rts

sol384_b39:
        +sol384_add_byte 71
        +sol384_add_byte 75
        +sol384_sub_byte 83
        +sol384_add_byte 87
        rts

sol384_b40:
        +sol384_add_byte 72
        +sol384_add_byte 76
        +sol384_sub_byte 84
        +sol384_add_byte 88
        rts

sol384_b41:
        +sol384_add_byte 73
        +sol384_add_byte 77
        +sol384_sub_byte 85
        +sol384_add_byte 89
        rts

sol384_b42:
        +sol384_add_byte 74
        +sol384_add_byte 78
        +sol384_sub_byte 86
        +sol384_add_byte 90
        rts

sol384_b43:
        +sol384_add_byte 75
        +sol384_add_byte 79
        +sol384_sub_byte 87
        +sol384_add_byte 91
        rts

sol384_b44:
        +sol384_add_byte 76
        +sol384_add_byte 80
        +sol384_sub_byte 88
        +sol384_add_byte 92
        rts

sol384_b45:
        +sol384_add_byte 77
        +sol384_add_byte 81
        +sol384_sub_byte 89
        +sol384_add_byte 93
        rts

sol384_b46:
        +sol384_add_byte 78
        +sol384_add_byte 82
        +sol384_sub_byte 90
        +sol384_add_byte 94
        rts

sol384_b47:
        +sol384_add_byte 79
        +sol384_add_byte 83
        +sol384_sub_byte 91
        +sol384_add_byte 95
        rts

sol384_acc_lo:      !byte 0
sol384_acc_hi:      !byte 0
sol384_sum_lo:      !byte 0
sol384_sum_hi:      !byte 0
sol384_byte_idx:    !byte 0
sol384_overflow:    !word 0

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
        bne +
        jmp @u_one
+
        lda #<fp384_inv_v
        sta fp_src1
        lda #>fp384_inv_v
        sta fp_src1+1
        jsr fp_chk_one_384
        bne +
        jmp @v_one
+

@halfu:
        lda fp384_inv_u
        and #1
        bne @halfv

        lda #<fp384_inv_u
        sta fp_src1
        lda #>fp384_inv_u
        sta fp_src1+1
        jsr fp_rshift1_384

        lda fp384_inv_x1
        and #1
        beq @x1ev_nocarry
        lda #<fp384_inv_x1
        sta fp_src1
        sta fp_dst
        lda #>fp384_inv_x1
        sta fp_src1+1
        sta fp_dst+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_add_384
        jmp @x1do_shift
@x1ev_nocarry:
        lda #0
        sta fp_carry
@x1do_shift:
        lda fp_carry
        lsr
        ldy #47
        ldx #48
@x1sh:
        lda fp384_inv_x1,y
        ror
        sta fp384_inv_x1,y
        dey
        dex
        bne @x1sh
        jmp @halfu

@halfv:
        lda fp384_inv_v
        and #1
        bne @comp

        lda #<fp384_inv_v
        sta fp_src1
        lda #>fp384_inv_v
        sta fp_src1+1
        jsr fp_rshift1_384

        lda fp384_inv_x2
        and #1
        beq @x2ev_nocarry
        lda #<fp384_inv_x2
        sta fp_src1
        sta fp_dst
        lda #>fp384_inv_x2
        sta fp_src1+1
        sta fp_dst+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_add_384
        jmp @x2do_shift
@x2ev_nocarry:
        lda #0
        sta fp_carry
@x2do_shift:
        lda fp_carry
        lsr
        ldy #47
        ldx #48
@x2sh:
        lda fp384_inv_x2,y
        ror
        sta fp384_inv_x2,y
        dey
        dex
        bne @x2sh
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
; ec_mulp_384 - Modular multiply mod p, copy result to (fp_dst)
; =============================================================================
ec_mulp_384:
        jsr ec_set_modp_384
        jsr fp_mod_mul_384
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
