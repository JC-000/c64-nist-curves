.setcpu "6502"

.segment "LIB_NISTCURVES_P256_CODE"

; Imports from zp_config
.importzp fp_src1, fp_src2, fp_misc

; Imports from mod256
.import ec_p256, fp_mod_sqr, fp_mod_mul

; Imports from data
.import fp_tmp1, fp_r0

; Exports
.export fp_mod_inv_fast

; Exponent p-2 as 32 big-endian bytes
.segment "LIB_NISTCURVES_P256_RODATA"
fp_inv_exp_p2:
        .byte $FF, $FF, $FF, $FF, $00, $00, $00, $01
        .byte $00, $00, $00, $00, $00, $00, $00, $00
        .byte $00, $00, $00, $00, $FF, $FF, $FF, $FF
        .byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FD

.segment "LIB_NISTCURVES_P256_CODE"

; Scratch state for the inversion loop
fp_inv_bytepos: .byte 0
fp_inv_bitcnt:  .byte 0
fp_inv_curbyte: .byte 0

fp_mod_inv_fast:
        lda #<ec_p256
        sta fp_misc
        lda #>ec_p256
        sta fp_misc+1

        ldy #31
@copy_x:
        lda (fp_src1),y
        sta fp_tmp1,y
        dey
        bpl @copy_x

        ldy #31
@copy_r0:
        lda fp_tmp1,y
        sta fp_r0,y
        dey
        bpl @copy_r0

        lda #0
        sta fp_inv_bytepos
        lda #$FF
        asl
        sta fp_inv_curbyte
        lda #7
        sta fp_inv_bitcnt

@next_bit:
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        jsr fp_mod_sqr

        asl fp_inv_curbyte
        bcc @skip_mul

        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        lda #<fp_tmp1
        sta fp_src2
        lda #>fp_tmp1
        sta fp_src2+1
        jsr fp_mod_mul

@skip_mul:
        dec fp_inv_bitcnt
        bne @next_bit

        inc fp_inv_bytepos
        lda fp_inv_bytepos
        cmp #32
        beq @done

        tax
        lda fp_inv_exp_p2,x
        sta fp_inv_curbyte
        lda #8
        sta fp_inv_bitcnt
        jmp @next_bit

@done:
        rts
