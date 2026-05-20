.setcpu "6502"

.segment "LIB_NISTCURVES_P256_CODE"

; Imports from zp_config
.importzp fp_src1, fp_src2, fp_dst, fp_carry, fp_mul_i, fp_mul_j

; Imports from data
.import fp_wide, mul_src2_buf, mul_dma_lo, mul_dma_hi
.import mul_cached_a, poly_prod_lo, poly_prod_hi

; Imports from constants
.import reu_reu_hi, reu_reu_bank, reu_command
.import reu_reu_lo, reu_addr_ctrl     ; issue #33-class defence

; REU layout contract (SPEC §3)
.import LIB_NISTCURVES_REU_BANK_MUL

; Exports
.export fp_copy, fp_zero, fp_cmp, fp_add, fp_sub
.export fp_is_zero, fp_rshift1, fp_mul, fp_sqr
.export fp_sqr_pairs, fp_sqr_extra

; =============================================================================
; fp_copy - Copy 32 bytes: (fp_dst) = (fp_src1)
; =============================================================================
fp_copy:
        ldy #31
@loop:
        lda (fp_src1),y
        sta (fp_dst),y
        dey
        bpl @loop
        rts

; =============================================================================
; fp_zero - Zero 32 bytes at (fp_dst)
; =============================================================================
fp_zero:
        lda #0
        ldy #31
@loop:
        sta (fp_dst),y
        dey
        bpl @loop
        rts

; =============================================================================
; fp_cmp - Compare (fp_src1) vs (fp_src2), 32 bytes, little-endian
; =============================================================================
fp_cmp:
        ldy #31
@loop:
        lda (fp_src1),y
        cmp (fp_src2),y
        bne @done
        dey
        bpl @loop
@done:
        rts

; =============================================================================
; fp_add - (fp_dst) = (fp_src1) + (fp_src2), 32 bytes, little-endian
; =============================================================================
fp_add:
        clc
        ldy #0
        ldx #32
@loop:
        lda (fp_src1),y
        adc (fp_src2),y
        sta (fp_dst),y
        iny
        dex
        bne @loop
        lda #0
        adc #0
        sta fp_carry
        rts

; =============================================================================
; fp_sub - (fp_dst) = (fp_src1) - (fp_src2), 32 bytes, little-endian
; =============================================================================
fp_sub:
        sec
        ldy #0
        ldx #32
@loop:
        lda (fp_src1),y
        sbc (fp_src2),y
        sta (fp_dst),y
        iny
        dex
        bne @loop
        lda #0
        adc #0
        eor #1
        sta fp_carry
        rts

; =============================================================================
; fp_is_zero - Test if (fp_src1) == 0
; =============================================================================
fp_is_zero:
        ldy #0
        lda #0
@loop:
        ora (fp_src1),y
        iny
        cpy #32
        bne @loop
        cmp #0
        rts

; =============================================================================
; fp_rshift1 - Right-shift (fp_src1) by 1 bit in place, little-endian
; =============================================================================
fp_rshift1:
        clc
        ldy #31
        ldx #32
@loop:
        lda (fp_src1),y
        ror
        sta (fp_src1),y
        dey
        dex
        bne @loop
        rts

; =============================================================================
; fp_mul - 256x256 -> 512 bit multiply, little-endian
; =============================================================================
fp_mul:
        ; --- Defensive REU register init (issue #33-class defence;
        ; see c64-x25519 commit 817f525). Per-row DMA below writes only
        ; reu_reu_hi/bank/command, trusting reu_reu_lo ($DF04) and
        ; reu_addr_ctrl ($DF0A) remain 0 from reu_mul_init's tail. A
        ; caller that touched those registers between init and us
        ; would silently route the row fetch to the wrong REU offset
        ; (or hold-C64-address) and we'd accumulate garbage.
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        ldx #63
        lda #0
@zero_wide:
        sta fp_wide,x
        dex
        bpl @zero_wide

        ldy #31
@copy_src2:
        lda (fp_src2),y
        sta mul_src2_buf,y
        dey
        bpl @copy_src2

        lda #0
        sta fp_mul_i
@mul_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        bne @nonzero_i
        jmp @skip_zero
@nonzero_i:
        sta mul_cached_a

        asl
        sta reu_reu_hi
        lda #<LIB_NISTCURVES_REU_BANK_MUL
        adc #0
        sta reu_reu_bank
        lda #%10110001
        sta reu_command

        lda #<fp_wide
        clc
        adc fp_mul_i
        sta @accum_ld1+1
        sta @accum_st1+1
        sta @accum_ld1_b+1
        sta @accum_st1_b+1
        sta @accum_ld1_c+1
        sta @accum_st1_c+1
        sta @accum_ld1_d+1
        sta @accum_st1_d+1
        lda #>fp_wide
        adc #0
        sta @accum_ld1+2
        sta @accum_st1+2
        sta @accum_ld1_b+2
        sta @accum_st1_b+2
        sta @accum_ld1_c+2
        sta @accum_st1_c+2
        sta @accum_ld1_d+2
        sta @accum_st1_d+2

        lda #<(fp_wide+1)
        clc
        adc fp_mul_i
        sta @accum_ld2+1
        sta @accum_st2+1
        sta @accum_ld2_b+1
        sta @accum_st2_b+1
        sta @accum_ld2_c+1
        sta @accum_st2_c+1
        sta @accum_ld2_d+1
        sta @accum_st2_d+1
        lda #>(fp_wide+1)
        adc #0
        sta @accum_ld2+2
        sta @accum_st2+2
        sta @accum_ld2_b+2
        sta @accum_st2_b+2
        sta @accum_ld2_c+2
        sta @accum_st2_c+2
        sta @accum_ld2_d+2
        sta @accum_st2_d+2

        ldx #0

@mul_inner:
        ldy mul_src2_buf,x
        beq @next_j_first
        clc
@accum_ld1:
        lda fp_wide,x
        adc mul_dma_lo,y
@accum_st1:
        sta fp_wide,x
@accum_ld2:
        lda fp_wide+1,x
        adc mul_dma_hi,y
@accum_st2:
        sta fp_wide+1,x
        bcs @do_prop_a
@next_j_first:
        inx

        ldy mul_src2_buf,x
        beq @next_j_second
        clc
@accum_ld1_b:
        lda fp_wide,x
        adc mul_dma_lo,y
@accum_st1_b:
        sta fp_wide,x
@accum_ld2_b:
        lda fp_wide+1,x
        adc mul_dma_hi,y
@accum_st2_b:
        sta fp_wide+1,x
        bcs @do_prop_b
@next_j_second:
        inx

        ldy mul_src2_buf,x
        beq @next_j_third
        clc
@accum_ld1_c:
        lda fp_wide,x
        adc mul_dma_lo,y
@accum_st1_c:
        sta fp_wide,x
@accum_ld2_c:
        lda fp_wide+1,x
        adc mul_dma_hi,y
@accum_st2_c:
        sta fp_wide+1,x
        bcs @do_prop_c
@next_j_third:
        inx

        ldy mul_src2_buf,x
        beq @next_j
        clc
@accum_ld1_d:
        lda fp_wide,x
        adc mul_dma_lo,y
@accum_st1_d:
        sta fp_wide,x
@accum_ld2_d:
        lda fp_wide+1,x
        adc mul_dma_hi,y
@accum_st2_d:
        sta fp_wide+1,x
        bcs @do_prop_d
@next_j:
        inx
        cpx #32
        bcc @mul_inner
        jmp @skip_zero

@do_prop_a:
        stx fp_mul_j
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@prop_carry_a:
        cpx #64
        bcs @carry_done_a
        inc fp_wide,x
        bne @carry_done_a
        inx
        bne @prop_carry_a
@carry_done_a:
        ldx fp_mul_j
        jmp @next_j_first

@do_prop_b:
        stx fp_mul_j
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@prop_carry_b:
        cpx #64
        bcs @carry_done_b
        inc fp_wide,x
        bne @carry_done_b
        inx
        bne @prop_carry_b
@carry_done_b:
        ldx fp_mul_j
        jmp @next_j_second

@do_prop_c:
        stx fp_mul_j
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@prop_carry_c:
        cpx #64
        bcs @carry_done_c
        inc fp_wide,x
        bne @carry_done_c
        inx
        bne @prop_carry_c
@carry_done_c:
        ldx fp_mul_j
        jmp @next_j_third

@do_prop_d:
        stx fp_mul_j
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@prop_carry_d:
        cpx #64
        bcs @carry_done_d
        inc fp_wide,x
        bne @carry_done_d
        inx
        bne @prop_carry_d
@carry_done_d:
        ldx fp_mul_j
        jmp @next_j

@skip_zero:
        inc fp_mul_i
        lda fp_mul_i
        cmp #32
        bcs @mul_done
        jmp @mul_outer
@mul_done:
        rts

; =============================================================================
; fp_sqr - 256-bit squaring with symmetry optimization, little-endian
; =============================================================================
fp_sqr:
        ; --- Defensive REU register init (issue #33-class defence;
        ; see fp_mul above and c64-x25519 commit 817f525).
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        ldx #63
        lda #0
@zero_wide:
        sta fp_wide,x
        dex
        bpl @zero_wide

        ldy #31
@copy_src:
        lda (fp_src1),y
        sta mul_src2_buf,y
        dey
        bpl @copy_src
        lda #0
        sta mul_src2_buf+32
        sta mul_src2_buf+33
        sta mul_src2_buf+34

        lda #0
        sta fp_mul_i
@sqr_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        bne @sqr_nonzero_i
        jmp @sqr_skip_i
@sqr_nonzero_i:
        sta mul_cached_a

        asl
        sta reu_reu_hi
        lda #<LIB_NISTCURVES_REU_BANK_MUL
        adc #0
        sta reu_reu_bank
        lda #%10110001
        sta reu_command

        lda #<fp_wide
        clc
        adc fp_mul_i
        sta @sqr_accum_ld1+1
        sta @sqr_accum_st1+1
        sta @sqr_accum_ld1_b+1
        sta @sqr_accum_st1_b+1
        sta @sqr_accum_ld1_c+1
        sta @sqr_accum_st1_c+1
        sta @sqr_accum_ld1_d+1
        sta @sqr_accum_st1_d+1
        lda #>fp_wide
        adc #0
        sta @sqr_accum_ld1+2
        sta @sqr_accum_st1+2
        sta @sqr_accum_ld1_b+2
        sta @sqr_accum_st1_b+2
        sta @sqr_accum_ld1_c+2
        sta @sqr_accum_st1_c+2
        sta @sqr_accum_ld1_d+2
        sta @sqr_accum_st1_d+2

        lda #<(fp_wide+1)
        clc
        adc fp_mul_i
        sta @sqr_accum_ld2+1
        sta @sqr_accum_st2+1
        sta @sqr_accum_ld2_b+1
        sta @sqr_accum_st2_b+1
        sta @sqr_accum_ld2_c+1
        sta @sqr_accum_st2_c+1
        sta @sqr_accum_ld2_d+1
        sta @sqr_accum_st2_d+1
        lda #>(fp_wide+1)
        adc #0
        sta @sqr_accum_ld2+2
        sta @sqr_accum_st2+2
        sta @sqr_accum_ld2_b+2
        sta @sqr_accum_st2_b+2
        sta @sqr_accum_ld2_c+2
        sta @sqr_accum_st2_c+2
        sta @sqr_accum_ld2_d+2
        sta @sqr_accum_st2_d+2

        ldx fp_mul_i
        inx

        lda #34
        sec
        sbc fp_mul_i
        lsr
        lsr
        sta fp_sqr_pairs

@sqr_inner:
        ldy mul_src2_buf,x
        beq @sqr_next_j_first
        clc
@sqr_accum_ld1:
        lda fp_wide,x
        adc mul_dma_lo,y
@sqr_accum_st1:
        sta fp_wide,x
@sqr_accum_ld2:
        lda fp_wide+1,x
        adc mul_dma_hi,y
@sqr_accum_st2:
        sta fp_wide+1,x
        bcs @sqr_do_prop_a
@sqr_next_j_first:
        inx

        ldy mul_src2_buf,x
        beq @sqr_next_j_second
        clc
@sqr_accum_ld1_b:
        lda fp_wide,x
        adc mul_dma_lo,y
@sqr_accum_st1_b:
        sta fp_wide,x
@sqr_accum_ld2_b:
        lda fp_wide+1,x
        adc mul_dma_hi,y
@sqr_accum_st2_b:
        sta fp_wide+1,x
        bcs @sqr_do_prop_b
@sqr_next_j_second:
        inx

        ldy mul_src2_buf,x
        beq @sqr_next_j_third
        clc
@sqr_accum_ld1_c:
        lda fp_wide,x
        adc mul_dma_lo,y
@sqr_accum_st1_c:
        sta fp_wide,x
@sqr_accum_ld2_c:
        lda fp_wide+1,x
        adc mul_dma_hi,y
@sqr_accum_st2_c:
        sta fp_wide+1,x
        bcs @sqr_do_prop_c
@sqr_next_j_third:
        inx

        ldy mul_src2_buf,x
        beq @sqr_next_j
        clc
@sqr_accum_ld1_d:
        lda fp_wide,x
        adc mul_dma_lo,y
@sqr_accum_st1_d:
        sta fp_wide,x
@sqr_accum_ld2_d:
        lda fp_wide+1,x
        adc mul_dma_hi,y
@sqr_accum_st2_d:
        sta fp_wide+1,x
        bcs @sqr_do_prop_d
@sqr_next_j:
        inx
        dec fp_sqr_pairs
        beq @sqr_skip_i
        jmp @sqr_inner

@sqr_do_prop_a:
        stx fp_mul_j
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@sqr_prop_carry_a:
        cpx #64
        bcs @sqr_carry_done_a
        inc fp_wide,x
        bne @sqr_carry_done_a
        inx
        bne @sqr_prop_carry_a
@sqr_carry_done_a:
        ldx fp_mul_j
        jmp @sqr_next_j_first

@sqr_do_prop_b:
        stx fp_mul_j
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@sqr_prop_carry_b:
        cpx #64
        bcs @sqr_carry_done_b
        inc fp_wide,x
        bne @sqr_carry_done_b
        inx
        bne @sqr_prop_carry_b
@sqr_carry_done_b:
        ldx fp_mul_j
        jmp @sqr_next_j_second

@sqr_do_prop_c:
        stx fp_mul_j
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@sqr_prop_carry_c:
        cpx #64
        bcs @sqr_carry_done_c
        inc fp_wide,x
        bne @sqr_carry_done_c
        inx
        bne @sqr_prop_carry_c
@sqr_carry_done_c:
        ldx fp_mul_j
        jmp @sqr_next_j_third

@sqr_do_prop_d:
        stx fp_mul_j
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@sqr_prop_carry_d:
        cpx #64
        bcs @sqr_carry_done_d
        inc fp_wide,x
        bne @sqr_carry_done_d
        inx
        bne @sqr_prop_carry_d
@sqr_carry_done_d:
        ldx fp_mul_j
        jmp @sqr_next_j

@sqr_skip_i:
        inc fp_mul_i
        lda fp_mul_i
        cmp #31
        bcs @sqr_cross_done
        jmp @sqr_outer
@sqr_cross_done:

        clc
        ldy #0
        ldx #64
@sqr_double:
        lda fp_wide,y
        rol
        sta fp_wide,y
        iny
        dex
        bne @sqr_double

        lda #0
        sta fp_mul_i
@diag_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        beq @diag_skip

        sta mul_cached_a
        asl
        sta reu_reu_hi
        lda #<LIB_NISTCURVES_REU_BANK_MUL
        adc #0
        sta reu_reu_bank
        lda #%10110001
        sta reu_command

        ldy mul_cached_a
        lda mul_dma_lo,y
        sta poly_prod_lo
        lda mul_dma_hi,y
        sta poly_prod_hi

        lda fp_mul_i
        asl
        tax

        clc
        lda fp_wide,x
        adc poly_prod_lo
        sta fp_wide,x
        inx
        lda fp_wide,x
        adc poly_prod_hi
        sta fp_wide,x
        bcc @diag_skip

@diag_prop:
        inx
        cpx #64
        bcs @diag_skip
        inc fp_wide,x
        beq @diag_prop

@diag_skip:
        inc fp_mul_i
        lda fp_mul_i
        cmp #32
        bcs @sqr_done
        jmp @diag_outer

@sqr_done:
        rts

fp_sqr_pairs:   .byte 0
fp_sqr_extra:   .byte 0
