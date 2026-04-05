; =============================================================================
; fp384.asm - P-384 48-byte field arithmetic (little-endian)
;
; All field elements stored LITTLE-ENDIAN: byte 0 = LSB, byte 47 = MSB.
; Adapted from fp256.asm; loop sizes grown from 32 to 48 and 64 to 96.
;
; Optimizations ported from c64-x25519/src/fe25519.asm:
;   - REU DMA multiplication table lookup (reu_fetch_mul_row)
;   - Self-modifying code for accumulation base addresses
;   - 2x unrolled inner loop in fp_mul_384
;   - Zero-skip for outer loop bytes
;   - Symmetry exploitation in fp_sqr_384 (cross terms doubled)
; =============================================================================

; =============================================================================
; fp_copy_384 - Copy 48 bytes: (fp_dst) = (fp_src1)
; Clobbers: A, Y
; =============================================================================
fp_copy_384:
        ldy #47
@loop:
        lda (fp_src1),y
        sta (fp_dst),y
        dey
        bpl @loop
        rts

; =============================================================================
; fp_zero_384 - Zero 48 bytes at (fp_dst)
; Clobbers: A, Y
; =============================================================================
fp_zero_384:
        lda #0
        ldy #47
@loop:
        sta (fp_dst),y
        dey
        bpl @loop
        rts

; =============================================================================
; fp_cmp_384 - Compare (fp_src1) vs (fp_src2), 48 bytes, little-endian
;
; Compare from byte 47 (MSB) down to byte 0 (LSB).
; Carry set if src1 >= src2, carry clear if src1 < src2.
; Clobbers: A, Y
; =============================================================================
fp_cmp_384:
        ldy #47
@loop:
        lda (fp_src1),y
        cmp (fp_src2),y
        bne @done
        dey
        bpl @loop
@done:
        rts

; =============================================================================
; fp_add_384 - (fp_dst) = (fp_src1) + (fp_src2), 48 bytes, little-endian
;
; Iterates from byte 0 (LSB) up to byte 47 (MSB) - natural carry chain.
; Carry output stored in fp_carry.
; Clobbers: A, X, Y
; =============================================================================
fp_add_384:
        clc
        ldy #0
        ldx #48
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
; fp_sub_384 - (fp_dst) = (fp_src1) - (fp_src2), 48 bytes, little-endian
;
; Iterates from byte 0 (LSB) up. Borrow in fp_carry (1 = borrow).
; Clobbers: A, X, Y
; =============================================================================
fp_sub_384:
        sec
        ldy #0
        ldx #48
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
; fp_is_zero_384 - Test if (fp_src1) == 0
;
; Z flag set if all 48 bytes are zero.
; Clobbers: A, Y
; =============================================================================
fp_is_zero_384:
        ldy #0
        lda #0
@loop:
        ora (fp_src1),y
        iny
        cpy #48
        bne @loop
        cmp #0
        rts

; =============================================================================
; fp_rshift1_384 - Right-shift (fp_src1) by 1 bit in place, little-endian
;
; MSB is byte 47. Start shifting from byte 47 downward.
; Clobbers: A, X, Y
; =============================================================================
fp_rshift1_384:
        clc
        ldy #47
        ldx #48
@loop:
        lda (fp_src1),y
        ror
        sta (fp_src1),y
        dey
        dex
        bne @loop
        rts

; =============================================================================
; fp_mul_384 - 384x384 -> 768 bit multiply, little-endian
;
; (fp_src1) * (fp_src2) -> fp384_wide (96 bytes, little-endian)
; Clobbers: A, X, Y
; =============================================================================
fp_mul_384:
        ; 1. Zero the 96-byte product buffer
        ldx #95
        lda #0
@zero_wide:
        sta fp384_wide,x
        dex
        bpl @zero_wide

        ; 2. Copy src2 to absolute buffer for indexed access
        ldy #47
@copy_src2:
        lda (fp_src2),y
        sta mul_src2_buf_384,y
        dey
        bpl @copy_src2

        ; 3. Schoolbook multiply with REU DMA lookup + self-mod accumulation
        lda #0
        sta fp_mul_i
@mul_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        bne @nonzero_i
        jmp @skip_zero
@nonzero_i:
        sta mul_cached_a

        jsr reu_fetch_mul_row

        ; Self-mod: patch accumulation addresses to base = fp384_wide + i
        lda #<fp384_wide
        clc
        adc fp_mul_i
        sta @accum_ld1+1
        sta @accum_st1+1
        sta @accum_ld1_b+1
        sta @accum_st1_b+1
        lda #>fp384_wide
        adc #0
        sta @accum_ld1+2
        sta @accum_st1+2
        sta @accum_ld1_b+2
        sta @accum_st1_b+2

        ; +1 accesses: base is fp384_wide + i + 1
        lda #<(fp384_wide+1)
        clc
        adc fp_mul_i
        sta @accum_ld2+1
        sta @accum_st2+1
        sta @accum_ld2_b+1
        sta @accum_st2_b+1
        lda #>(fp384_wide+1)
        adc #0
        sta @accum_ld2+2
        sta @accum_st2+2
        sta @accum_ld2_b+2
        sta @accum_st2_b+2

        lda #0
        sta fp_mul_j

        ; ===== UNROLLED 2x INNER LOOP =====
@mul_inner:
        ; --- First copy ---
        ldx fp_mul_j
        ldy mul_src2_buf_384,x
        beq @next_j_first

        lda mul_dma_lo,y
        sta poly_prod_lo
        lda mul_dma_hi,y
        sta poly_prod_hi

        ldx fp_mul_j

        clc
@accum_ld1:
        lda fp384_wide,x
        adc poly_prod_lo
@accum_st1:
        sta fp384_wide,x
@accum_ld2:
        lda fp384_wide+1,x
        adc poly_prod_hi
@accum_st2:
        sta fp384_wide+1,x
        bcc @next_j_first

        ; Propagate carry
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@prop_carry_a:
        cpx #96
        bcs @next_j_first
        sec
        lda fp384_wide,x
        adc #0
        sta fp384_wide,x
        inx
        bcs @prop_carry_a

@next_j_first:
        inc fp_mul_j

        ; --- Second copy ---
        ldx fp_mul_j
        ldy mul_src2_buf_384,x
        beq @next_j

        lda mul_dma_lo,y
        sta poly_prod_lo
        lda mul_dma_hi,y
        sta poly_prod_hi

        ldx fp_mul_j

        clc
@accum_ld1_b:
        lda fp384_wide,x
        adc poly_prod_lo
@accum_st1_b:
        sta fp384_wide,x
@accum_ld2_b:
        lda fp384_wide+1,x
        adc poly_prod_hi
@accum_st2_b:
        sta fp384_wide+1,x
        bcc @next_j

        ; Propagate carry
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@prop_carry_b:
        cpx #96
        bcs @next_j
        sec
        lda fp384_wide,x
        adc #0
        sta fp384_wide,x
        inx
        bcs @prop_carry_b

@next_j:
        inc fp_mul_j
        lda fp_mul_j
        cmp #48
        bcs @skip_zero
        jmp @mul_inner

@skip_zero:
        inc fp_mul_i
        lda fp_mul_i
        cmp #48
        bcs @mul_done
        jmp @mul_outer
@mul_done:
        rts

; =============================================================================
; fp_sqr_384 - 384-bit squaring with symmetry optimization, little-endian
;
; (fp_src1)^2 -> fp384_wide (96 bytes)
; Clobbers: A, X, Y
; =============================================================================
fp_sqr_384:
        ; 1. Zero the 96-byte product buffer
        ldx #95
        lda #0
@zero_wide:
        sta fp384_wide,x
        dex
        bpl @zero_wide

        ; 2. Copy src1 to absolute buffer
        ldy #47
@copy_src:
        lda (fp_src1),y
        sta mul_src2_buf_384,y
        dey
        bpl @copy_src

        ; 3. Cross terms: accumulate 2*a[i]*a[j] for all i < j
        lda #0
        sta fp_mul_i
@sqr_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        bne @sqr_nonzero_i
        jmp @sqr_skip_i
@sqr_nonzero_i:
        sta mul_cached_a

        jsr reu_fetch_mul_row

        ; Self-mod: patch accumulation addresses to base = fp384_wide + i
        lda #<fp384_wide
        clc
        adc fp_mul_i
        sta @sqr_accum_ld1+1
        sta @sqr_accum_st1+1
        lda #>fp384_wide
        adc #0
        sta @sqr_accum_ld1+2
        sta @sqr_accum_st1+2

        lda #<(fp384_wide+1)
        clc
        adc fp_mul_i
        sta @sqr_accum_ld2+1
        sta @sqr_accum_st2+1
        lda #>(fp384_wide+1)
        adc #0
        sta @sqr_accum_ld2+2
        sta @sqr_accum_st2+2

        ; j starts at i+1
        lda fp_mul_i
        clc
        adc #1
        sta fp_mul_j

@sqr_inner:
        ldx fp_mul_j
        ldy mul_src2_buf_384,x
        bne @sqr_nonzero_j
        jmp @sqr_next_j
@sqr_nonzero_j:

        lda mul_dma_lo,y
        sta poly_prod_lo
        lda mul_dma_hi,y
        sta poly_prod_hi

        ; Double the product
        asl poly_prod_lo
        rol poly_prod_hi
        lda #0
        adc #0
        sta fp384_sqr_extra

        ldx fp_mul_j

        clc
@sqr_accum_ld1:
        lda fp384_wide,x
        adc poly_prod_lo
@sqr_accum_st1:
        sta fp384_wide,x
@sqr_accum_ld2:
        lda fp384_wide+1,x
        adc poly_prod_hi
@sqr_accum_st2:
        sta fp384_wide+1,x

        ; Combine carries and propagate
        lda #0
        adc fp384_sqr_extra
        beq @sqr_next_j

        ldx fp_mul_i
        tay
        txa
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
        tya
        clc
        adc fp384_wide,x
        sta fp384_wide,x
        bcc @sqr_next_j
@sqr_prop1:
        inx
        cpx #96
        bcs @sqr_next_j
        sec
        lda fp384_wide,x
        adc #0
        sta fp384_wide,x
        bcs @sqr_prop1

@sqr_next_j:
        inc fp_mul_j
        lda fp_mul_j
        cmp #48
        bcs @sqr_skip_i
        jmp @sqr_inner

@sqr_skip_i:
        inc fp_mul_i
        lda fp_mul_i
        cmp #47                 ; i goes 0..46 (j needs room for i+1)
        bcs @sqr_cross_done
        jmp @sqr_outer
@sqr_cross_done:

        ; 4. Add diagonal terms: a[i]^2 at position 2*i
        lda #0
        sta fp_mul_i
@diag_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        beq @diag_skip

        sta mul_cached_a
        jsr reu_fetch_mul_row

        ldy mul_cached_a
        lda mul_dma_lo,y
        sta poly_prod_lo
        lda mul_dma_hi,y
        sta poly_prod_hi

        ; Add to fp384_wide[2*i]
        lda fp_mul_i
        asl
        tax

        clc
        lda fp384_wide,x
        adc poly_prod_lo
        sta fp384_wide,x
        inx
        lda fp384_wide,x
        adc poly_prod_hi
        sta fp384_wide,x
        bcc @diag_skip

@diag_prop:
        inx
        cpx #96
        bcs @diag_skip
        sec
        lda fp384_wide,x
        adc #0
        sta fp384_wide,x
        bcs @diag_prop

@diag_skip:
        inc fp_mul_i
        lda fp_mul_i
        cmp #48
        bcs @sqr_done
        jmp @diag_outer

@sqr_done:
        rts

; Scratch byte for squaring
fp384_sqr_extra:  !byte 0

; Absolute copy buffer for 48-byte src2 during multiply/square
mul_src2_buf_384:
        !fill 48, 0
