; =============================================================================
; fp256.asm - P-256 32-byte field arithmetic (little-endian)
;
; All field elements stored LITTLE-ENDIAN: byte 0 = LSB, byte 31 = MSB.
; This matches the natural 6502 carry propagation direction (low to high).
;
; Optimizations ported from c64-x25519/src/fe25519.asm:
;   - REU DMA multiplication table lookup (reu_fetch_mul_row)
;   - Self-modifying code for accumulation base addresses
;   - 2x unrolled inner loop in fp_mul
;   - Zero-skip for outer loop bytes
;   - Symmetry exploitation in fp_sqr (cross terms doubled)
; =============================================================================

; =============================================================================
; fp_copy - Copy 32 bytes: (fp_dst) = (fp_src1)
; Clobbers: A, Y
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
; Clobbers: A, Y
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
;
; For little-endian, compare from byte 31 (MSB) down to byte 0 (LSB).
; Carry set if src1 >= src2, carry clear if src1 < src2.
; Zero flag set if equal.
; Clobbers: A, Y
; =============================================================================
fp_cmp:
        ldy #31
@loop:
        lda (fp_src1),y
        cmp (fp_src2),y
        bne @done               ; first mismatch determines result
        dey
        bpl @loop
@done:
        rts

; =============================================================================
; fp_add - (fp_dst) = (fp_src1) + (fp_src2), 32 bytes, little-endian
;
; Iterates from byte 0 (LSB) up to byte 31 (MSB) - natural carry chain.
; Uses DEX to count down without clobbering carry flag.
; Carry output stored in fp_carry (1 = carry, 0 = no carry).
; Clobbers: A, X, Y
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
        dex                     ; DEX does not affect carry
        bne @loop
        lda #0
        adc #0
        sta fp_carry
        rts

; =============================================================================
; fp_sub - (fp_dst) = (fp_src1) - (fp_src2), 32 bytes, little-endian
;
; Iterates from byte 0 (LSB) up. Borrow in fp_carry (1 = borrow).
; Clobbers: A, X, Y
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
        sta fp_carry            ; 1 = borrow occurred, 0 = no borrow
        rts

; =============================================================================
; fp_is_zero - Test if (fp_src1) == 0
;
; Z flag set if all 32 bytes are zero.
; Clobbers: A, Y
; =============================================================================
fp_is_zero:
        ldy #0
        lda #0
@loop:
        ora (fp_src1),y
        iny
        cpy #32
        bne @loop
        cmp #0                  ; set Z flag based on accumulated OR
        rts

; =============================================================================
; fp_rshift1 - Right-shift (fp_src1) by 1 bit in place, little-endian
;
; For little-endian, MSB is byte 31. Start shifting from byte 31 downward.
; LSR the MSB first (clears carry into top), then ROR each subsequent byte.
; Clobbers: A, X, Y
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
;
; (fp_src1) * (fp_src2) -> fp_wide (64 bytes, little-endian)
;
; Optimization: REU DMA lookup + self-modifying accumulation code.
; For each outer byte src1[i], DMA the full multiply row from REU,
; then inner loop uses mul_dma_lo/hi[src2[j]] for instant lookup.
; Inner loop unrolled 2x to reduce branch overhead.
;
; Little-endian layout: src1[i]*src2[j] product placed at fp_wide[i+j].
; Clobbers: A, X, Y
; =============================================================================
fp_mul:
        ; 1. Zero the 64-byte product buffer
        ldx #63
        lda #0
@zero_wide:
        sta fp_wide,x
        dex
        bpl @zero_wide

        ; 2. Copy src2 to absolute buffer for indexed access
        ldy #31
@copy_src2:
        lda (fp_src2),y
        sta mul_src2_buf,y
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
        sta mul_cached_a        ; cache src1[i] for DMA row fetch

        ; DMA the multiplication row for src1[i] from REU
        jsr reu_fetch_mul_row

        ; Self-mod: patch accumulation addresses to base = fp_wide + i
        lda #<fp_wide
        clc
        adc fp_mul_i            ; A = low byte of (fp_wide + i)
        sta @accum_ld1+1
        sta @accum_st1+1
        sta @accum_ld1_b+1
        sta @accum_st1_b+1
        lda #>fp_wide
        adc #0                  ; handle page crossing
        sta @accum_ld1+2
        sta @accum_st1+2
        sta @accum_ld1_b+2
        sta @accum_st1_b+2

        ; For +1 accesses (high byte of product), base is fp_wide + i + 1
        lda #<(fp_wide+1)
        clc
        adc fp_mul_i
        sta @accum_ld2+1
        sta @accum_st2+1
        sta @accum_ld2_b+1
        sta @accum_st2_b+1
        lda #>(fp_wide+1)
        adc #0
        sta @accum_ld2+2
        sta @accum_st2+2
        sta @accum_ld2_b+2
        sta @accum_st2_b+2

        lda #0
        sta fp_mul_j

        ; ===== UNROLLED 2x INNER LOOP =====
@mul_inner:
        ; --- First copy: process src2[j] ---
        ldx fp_mul_j
        ldy mul_src2_buf,x      ; Y = src2[j]
        beq @next_j_first       ; skip if zero

        ; REU table lookup: src1[i] * src2[j]
        lda mul_dma_lo,y        ; lo byte of product
        sta poly_prod_lo
        lda mul_dma_hi,y        ; hi byte of product
        sta poly_prod_hi

        ; Add 16-bit product to fp_wide[i+j]
        ldx fp_mul_j

        clc
@accum_ld1:
        lda fp_wide,x           ; patched to fp_wide+i base
        adc poly_prod_lo
@accum_st1:
        sta fp_wide,x
@accum_ld2:
        lda fp_wide+1,x         ; patched to fp_wide+i+1 base
        adc poly_prod_hi
@accum_st2:
        sta fp_wide+1,x
        bcc @next_j_first

        ; Propagate carry (rare path)
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@prop_carry_a:
        cpx #64
        bcs @next_j_first
        sec
        lda fp_wide,x
        adc #0
        sta fp_wide,x
        inx
        bcs @prop_carry_a

@next_j_first:
        inc fp_mul_j            ; advance j, no exit check yet

        ; --- Second copy: process src2[j+1] ---
        ldx fp_mul_j
        ldy mul_src2_buf,x      ; Y = src2[j]
        beq @next_j             ; skip if zero

        ; REU table lookup
        lda mul_dma_lo,y
        sta poly_prod_lo
        lda mul_dma_hi,y
        sta poly_prod_hi

        ; Add 16-bit product to fp_wide[i+j]
        ldx fp_mul_j

        clc
@accum_ld1_b:
        lda fp_wide,x           ; patched to fp_wide+i base
        adc poly_prod_lo
@accum_st1_b:
        sta fp_wide,x
@accum_ld2_b:
        lda fp_wide+1,x         ; patched to fp_wide+i+1 base
        adc poly_prod_hi
@accum_st2_b:
        sta fp_wide+1,x
        bcc @next_j

        ; Propagate carry (rare path)
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@prop_carry_b:
        cpx #64
        bcs @next_j
        sec
        lda fp_wide,x
        adc #0
        sta fp_wide,x
        inx
        bcs @prop_carry_b

@next_j:
        inc fp_mul_j
        lda fp_mul_j
        cmp #32
        bcs @skip_zero
        jmp @mul_inner

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
;
; (fp_src1)^2 -> fp_wide (64 bytes)
;
; Cross terms (i < j): compute a[i]*a[j] once, double, then accumulate.
; Diagonal terms (i == i): compute a[i]^2 normally.
; Same self-modifying accumulation as fp_mul.
; Clobbers: A, X, Y
; =============================================================================
fp_sqr:
        ; 1. Zero the 64-byte product buffer
        ldx #63
        lda #0
@zero_wide:
        sta fp_wide,x
        dex
        bpl @zero_wide

        ; 2. Copy src1 to absolute buffer (src1 == src2 for squaring)
        ldy #31
@copy_src:
        lda (fp_src1),y
        sta mul_src2_buf,y
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
        sta mul_cached_a        ; cache a[i]

        ; DMA the multiplication row for a[i] from REU
        jsr reu_fetch_mul_row

        ; Self-mod: patch accumulation addresses to base = fp_wide + i
        lda #<fp_wide
        clc
        adc fp_mul_i
        sta @sqr_accum_ld1+1
        sta @sqr_accum_st1+1
        lda #>fp_wide
        adc #0
        sta @sqr_accum_ld1+2
        sta @sqr_accum_st1+2

        lda #<(fp_wide+1)
        clc
        adc fp_mul_i
        sta @sqr_accum_ld2+1
        sta @sqr_accum_st2+1
        lda #>(fp_wide+1)
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
        ldy mul_src2_buf,x      ; Y = a[j]
        bne @sqr_nonzero_j
        jmp @sqr_next_j
@sqr_nonzero_j:

        ; REU table lookup: a[i] * a[j]
        lda mul_dma_lo,y
        sta poly_prod_lo
        lda mul_dma_hi,y
        sta poly_prod_hi

        ; Double the product (cross terms counted twice)
        asl poly_prod_lo
        rol poly_prod_hi
        lda #0
        adc #0
        sta fp_sqr_extra        ; save 17th bit (0 or 1)

        ; Single addition of doubled product to fp_wide[i+j]
        ldx fp_mul_j

        clc
@sqr_accum_ld1:
        lda fp_wide,x           ; patched to fp_wide+i base
        adc poly_prod_lo
@sqr_accum_st1:
        sta fp_wide,x
@sqr_accum_ld2:
        lda fp_wide+1,x         ; patched to fp_wide+i+1 base
        adc poly_prod_hi
@sqr_accum_st2:
        sta fp_wide+1,x

        ; Capture accumulation carry and combine with shift carry
        lda #0
        adc fp_sqr_extra        ; A = accum_carry + shift_carry (0, 1, or 2)
        beq @sqr_next_j         ; both zero, skip

        ; Add combined carries to fp_wide[i+j+2]
        ldx fp_mul_i
        tay                     ; Y = combined carry value
        txa
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
        tya                     ; A = combined carry value
        clc
        adc fp_wide,x
        sta fp_wide,x
        bcc @sqr_next_j
        ; Propagate further carries
@sqr_prop1:
        inx
        cpx #64
        bcs @sqr_next_j
        sec
        lda fp_wide,x
        adc #0
        sta fp_wide,x
        bcs @sqr_prop1

@sqr_next_j:
        inc fp_mul_j
        lda fp_mul_j
        cmp #32
        bcs @sqr_skip_i
        jmp @sqr_inner

@sqr_skip_i:
        inc fp_mul_i
        lda fp_mul_i
        cmp #31                 ; i goes 0..30 (j needs room for i+1)
        bcs @sqr_cross_done
        jmp @sqr_outer
@sqr_cross_done:

        ; 4. Add diagonal terms: a[i]^2 at position 2*i
        lda #0
        sta fp_mul_i
@diag_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        beq @diag_skip          ; skip if a[i] == 0

        ; DMA row for a[i] (may already be cached for i=30, but safe to re-fetch)
        sta mul_cached_a
        jsr reu_fetch_mul_row

        ; Look up a[i]^2 from the DMA tables
        ldy mul_cached_a        ; Y = a[i]
        lda mul_dma_lo,y        ; lo byte of a[i]^2
        sta poly_prod_lo
        lda mul_dma_hi,y        ; hi byte of a[i]^2
        sta poly_prod_hi

        ; Add to fp_wide[2*i]
        lda fp_mul_i
        asl                     ; A = 2*i
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

        ; Propagate carry
@diag_prop:
        inx
        cpx #64
        bcs @diag_skip
        sec
        lda fp_wide,x
        adc #0
        sta fp_wide,x
        bcs @diag_prop

@diag_skip:
        inc fp_mul_i
        lda fp_mul_i
        cmp #32
        bcs @sqr_done
        jmp @diag_outer

@sqr_done:
        rts

; Scratch byte for squaring
fp_sqr_extra:   !byte 0
