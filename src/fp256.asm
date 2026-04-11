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

        ; DMA the multiplication row for src1[i] from REU (inlined)
        ; A already contains mul_cached_a from the sta above
        asl                     ; A = multiplier * 2, carry = bit 7
        sta reu_reu_hi
        lda #0
        adc #0                  ; bank = carry from shift
        sta reu_reu_bank
        lda #%10110001          ; execute + autoload + FETCH (REU->C64)
        sta reu_command

        ; Self-mod: patch accumulation addresses to base = fp_wide + i
        ; Patches both LSB and MSB of the 16-bit operand.
        ; All four bodies of the unrolled inner loop use the same base.
        lda #<fp_wide
        clc
        adc fp_mul_i            ; A = low byte of (fp_wide + i)
        sta @accum_ld1+1
        sta @accum_st1+1
        sta @accum_ld1_b+1
        sta @accum_st1_b+1
        sta @accum_ld1_c+1
        sta @accum_st1_c+1
        sta @accum_ld1_d+1
        sta @accum_st1_d+1
        lda #>fp_wide
        adc #0                  ; handle page crossing
        sta @accum_ld1+2
        sta @accum_st1+2
        sta @accum_ld1_b+2
        sta @accum_st1_b+2
        sta @accum_ld1_c+2
        sta @accum_st1_c+2
        sta @accum_ld1_d+2
        sta @accum_st1_d+2

        ; For +1 accesses (high byte of product), base is fp_wide + i + 1
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

        ldx #0                  ; X = j, kept in register throughout

        ; ===== UNROLLED 4x INNER LOOP =====
        ; X register holds j; fp_wide,X base is self-mod patched to fp_wide+i.
@mul_inner:
        ; --- Body A: process src2[j] ---
        ldy mul_src2_buf,x      ; Y = src2[j]
        beq @next_j_first       ; skip if zero
        clc
@accum_ld1:
        lda fp_wide,x           ; patched to fp_wide+i base
        adc mul_dma_lo,y
@accum_st1:
        sta fp_wide,x
@accum_ld2:
        lda fp_wide+1,x         ; patched to fp_wide+i+1 base
        adc mul_dma_hi,y
@accum_st2:
        sta fp_wide+1,x
        bcs @do_prop_a
@next_j_first:
        inx                     ; advance j

        ; --- Body B: process src2[j+1] ---
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

        ; --- Body C: process src2[j+2] ---
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

        ; --- Body D: process src2[j+3] ---
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

        ; --- Carry propagation blocks (rare path) ---
        ; Each block stashes X=j, computes fp_wide index = i+j+2,
        ; propagates carry, then restores X and jumps back inline.
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
        inc fp_wide,x           ; add the pending carry byte
        bne @carry_done_a       ; if no overflow, done
        inx
        bne @prop_carry_a       ; always (x<64)
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
;
; (fp_src1)^2 -> fp_wide (64 bytes)
;
; Strategy (deferred doubling):
;   1. Accumulate the undoubled cross-term sum S = sum_{i<j} a[i]*a[j]
;      into fp_wide at positions i+j, using exactly the same self-modifying
;      inner loop as fp_mul (no per-partial shifts, no 3-way carry).
;      Only 31*32/2 = 496 byte-muls are performed (vs 1024 in fp_mul).
;   2. Double fp_wide (64-byte ASL sweep) -> fp_wide holds 2*S.
;   3. Add diagonal terms a[i]^2 at position 2*i (one DMA fetch per i).
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
        ; Ensure padding bytes are zero (init-time zeroed, but be safe)
        lda #0
        sta mul_src2_buf+32
        sta mul_src2_buf+33
        sta mul_src2_buf+34

        ; 3. Cross terms (UNDOUBLED): accumulate sum_{i<j} a[i]*a[j]
        ;    into fp_wide at position (i+j). i runs 0..30.
        lda #0
        sta fp_mul_i
@sqr_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        bne @sqr_nonzero_i
        jmp @sqr_skip_i
@sqr_nonzero_i:
        sta mul_cached_a        ; cache a[i]

        ; DMA the multiplication row for a[i] from REU (inlined)
        ; A still contains a[i] from the sta above
        asl                     ; A = multiplier * 2, carry = bit 7
        sta reu_reu_hi
        lda #0
        adc #0                  ; bank = carry from shift
        sta reu_reu_bank
        lda #%10110001          ; execute + autoload + FETCH (REU->C64)
        sta reu_command

        ; Self-mod: patch accumulation addresses to base = fp_wide + i
        ; All four unrolled bodies share the same base.
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

        ; X = j, starts at i+1, kept in register through all 4 bodies.
        ; Base address for accumulation was patched to fp_wide+i above, so
        ; fp_wide,X accesses fp_wide+i+j = fp_wide+2i+1 on the first iteration.
        ldx fp_mul_i
        inx

        ; Quad count = ceil((32 - (i+1)) / 4) = ceil((31 - i) / 4)
        ;            = floor((34 - i) / 4).
        ; Bounds iterations of the 4x-unrolled inner loop so we don't waste
        ; body executions past j=31. mul_src2_buf[32..34] is zero-padded so
        ; any tail over-reads within the final quad take the beq fast-skip path.
        lda #34
        sec
        sbc fp_mul_i
        lsr
        lsr
        sta fp_sqr_pairs        ; reuses the old fp_sqr_extra byte slot

        ; ===== UNROLLED 4x INNER LOOP (bounded by fp_sqr_pairs) =====
@sqr_inner:
        ; --- Body A ---
        ldy mul_src2_buf,x
        beq @sqr_next_j_first
        clc
@sqr_accum_ld1:
        lda fp_wide,x           ; patched fp_wide+i,X
        adc mul_dma_lo,y
@sqr_accum_st1:
        sta fp_wide,x
@sqr_accum_ld2:
        lda fp_wide+1,x         ; patched fp_wide+i+1,X
        adc mul_dma_hi,y
@sqr_accum_st2:
        sta fp_wide+1,x
        bcs @sqr_do_prop_a
@sqr_next_j_first:
        inx

        ; --- Body B ---
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

        ; --- Body C ---
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

        ; --- Body D ---
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

        ; --- Carry propagation blocks (rare path) ---
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
        cmp #31                 ; i goes 0..30 (j needs room for i+1)
        bcs @sqr_cross_done
        jmp @sqr_outer
@sqr_cross_done:

        ; 4. Double the accumulated cross-term sum: fp_wide <<= 1 (64 bytes).
        ; Y indexes fp_wide[0..63] (INY does not touch C).
        ; X counts down 64..1 as the loop counter (DEX does not touch C).
        ; Together they preserve the rolling carry across all 64 rols.
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
        ; any carry out of bit 63 is discarded (sum fits in 64 bytes)

        ; 5. Add diagonal terms: a[i]^2 at position 2*i
        lda #0
        sta fp_mul_i
@diag_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        beq @diag_skip          ; skip if a[i] == 0

        ; DMA row for a[i] (may already be cached for i=30, but safe to re-fetch)
        sta mul_cached_a
        ; Inlined REU DMA fetch; A still contains a[i]
        asl
        sta reu_reu_hi
        lda #0
        adc #0
        sta reu_reu_bank
        lda #%10110001
        sta reu_command

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

; Scratch byte for squaring (quad counter for fp_sqr inner loop)
fp_sqr_pairs:   !byte 0
fp_sqr_extra:   !byte 0         ; orphaned (kept so layout shift is zero)
