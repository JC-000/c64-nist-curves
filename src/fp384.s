.setcpu "6502"

; =============================================================================
; fp384.s - P-384 48-byte field arithmetic (little-endian)
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

; --- Imports: ZP ---
.importzp fp_src1, fp_src2, fp_dst, fp_carry, fp_mul_i, fp_mul_j

; --- Imports: data ---
.import fp384_wide, mul_cached_a, poly_prod_lo, poly_prod_hi
.import mul_dma_lo, mul_dma_hi

; --- Imports: constants ---
.import reu_reu_hi, reu_reu_bank, reu_command
.import reu_reu_lo, reu_addr_ctrl     ; issue #33-class defence

; --- REU layout contract (SPEC §3) ---
.import LIB_NISTCURVES_REU_BANK_MUL

; --- Exports ---
.export fp_copy_384, fp_zero_384, fp_cmp_384, fp_add_384, fp_sub_384
.export fp_is_zero_384, fp_rshift1_384, fp_mul_384, fp_sqr_384

.segment "CODE"

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
        ; --- Defensive REU register init (issue #33-class defence;
        ; see c64-x25519 commit 817f525). Per-row DMA below trusts
        ; reu_reu_lo ($DF04) and reu_addr_ctrl ($DF0A) are still 0
        ; from reu_mul_init's tail. Re-establish them so caller residue
        ; cannot silently route the fetch to the wrong REU offset.
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

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

        ; DMA the multiplication row for src1[i] from REU (inlined)
        ; A already contains mul_cached_a
        asl                    ; A = multiplier * 2, carry = bit 7
        sta reu_reu_hi
        lda #<LIB_NISTCURVES_REU_BANK_MUL
        adc #0                 ; bank = MUL_BASE + carry from shift
        sta reu_reu_bank
        lda #%10110001         ; execute + autoload + FETCH (REU->C64)
        sta reu_command

        ; Self-mod: patch accumulation addresses to base = fp384_wide + i
        ; fp384_wide is in absolute memory (crosses pages), so patch both bytes.
        lda #<fp384_wide
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
        lda #>fp384_wide
        adc #0
        sta @accum_ld1+2
        sta @accum_st1+2
        sta @accum_ld1_b+2
        sta @accum_st1_b+2
        sta @accum_ld1_c+2
        sta @accum_st1_c+2
        sta @accum_ld1_d+2
        sta @accum_st1_d+2

        ; +1 accesses: base is fp384_wide + i + 1
        lda #<(fp384_wide+1)
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
        lda #>(fp384_wide+1)
        adc #0
        sta @accum_ld2+2
        sta @accum_st2+2
        sta @accum_ld2_b+2
        sta @accum_st2_b+2
        sta @accum_ld2_c+2
        sta @accum_st2_c+2
        sta @accum_ld2_d+2
        sta @accum_st2_d+2

        ldx #0                 ; X = j, kept in register throughout

        ; ===== UNROLLED 4x INNER LOOP =====
@mul_inner:
        ; --- Body A: process src2[j] ---
        ldy mul_src2_buf_384,x
        beq @next_j_first
        clc
@accum_ld1:
        lda fp384_wide,x       ; patched base = fp384_wide + i
        adc mul_dma_lo,y
@accum_st1:
        sta fp384_wide,x
@accum_ld2:
        lda fp384_wide+1,x     ; patched base = fp384_wide + i + 1
        adc mul_dma_hi,y
@accum_st2:
        sta fp384_wide+1,x
        bcs @do_prop_a
@next_j_first:
        inx

        ; --- Body B: process src2[j+1] ---
        ldy mul_src2_buf_384,x
        beq @next_j_second
        clc
@accum_ld1_b:
        lda fp384_wide,x
        adc mul_dma_lo,y
@accum_st1_b:
        sta fp384_wide,x
@accum_ld2_b:
        lda fp384_wide+1,x
        adc mul_dma_hi,y
@accum_st2_b:
        sta fp384_wide+1,x
        bcs @do_prop_b
@next_j_second:
        inx

        ; --- Body C: process src2[j+2] ---
        ldy mul_src2_buf_384,x
        beq @next_j_third
        clc
@accum_ld1_c:
        lda fp384_wide,x
        adc mul_dma_lo,y
@accum_st1_c:
        sta fp384_wide,x
@accum_ld2_c:
        lda fp384_wide+1,x
        adc mul_dma_hi,y
@accum_st2_c:
        sta fp384_wide+1,x
        bcs @do_prop_c
@next_j_third:
        inx

        ; --- Body D: process src2[j+3] ---
        ldy mul_src2_buf_384,x
        beq @next_j
        clc
@accum_ld1_d:
        lda fp384_wide,x
        adc mul_dma_lo,y
@accum_st1_d:
        sta fp384_wide,x
@accum_ld2_d:
        lda fp384_wide+1,x
        adc mul_dma_hi,y
@accum_st2_d:
        sta fp384_wide+1,x
        bcs @do_prop_d
@next_j:
        inx
        cpx #48
        bcc @mul_inner
        jmp @skip_zero

        ; --- Carry propagation blocks (rare path) ---
@do_prop_a:
        stx fp_mul_j
        lda fp_mul_i
        clc
        adc fp_mul_j
        clc
        adc #2
        tax
@prop_carry_a:
        cpx #96
        bcs @carry_done_a
        inc fp384_wide,x
        bne @carry_done_a
        inx
        bne @prop_carry_a       ; always (x<96)
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
        cpx #96
        bcs @carry_done_b
        inc fp384_wide,x
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
        cpx #96
        bcs @carry_done_c
        inc fp384_wide,x
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
        cpx #96
        bcs @carry_done_d
        inc fp384_wide,x
        bne @carry_done_d
        inx
        bne @prop_carry_d
@carry_done_d:
        ldx fp_mul_j
        jmp @next_j

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
;
; Strategy (deferred doubling):
;   1. Accumulate undoubled cross-term sum S = sum_{i<j} a[i]*a[j] into
;      fp384_wide at positions i+j (mirrors fp_mul_384's inner loop exactly).
;      Only 47*48/2 = 1128 byte-muls (vs 2304 in fp_mul_384).
;   2. Double fp384_wide via a single 96-byte ASL sweep -> 2*S.
;   3. Add diagonal terms a[i]^2 at position 2*i.
; Clobbers: A, X, Y
; =============================================================================
fp_sqr_384:
        ; --- Defensive REU register init (issue #33-class defence;
        ; see fp_mul_384 above and c64-x25519 commit 817f525).
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        ; 1. Zero the 96-byte product buffer
        ldx #95
        lda #0
@zero_wide:
        sta fp384_wide,x
        dex
        bpl @zero_wide

        ; 2. Copy src1 to absolute buffer (48 bytes, 3 zero-pad at [48..50])
        ldy #47
@copy_src:
        lda (fp_src1),y
        sta mul_src2_buf_384,y
        dey
        bpl @copy_src
        lda #0
        sta mul_src2_buf_384+48
        sta mul_src2_buf_384+49
        sta mul_src2_buf_384+50

        ; 3. Cross terms (UNDOUBLED): sum_{i<j} a[i]*a[j] at position i+j
        lda #0
        sta fp_mul_i
@sqr_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        bne @sqr_nonzero_i
        jmp @sqr_skip_i
@sqr_nonzero_i:
        sta mul_cached_a

        ; DMA mul row for a[i] (inlined)
        asl
        sta reu_reu_hi
        lda #<LIB_NISTCURVES_REU_BANK_MUL
        adc #0
        sta reu_reu_bank
        lda #%10110001
        sta reu_command

        ; Self-mod: patch accumulation addresses to base = fp384_wide + i
        lda #<fp384_wide
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
        lda #>fp384_wide
        adc #0
        sta @sqr_accum_ld1+2
        sta @sqr_accum_st1+2
        sta @sqr_accum_ld1_b+2
        sta @sqr_accum_st1_b+2
        sta @sqr_accum_ld1_c+2
        sta @sqr_accum_st1_c+2
        sta @sqr_accum_ld1_d+2
        sta @sqr_accum_st1_d+2

        lda #<(fp384_wide+1)
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
        lda #>(fp384_wide+1)
        adc #0
        sta @sqr_accum_ld2+2
        sta @sqr_accum_st2+2
        sta @sqr_accum_ld2_b+2
        sta @sqr_accum_st2_b+2
        sta @sqr_accum_ld2_c+2
        sta @sqr_accum_st2_c+2
        sta @sqr_accum_ld2_d+2
        sta @sqr_accum_st2_d+2

        ; j starts at i+1, pinned in X
        ldx fp_mul_i
        inx                    ; X = j = i+1

        ; Quad count = ceil((48 - (i+1)) / 4) = ceil((47 - i) / 4)
        ;            = floor((50 - i) / 4).
        lda #50
        sec
        sbc fp_mul_i
        lsr
        lsr
        sta fp384_sqr_pairs

        ; ===== UNROLLED 4x INNER LOOP (bounded by fp384_sqr_pairs) =====
@sqr_inner:
        ; --- Body A ---
        ldy mul_src2_buf_384,x
        beq @sqr_next_j_first
        clc
@sqr_accum_ld1:
        lda fp384_wide,x       ; patched base = fp384_wide + i
        adc mul_dma_lo,y
@sqr_accum_st1:
        sta fp384_wide,x
@sqr_accum_ld2:
        lda fp384_wide+1,x     ; patched base = fp384_wide + i + 1
        adc mul_dma_hi,y
@sqr_accum_st2:
        sta fp384_wide+1,x
        bcs @sqr_do_prop_a
@sqr_next_j_first:
        inx

        ; --- Body B ---
        ldy mul_src2_buf_384,x
        beq @sqr_next_j_second
        clc
@sqr_accum_ld1_b:
        lda fp384_wide,x
        adc mul_dma_lo,y
@sqr_accum_st1_b:
        sta fp384_wide,x
@sqr_accum_ld2_b:
        lda fp384_wide+1,x
        adc mul_dma_hi,y
@sqr_accum_st2_b:
        sta fp384_wide+1,x
        bcs @sqr_do_prop_b
@sqr_next_j_second:
        inx

        ; --- Body C ---
        ldy mul_src2_buf_384,x
        beq @sqr_next_j_third
        clc
@sqr_accum_ld1_c:
        lda fp384_wide,x
        adc mul_dma_lo,y
@sqr_accum_st1_c:
        sta fp384_wide,x
@sqr_accum_ld2_c:
        lda fp384_wide+1,x
        adc mul_dma_hi,y
@sqr_accum_st2_c:
        sta fp384_wide+1,x
        bcs @sqr_do_prop_c
@sqr_next_j_third:
        inx

        ; --- Body D ---
        ldy mul_src2_buf_384,x
        beq @sqr_next_j
        clc
@sqr_accum_ld1_d:
        lda fp384_wide,x
        adc mul_dma_lo,y
@sqr_accum_st1_d:
        sta fp384_wide,x
@sqr_accum_ld2_d:
        lda fp384_wide+1,x
        adc mul_dma_hi,y
@sqr_accum_st2_d:
        sta fp384_wide+1,x
        bcs @sqr_do_prop_d
@sqr_next_j:
        inx
        dec fp384_sqr_pairs
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
        cpx #96
        bcs @sqr_carry_done_a
        inc fp384_wide,x
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
        cpx #96
        bcs @sqr_carry_done_b
        inc fp384_wide,x
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
        cpx #96
        bcs @sqr_carry_done_c
        inc fp384_wide,x
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
        cpx #96
        bcs @sqr_carry_done_d
        inc fp384_wide,x
        bne @sqr_carry_done_d
        inx
        bne @sqr_prop_carry_d
@sqr_carry_done_d:
        ldx fp_mul_j
        jmp @sqr_next_j

@sqr_skip_i:
        inc fp_mul_i
        lda fp_mul_i
        cmp #47                 ; i goes 0..46 (j needs room for i+1)
        bcs @sqr_cross_done
        jmp @sqr_outer
@sqr_cross_done:

        ; 4. Double the cross-term sum: fp384_wide <<= 1 (96 bytes).
        clc
        ldy #0
        ldx #96
@sqr_double:
        lda fp384_wide,y
        rol
        sta fp384_wide,y
        iny
        dex
        bne @sqr_double

        ; 5. Add diagonal terms: a[i]^2 at position 2*i
        lda #0
        sta fp_mul_i
@diag_outer:
        ldy fp_mul_i
        lda (fp_src1),y
        beq @diag_skip

        sta mul_cached_a
        ; Inlined REU row fetch (mirrors fp_sqr in fp256.s; saves the
        ; ~12-cy jsr/rts round trip × 48 diag iterations per call).
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
        inc fp384_wide,x
        beq @diag_prop

@diag_skip:
        inc fp_mul_i
        lda fp_mul_i
        cmp #48
        bcs @sqr_done
        jmp @diag_outer

@sqr_done:
        rts

.segment "BSS"

; Scratch byte for squaring
fp384_sqr_extra:  .res 1

; Absolute copy buffer for 48-byte src2 during multiply/square.
; Includes three bytes of zero padding so the squaring 4x-unroll can safely
; read indices 48..50 when the residual length isn't a multiple of 4
mul_src2_buf_384:
        .res 51

; Scratch for squaring 4x unroll quad counter
fp384_sqr_pairs:  .res 1
