.setcpu "6502"

; =============================================================================
; points384_comb.s - P-384 Lim-Lee fixed-base comb (Wave 7a h=8).
;
; Hosts ec_precompute_384 and ec_scalar_mul_384 (fixed-base k*G) plus the
; sm384w_* helpers they use to stash/fetch 96-byte affine table entries
; in REU bank 2 at offset $4000. Excluded from lib-p384-verify (variable-
; base verify uses ec_scalar_mul_var_384 from points384_core.s instead).
;
; Split from src/points384.s as part of #40 (SPEC §6).
;
; All field elements are LITTLE-ENDIAN (byte 0 = LSB).
; Point layout: X = offset 0..47, Y = offset 48..95, Z = offset 96..143
; =============================================================================

.segment "LIB_NISTCURVES_P384_CODE"

; --- Exports ---
.export ec_precompute_384, ec_scalar_mul_384

; --- ZP imports ---
.importzp ec_scalar_ptr, zp_ptr1, zp_tmp1, zp_tmp2

; --- Core point ops (from points384_core.s) ---
.import ec_point_double_384, ec_point_add_384, ec_jacobian_to_affine_384

; --- mod384 imports ---
.import ec_set_modp_384

; --- curve384 imports ---
.import ec_gx384, ec_gy384

; --- data imports (P-384 core scratch) ---
.import ec384_p1, ec384_p2, ec384_p3
.import ec384_affine_x, ec384_affine_y
.import ec384_sc_mask, ec384_precomp_i

; --- data imports (P-384 Lim-Lee anchors) ---
.import ec_anchor1_384_x, ec_anchor2_384_x, ec_anchor3_384_x, ec_anchor4_384_x
.import ec_anchor5_384_x, ec_anchor6_384_x, ec_anchor7_384_x, ec_anchor8_384_x
.import ec_anchor1_384_y, ec_anchor2_384_y, ec_anchor3_384_y, ec_anchor4_384_y
.import ec_anchor5_384_y, ec_anchor6_384_y, ec_anchor7_384_y, ec_anchor8_384_y
.import cm_k_384
.import mul_dma_lo

; --- constants imports ---
.import reu_c64_lo, reu_c64_hi, reu_reu_lo, reu_reu_hi
.import reu_reu_bank, reu_len_lo, reu_len_hi
.import reu_addr_ctrl, reu_command

; --- REU layout contract (SPEC §3) ---
.import LIB_NISTCURVES_REU_BANK_COMB
.import LIB_NISTCURVES_REU_OFFSET_COMB_P384

; =============================================================================
; Wave 7a: Lim-Lee 8-way fixed-base comb for P-384 (h=8, a=48).
;
; Precompute: ec_precompute_384 builds anchors A_p = 2^(48*(p-1))*G for
; p = 1..8 and then T[j] (j=1..255) = sum over set bits of j of the
; corresponding anchors, stored as affine (X||Y, 96 bytes) in REU bank 2
; offset $4000, 256 * 96 = 24576 bytes.
;
; Index convention (IMPORTANT -- must match ec_scalar_mul_384):
;   bit p (value 1<<p) of j corresponds to anchor A_{p+1}, which is the
;   contribution of sub-scalar K_p. K_0 is the least significant 48-bit
;   chunk; K_7 is the most significant.
;
; Scalar mul: splits the 384-bit scalar into K7||...||K0 (6 bytes each),
; then runs 48 iterations. At iteration i (bit = 47..0) we form
;     idx = sum over p=0..7 of bit_i(K_p) << p
; double R and (if idx != 0) add T[idx]. The first non-zero idx seeds R.
; =============================================================================

; =============================================================================
; ec_precompute_384: Build the P-384 Lim-Lee comb table in REU bank 2
; at offset $4000. 256 * 96 = 24576 bytes. Slot 0 is never fetched.
; Uses 336 ec_point_double_384's (48*7 for seven anchor chains) plus
; 762 mixed adds (sum of (popcount(j)-1) for j=1..255) and 255 J->A
; conversions (table entries).
; =============================================================================
ec_precompute_384:
        jsr ec_set_modp_384

        ; ----- A1 = G affine: store directly into ec_anchor1_384_x/y. -----
        ldy #47
@cmp384_a1x:
        lda ec_gx384,y
        sta ec_anchor1_384_x,y
        dey
        bpl @cmp384_a1x
        ldy #47
@cmp384_a1y:
        lda ec_gy384,y
        sta ec_anchor1_384_y,y
        dey
        bpl @cmp384_a1y

        ; ----- Build A2..A8: each via 48 doublings from the previous. -----
        jsr @cmp384_load_p1_g           ; ec384_p1 = G (Jacobian, Z=1)

        ; A2 = 2^48 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa2x:
        lda ec384_affine_x,y
        sta ec_anchor2_384_x,y
        dey
        bpl @cmp384_sa2x
        ldy #47
@cmp384_sa2y:
        lda ec384_affine_y,y
        sta ec_anchor2_384_y,y
        dey
        bpl @cmp384_sa2y

        ; A3 = 2^96 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa3x:
        lda ec384_affine_x,y
        sta ec_anchor3_384_x,y
        dey
        bpl @cmp384_sa3x
        ldy #47
@cmp384_sa3y:
        lda ec384_affine_y,y
        sta ec_anchor3_384_y,y
        dey
        bpl @cmp384_sa3y

        ; A4 = 2^144 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa4x:
        lda ec384_affine_x,y
        sta ec_anchor4_384_x,y
        dey
        bpl @cmp384_sa4x
        ldy #47
@cmp384_sa4y:
        lda ec384_affine_y,y
        sta ec_anchor4_384_y,y
        dey
        bpl @cmp384_sa4y

        ; A5 = 2^192 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa5x:
        lda ec384_affine_x,y
        sta ec_anchor5_384_x,y
        dey
        bpl @cmp384_sa5x
        ldy #47
@cmp384_sa5y:
        lda ec384_affine_y,y
        sta ec_anchor5_384_y,y
        dey
        bpl @cmp384_sa5y

        ; A6 = 2^240 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa6x:
        lda ec384_affine_x,y
        sta ec_anchor6_384_x,y
        dey
        bpl @cmp384_sa6x
        ldy #47
@cmp384_sa6y:
        lda ec384_affine_y,y
        sta ec_anchor6_384_y,y
        dey
        bpl @cmp384_sa6y

        ; A7 = 2^288 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa7x:
        lda ec384_affine_x,y
        sta ec_anchor7_384_x,y
        dey
        bpl @cmp384_sa7x
        ldy #47
@cmp384_sa7y:
        lda ec384_affine_y,y
        sta ec_anchor7_384_y,y
        dey
        bpl @cmp384_sa7y

        ; A8 = 2^336 * G
        lda #48
        jsr @cmp384_double_p1_n
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ldy #47
@cmp384_sa8x:
        lda ec384_affine_x,y
        sta ec_anchor8_384_x,y
        dey
        bpl @cmp384_sa8x
        ldy #47
@cmp384_sa8y:
        lda ec384_affine_y,y
        sta ec_anchor8_384_y,y
        dey
        bpl @cmp384_sa8y

        ; ----- Build T[j] for j = 1..255 by subset-sum over 8 anchors. -----
        lda #1
        sta ec384_precomp_i
@cmp384_tloop:
        lda #0
        sta cm384_seeded
        lda ec384_precomp_i
        and #$01
        beq @cmp384_tj_b1
        lda #0
        jsr @cmp384_accum_anchor
@cmp384_tj_b1:
        lda ec384_precomp_i
        and #$02
        beq @cmp384_tj_b2
        lda #1
        jsr @cmp384_accum_anchor
@cmp384_tj_b2:
        lda ec384_precomp_i
        and #$04
        beq @cmp384_tj_b3
        lda #2
        jsr @cmp384_accum_anchor
@cmp384_tj_b3:
        lda ec384_precomp_i
        and #$08
        beq @cmp384_tj_b4
        lda #3
        jsr @cmp384_accum_anchor
@cmp384_tj_b4:
        lda ec384_precomp_i
        and #$10
        beq @cmp384_tj_b5
        lda #4
        jsr @cmp384_accum_anchor
@cmp384_tj_b5:
        lda ec384_precomp_i
        and #$20
        beq @cmp384_tj_b6
        lda #5
        jsr @cmp384_accum_anchor
@cmp384_tj_b6:
        lda ec384_precomp_i
        and #$40
        beq @cmp384_tj_b7
        lda #6
        jsr @cmp384_accum_anchor
@cmp384_tj_b7:
        lda ec384_precomp_i
        and #$80
        beq @cmp384_tj_done
        lda #7
        jsr @cmp384_accum_anchor
@cmp384_tj_done:
        ; ec384_p1 holds T[j] in Jacobian. Convert and stash.
        jsr @cmp384_p1_to_p3
        jsr ec_jacobian_to_affine_384
        ; Copy affine to ec384_p2 (stash helper reads ec384_p2).
        ldy #47
@cmp384_tj_cpx:
        lda ec384_affine_x,y
        sta ec384_p2,y
        dey
        bpl @cmp384_tj_cpx
        ldy #47
@cmp384_tj_cpy:
        lda ec384_affine_y,y
        sta ec384_p2+48,y
        dey
        bpl @cmp384_tj_cpy
        jsr sm384w_stash_p2
        inc ec384_precomp_i
        beq @cmp384_tdone               ; wraps 255->0 -> done
        jmp @cmp384_tloop
@cmp384_tdone:
        rts

; --- Internal helper: load ec384_p1 = G as Jacobian (Z=1). ---
@cmp384_load_p1_g:
        ldy #47
@cmp384_lpg_x:
        lda ec_gx384,y
        sta ec384_p1,y
        dey
        bpl @cmp384_lpg_x
        ldy #47
@cmp384_lpg_y:
        lda ec_gy384,y
        sta ec384_p1+48,y
        dey
        bpl @cmp384_lpg_y
        ldy #47
        lda #0
@cmp384_lpg_z:
        sta ec384_p1+96,y
        dey
        bpl @cmp384_lpg_z
        lda #1
        sta ec384_p1+96
        rts

; --- ec384_p1 = 2^A * ec384_p1 (A successive doublings). A in 1..255. ---
@cmp384_double_p1_n:
        sta ec384_sc_mask
@cmp384_dpn_loop:
        jsr ec_point_double_384
        ldy #0
@cmp384_dpn_cp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne @cmp384_dpn_cp
        dec ec384_sc_mask
        bne @cmp384_dpn_loop
        rts

; --- Copy ec384_p1 -> ec384_p3 (144 bytes). ---
@cmp384_p1_to_p3:
        ldy #0
@cmp384_pp3_cp:
        lda ec384_p1,y
        sta ec384_p3,y
        iny
        cpy #144
        bne @cmp384_pp3_cp
        rts

; --- Accumulate anchor[A] into ec384_p1 (Jacobian).
; If cm_seeded == 0 : copy anchor as ec384_p1 with Z=1, cm_seeded = 1.
; Else               : copy anchor into ec384_p2, call ec_point_add_384,
;                      copy ec384_p3 -> ec384_p1. A in 0..7.
@cmp384_accum_anchor:
        sta cm384_anch_idx
        lda cm384_seeded
        bne @cmp384_acc_add
        lda cm384_anch_idx
        jsr @cmp384_load_anchor_p1
        lda #1
        sta cm384_seeded
        rts
@cmp384_acc_add:
        lda cm384_anch_idx
        jsr @cmp384_load_anchor_p2
        jsr ec_point_add_384
        ldy #0
@cmp384_acc_cp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne @cmp384_acc_cp
        rts

; --- Load anchor[A] into ec384_p1 (Jacobian, Z=1). A in 0..7. ---
@cmp384_load_anchor_p1:
        asl
        tax
        lda @cmp384_anchor_tbl,x
        sta zp_ptr1
        lda @cmp384_anchor_tbl+1,x
        sta zp_ptr1+1
        ; Copy 48 X bytes from (zp_ptr1) to ec384_p1.
        ldy #47
@cmp384_lap1_x:
        lda (zp_ptr1),y
        sta ec384_p1,y
        dey
        bpl @cmp384_lap1_x
        ; Advance pointer by 48 to Y coordinate.
        lda zp_ptr1
        clc
        adc #48
        sta zp_ptr1
        bcc :+
        inc zp_ptr1+1
:
        ldy #47
@cmp384_lap1_y:
        lda (zp_ptr1),y
        sta ec384_p1+48,y
        dey
        bpl @cmp384_lap1_y
        ldy #47
        lda #0
@cmp384_lap1_z:
        sta ec384_p1+96,y
        dey
        bpl @cmp384_lap1_z
        lda #1
        sta ec384_p1+96
        rts

; --- Load anchor[A] into ec384_p2 (affine X,Y). A in 0..7. ---
@cmp384_load_anchor_p2:
        asl
        tax
        lda @cmp384_anchor_tbl,x
        sta zp_ptr1
        lda @cmp384_anchor_tbl+1,x
        sta zp_ptr1+1
        ldy #47
@cmp384_lap2_x:
        lda (zp_ptr1),y
        sta ec384_p2,y
        dey
        bpl @cmp384_lap2_x
        lda zp_ptr1
        clc
        adc #48
        sta zp_ptr1
        bcc :+
        inc zp_ptr1+1
:
        ldy #47
@cmp384_lap2_y:
        lda (zp_ptr1),y
        sta ec384_p2+48,y
        dey
        bpl @cmp384_lap2_y
        rts

@cmp384_anchor_tbl:
        .word ec_anchor1_384_x
        .word ec_anchor2_384_x
        .word ec_anchor3_384_x
        .word ec_anchor4_384_x
        .word ec_anchor5_384_x
        .word ec_anchor6_384_x
        .word ec_anchor7_384_x
        .word ec_anchor8_384_x

; =============================================================================
; ec_scalar_mul_384: ec384_p3 = k * G using an 8-way Lim-Lee fixed-base comb.
;
; k is a 48-byte scalar pointed to by (ec_scalar_ptr), BIG-ENDIAN. Split into
; K7||...||K0, each 48 bits (6 bytes). Uses the precompute table built by
; ec_precompute_384 in REU bank 2 offset $4000 (256 entries * 96 bytes).
;
; Index convention (matches ec_precompute_384):
;   idx bit p corresponds to sub-scalar K_p (bit p in j toggles anchor A_{p+1}).
; For iter bit b = 47..0:
;     idx = sum over p=0..7 of bit_b(K_p) << p
;     R = 2*R; if idx != 0: R += T[idx]   (first idx!=0 seeds R).
;
; Cost: 48 doublings + ~48 mixed adds (vs 96 doublings + ~90 adds for h=4).
; REQUIRES: ec_precompute_384 must have been called first.
; =============================================================================
ec_scalar_mul_384:
        ; --- Defensive REU register init (issue #33-class defence;
        ; see c64-x25519 commit 817f525). The per-row DMA in fp_mul_384/
        ; fp_sqr_384 trusts reu_reu_lo / reu_addr_ctrl remain 0 from
        ; reu_mul_init. Defence-in-depth at the public surface.
        lda #0
        sta reu_reu_lo
        sta reu_addr_ctrl

        ; --- Transpose 48-byte BE scalar -> cm_k_384 little-endian ---
        ; cm_k_384[0..5] = K0 (LSBs), cm_k_384[6..11] = K1, ..., cm_k_384[42..47] = K7.
        ldy #47                 ; BE source index
        ldx #0                  ; LE destination index
@cm384_xpose:
        lda (ec_scalar_ptr),y
        sta cm_k_384,x
        inx
        dey
        bpl @cm384_xpose

        ; --- Init state ---
        lda #5
        sta cm384_byte_off      ; bit 47 of each K_p lives in cm_k_384[5 + 6*p]
        lda #$80
        sta cm384_bit_mask
        lda #48
        sta cm384_loop_ctr
        lda #1
        sta cm384_r_inf

        jsr ec_set_modp_384

@cm384_loop:
        ; --- Double R (skip if still infinity) ---
        lda cm384_r_inf
        bne @cm384_skip_double
        jsr ec_point_double_384
        ldy #0
@cm384_dcp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne @cm384_dcp
@cm384_skip_double:

        ; --- Extract idx (8 bits) from current bit position, K7..K0 ---
        lda #0
        sta cm384_idx
        ldx cm384_byte_off

        lda cm_k_384+42,x       ; K7
        and cm384_bit_mask
        beq @cm384_b7z
        lda #$80
        ora cm384_idx
        sta cm384_idx
@cm384_b7z:
        lda cm_k_384+36,x       ; K6
        and cm384_bit_mask
        beq @cm384_b6z
        lda #$40
        ora cm384_idx
        sta cm384_idx
@cm384_b6z:
        lda cm_k_384+30,x       ; K5
        and cm384_bit_mask
        beq @cm384_b5z
        lda #$20
        ora cm384_idx
        sta cm384_idx
@cm384_b5z:
        lda cm_k_384+24,x       ; K4
        and cm384_bit_mask
        beq @cm384_b4z
        lda #$10
        ora cm384_idx
        sta cm384_idx
@cm384_b4z:
        lda cm_k_384+18,x       ; K3
        and cm384_bit_mask
        beq @cm384_b3z
        lda #$08
        ora cm384_idx
        sta cm384_idx
@cm384_b3z:
        lda cm_k_384+12,x       ; K2
        and cm384_bit_mask
        beq @cm384_b2z
        lda #$04
        ora cm384_idx
        sta cm384_idx
@cm384_b2z:
        lda cm_k_384+6,x        ; K1
        and cm384_bit_mask
        beq @cm384_b1z
        lda #$02
        ora cm384_idx
        sta cm384_idx
@cm384_b1z:
        lda cm_k_384+0,x        ; K0
        and cm384_bit_mask
        beq @cm384_b0z
        lda #$01
        ora cm384_idx
        sta cm384_idx
@cm384_b0z:

        ; --- Advance bit position ---
        lsr cm384_bit_mask
        bne @cm384_after_advance
        lda #$80
        sta cm384_bit_mask
        dec cm384_byte_off
@cm384_after_advance:

        ; --- If idx == 0, no addition this iter ---
        lda cm384_idx
        beq @cm384_after_add

        ; --- Fetch T[idx] affine into ec384_p2 ---
        lda cm384_idx
        jsr sm384w_fetch_to_p2

        ; --- If R was infinity, seed R = T[idx] and clear flag ---
        lda cm384_r_inf
        beq @cm384_real_add
        ldy #47
@cm384_seed_x:
        lda ec384_p2,y
        sta ec384_p1,y
        dey
        bpl @cm384_seed_x
        ldy #47
@cm384_seed_y:
        lda ec384_p2+48,y
        sta ec384_p1+48,y
        dey
        bpl @cm384_seed_y
        ldy #47
        lda #0
@cm384_seed_z:
        sta ec384_p1+96,y
        dey
        bpl @cm384_seed_z
        lda #1
        sta ec384_p1+96
        lda #0
        sta cm384_r_inf
        jmp @cm384_after_add

@cm384_real_add:
        jsr ec_point_add_384
        ldy #0
@cm384_acp:
        lda ec384_p3,y
        sta ec384_p1,y
        iny
        cpy #144
        bne @cm384_acp

@cm384_after_add:
        dec cm384_loop_ctr
        beq @cm384_done
        jmp @cm384_loop

@cm384_done:
        ; --- If R is still infinity, return all-zero point. ---
        lda cm384_r_inf
        beq @cm384_copy_out
        ldy #0
        lda #0
@cm384_zinf:
        sta ec384_p3,y
        iny
        cpy #144
        bne @cm384_zinf
        rts

@cm384_copy_out:
        ldy #0
@cm384_finc:
        lda ec384_p1,y
        sta ec384_p3,y
        iny
        cpy #144
        bne @cm384_finc
        rts

; --- Comb scalar-mul state vars (384-specific to avoid linker clash with points256) ---
cm384_byte_off:  .byte 0
cm384_bit_mask:  .byte 0
cm384_loop_ctr:  .byte 0
cm384_idx:       .byte 0
cm384_r_inf:     .byte 0
cm384_seeded:    .byte 0         ; precompute helper
cm384_anch_idx:  .byte 0         ; precompute helper

; -----------------------------------------------------------------------------
; sm384w_stash_p2: Stash ec384_p2 (96 bytes affine) to REU bank 2
; Input: ec384_precomp_i = table index (0..15)
; REU offset = $0400 + index * 96
; -----------------------------------------------------------------------------
sm384w_stash_p2:
        jsr sm384w_calc_reu_offset

        lda #<ec384_p2
        sta reu_c64_lo
        lda #>ec384_p2
        sta reu_c64_hi
        lda #96
        sta reu_len_lo
        lda #0
        sta reu_len_hi
        sta reu_addr_ctrl
        lda #%10110000           ; execute + autoload + STASH
        sta reu_command

        jsr sm384w_restore_reu
        rts

; -----------------------------------------------------------------------------
; sm384w_fetch_to_p2: Fetch T[A] affine (96 bytes) from REU into ec384_p2
; Input: A = table index (0..15)
; -----------------------------------------------------------------------------
sm384w_fetch_to_p2:
        sta ec384_precomp_i
        jsr sm384w_calc_reu_offset

        lda #<ec384_p2
        sta reu_c64_lo
        lda #>ec384_p2
        sta reu_c64_hi
        lda #96
        sta reu_len_lo
        lda #0
        sta reu_len_hi
        sta reu_addr_ctrl
        lda #%10110001           ; execute + autoload + FETCH
        sta reu_command

        jsr sm384w_restore_reu
        rts

; -----------------------------------------------------------------------------
; sm384w_calc_reu_offset: Set REU address registers for table index
; Input: ec384_precomp_i = index (0..255)
; Offset = $4000 + index * 96 = $4000 + index*64 + index*32  (16-bit result)
; Wave 7a: h=8 requires 16-bit table index * 96; max offset 255*96 = 24480,
; plus $4000 base = $9FA0, fits in 16 bits.
; -----------------------------------------------------------------------------
sm384w_calc_reu_offset:
        lda ec384_precomp_i
        asl
        asl
        asl
        asl
        asl
        sta zp_tmp1              ; low byte of i*32 (top 3 bits of i lost here)
        lda ec384_precomp_i
        lsr
        lsr
        lsr                      ; high byte of i*32
        sta zp_tmp2

        ; i*64 = (i*32)*2
        lda zp_tmp1
        asl
        sta reu_reu_lo
        lda zp_tmp2
        rol
        sta reu_reu_hi

        ; + i*32 -> i*96
        lda reu_reu_lo
        clc
        adc zp_tmp1
        sta reu_reu_lo
        lda reu_reu_hi
        adc zp_tmp2
        ; + P-384 comb-anchor base offset (high byte)
        clc
        adc #>LIB_NISTCURVES_REU_OFFSET_COMB_P384
        sta reu_reu_hi

        lda #<LIB_NISTCURVES_REU_BANK_COMB
        sta reu_reu_bank
        rts

; -----------------------------------------------------------------------------
; sm384w_restore_reu: Restore REU registers for multiply table access
; -----------------------------------------------------------------------------
sm384w_restore_reu:
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
