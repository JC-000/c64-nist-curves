.setcpu "6502"

; =============================================================================
; data.s - Data buffers for P-256 field arithmetic and point operations
; All field elements stored LITTLE-ENDIAN (byte 0 = LSB)
; =============================================================================

.segment "DATA"

; --- Field arithmetic working buffers (32 bytes each for P-256) ---
.export fp_wide
fp_wide:
        .res 64, 0            ; 512-bit product from multiply
.export fp_tmp1
fp_tmp1:
        .res 32, 0            ; temporary field element 1
.export fp_tmp2
fp_tmp2:
        .res 32, 0            ; temporary field element 2
.export fp_tmp3
fp_tmp3:
        .res 32, 0            ; temporary field element 3
.export fp_tmp4
fp_tmp4:
        .res 32, 0            ; temporary field element 4

; --- Result registers ---
.export fp_r0
fp_r0:      .res 32, 0        ; primary result register
.export fp_r1
fp_r1:      .res 32, 0
.export fp_r2
fp_r2:      .res 32, 0
.export fp_r3
fp_r3:      .res 32, 0

; --- Modular inverse working space ---
.export fp_inv_u
fp_inv_u:   .res 32, 0
.export fp_inv_v
fp_inv_v:   .res 32, 0
.export fp_inv_x1
fp_inv_x1:  .res 32, 0
.export fp_inv_x2
fp_inv_x2:  .res 32, 0
.export fp_inv_iter
fp_inv_iter: .res 2, 0

; --- Point storage (Jacobian: X,Y,Z each 32 bytes = 96 bytes) ---
.export ec_p1
ec_p1:  .res 96, 0            ; working point (Jacobian)
.export ec_p2
ec_p2:  .res 96, 0            ; second point (affine X,Y; Z unused)
.export ec_p3
ec_p3:  .res 96, 0            ; result point (Jacobian)

; --- Point math temporaries ---
.export ec_t1
ec_t1:  .res 32, 0
.export ec_t2
ec_t2:  .res 32, 0
.export ec_t3
ec_t3:  .res 32, 0
.export ec_t4
ec_t4:  .res 32, 0
.export ec_t5
ec_t5:  .res 32, 0
.export ec_t6
ec_t6:  .res 32, 0

; --- Affine output ---
.export ec_affine_x
ec_affine_x:    .res 32, 0
.export ec_affine_y
ec_affine_y:    .res 32, 0

; --- Scalar multiply state ---
.export ec_sc_byte
ec_sc_byte:     .byte 0
.export ec_sc_mask
ec_sc_mask:     .byte 0

; --- fe_mul optimization buffers ---
; NOT RE-ENTRANT. The buffers below (mul_cached_a, mul_src2_buf, mul_dma_lo,
; mul_dma_hi) plus the fp_src1/fp_src2/fp_dst zero-page slots are SHARED
; between all P-256 and P-384 field operations. Sequential calls across
; curves are fine, but the host program MUST NOT interleave them - e.g.
; calling fp_mod_mul_384 from an IRQ handler while fp_mod_mul is running
; in mainline will corrupt the cached operand / DMA target state. Serialize
; all calls into the library (mask IRQs around field ops or keep crypto on
; a single thread of control).
.export mul_cached_a
mul_cached_a:
        .byte 0                ; cached src1[i] for inlined multiply
.export mul_src2_buf
mul_src2_buf:
        .res 35, 0            ; absolute copy of src2 for fast indexed access
                               ; (32 bytes + 3 pad zeros so fp_sqr 4x-unroll
                               ; can over-read past j=31 into zeros for fast-skip)

; --- REU DMA target buffers (page-aligned for LDA abs,Y without penalty) ---
; SHARED between P-256 and P-384 code paths - see re-entrancy note above.
.segment "TABLES"
.export mul_dma_lo
mul_dma_lo:
        .res 256, 0           ; DMA target: lo bytes of a*b for current a
.export mul_dma_hi
mul_dma_hi:
        .res 256, 0           ; DMA target: hi bytes of a*b for current a

.segment "DATA"

; --- Solinas reduction scratch (for P-256 fast reduction) ---
; 33 bytes to hold intermediate sum with carry byte
.export fp_red_tmp
fp_red_tmp:
        .res 33, 0

; --- P-384 field arithmetic working buffers (48 bytes each) ---
.export fp384_wide
fp384_wide:
        .res 96, 0            ; 768-bit product from multiply
.export fp384_tmp1
fp384_tmp1:
        .res 48, 0
.export fp384_tmp2
fp384_tmp2:
        .res 48, 0
.export fp384_tmp3
fp384_tmp3:
        .res 48, 0
.export fp384_tmp4
fp384_tmp4:
        .res 48, 0

; --- P-384 result registers ---
.export fp384_r0
fp384_r0:
        .res 48, 0
.export fp384_r1
fp384_r1:
        .res 48, 0
.export fp384_r2
fp384_r2:
        .res 48, 0
.export fp384_r3
fp384_r3:
        .res 48, 0

; --- P-384 modular inverse working space ---
.export fp384_inv_u
fp384_inv_u:
        .res 48, 0
.export fp384_inv_v
fp384_inv_v:
        .res 48, 0
.export fp384_inv_x1
fp384_inv_x1:
        .res 48, 0
.export fp384_inv_x2
fp384_inv_x2:
        .res 48, 0

; --- P-384 point storage (144 bytes: X=48 + Y=48 + Z=48 Jacobian) ---
.export ec384_p1
ec384_p1:
        .res 144, 0
.export ec384_p2
ec384_p2:
        .res 144, 0
.export ec384_p3
ec384_p3:
        .res 144, 0

; --- P-384 point math temporaries ---
.export ec384_t1
ec384_t1: .res 48, 0
.export ec384_t2
ec384_t2: .res 48, 0
.export ec384_t3
ec384_t3: .res 48, 0
.export ec384_t4
ec384_t4: .res 48, 0
.export ec384_t5
ec384_t5: .res 48, 0
.export ec384_t6
ec384_t6: .res 48, 0

; --- P-384 affine output ---
.export ec384_affine_x
ec384_affine_x: .res 48, 0
.export ec384_affine_y
ec384_affine_y: .res 48, 0

; --- P-384 scalar multiply state ---
.export ec384_sc_byte
ec384_sc_byte:  .byte 0
.export ec384_sc_mask
ec384_sc_mask:  .byte 0
.export ec384_sc_nibble
ec384_sc_nibble: .byte 0          ; current nibble index (0..95)
.export ec384_sc_half
ec384_sc_half:  .byte 0           ; 0=high nibble, 1=low nibble
.export ec384_precomp_i
ec384_precomp_i: .byte 0          ; precompute loop counter

; --- P-384 Solinas reduction scratch ---
.export fp384_red_tmp
fp384_red_tmp:
        .res 49, 0

; --- Affine 2G storage used during Lim-Lee comb precompute for P-256
;     (persists across the anchor-doubling loop since ec_affine_x/
;     ec_affine_y is clobbered by each jacobian_to_affine call).
.export ec_aff2g_256_x
ec_aff2g_256_x: .res 32, 0
.export ec_aff2g_256_y
ec_aff2g_256_y: .res 32, 0

; --- Lim-Lee 8-way fixed-base comb anchors for P-256 (Wave 7a, h=8).
;     A_p (p in 1..8) = 2^(32*(p-1)) * G stored as affine (X then Y, each
;     32 bytes, contiguous so a single base pointer can index both halves).
.export ec_anchor1_x
ec_anchor1_x:   .res 32, 0
.export ec_anchor1_y
ec_anchor1_y:   .res 32, 0
.export ec_anchor2_x
ec_anchor2_x:   .res 32, 0
.export ec_anchor2_y
ec_anchor2_y:   .res 32, 0
.export ec_anchor3_x
ec_anchor3_x:   .res 32, 0
.export ec_anchor3_y
ec_anchor3_y:   .res 32, 0
.export ec_anchor4_x
ec_anchor4_x:   .res 32, 0
.export ec_anchor4_y
ec_anchor4_y:   .res 32, 0
.export ec_anchor5_x
ec_anchor5_x:   .res 32, 0
.export ec_anchor5_y
ec_anchor5_y:   .res 32, 0
.export ec_anchor6_x
ec_anchor6_x:   .res 32, 0
.export ec_anchor6_y
ec_anchor6_y:   .res 32, 0
.export ec_anchor7_x
ec_anchor7_x:   .res 32, 0
.export ec_anchor7_y
ec_anchor7_y:   .res 32, 0
.export ec_anchor8_x
ec_anchor8_x:   .res 32, 0
.export ec_anchor8_y
ec_anchor8_y:   .res 32, 0

; --- Lim-Lee comb working scalar (32 bytes, little-endian transpose of
;     the BE input scalar). Wave 7a h=8: 8 sub-scalars of 32 bits (4 bytes)
;     each. cm_k[0..3] = K0 (LSBs), cm_k[4..7] = K1, ..., cm_k[28..31] = K7.
.export cm_k
cm_k:           .res 32, 0

; --- Lim-Lee 8-way fixed-base comb anchors for P-384 (Wave 7a, h=8).
;     A_p (p in 1..8) = 2^(48*(p-1)) * G stored as affine (X then Y, each
;     48 bytes, contiguous so a single base pointer can index both halves).
.export ec_anchor1_384_x
ec_anchor1_384_x: .res 48, 0
.export ec_anchor1_384_y
ec_anchor1_384_y: .res 48, 0
.export ec_anchor2_384_x
ec_anchor2_384_x: .res 48, 0
.export ec_anchor2_384_y
ec_anchor2_384_y: .res 48, 0
.export ec_anchor3_384_x
ec_anchor3_384_x: .res 48, 0
.export ec_anchor3_384_y
ec_anchor3_384_y: .res 48, 0
.export ec_anchor4_384_x
ec_anchor4_384_x: .res 48, 0
.export ec_anchor4_384_y
ec_anchor4_384_y: .res 48, 0
.export ec_anchor5_384_x
ec_anchor5_384_x: .res 48, 0
.export ec_anchor5_384_y
ec_anchor5_384_y: .res 48, 0
.export ec_anchor6_384_x
ec_anchor6_384_x: .res 48, 0
.export ec_anchor6_384_y
ec_anchor6_384_y: .res 48, 0
.export ec_anchor7_384_x
ec_anchor7_384_x: .res 48, 0
.export ec_anchor7_384_y
ec_anchor7_384_y: .res 48, 0
.export ec_anchor8_384_x
ec_anchor8_384_x: .res 48, 0
.export ec_anchor8_384_y
ec_anchor8_384_y: .res 48, 0

; --- Lim-Lee comb working scalar for P-384 (48 bytes, LE transpose of
;     BE input). Wave 7a h=8: 8 sub-scalars of 48 bits (6 bytes) each.
;     cm_k_384[0..5] = K0 (LSBs), ..., cm_k_384[42..47] = K7 (MSBs).
.export cm_k_384
cm_k_384:       .res 48, 0
