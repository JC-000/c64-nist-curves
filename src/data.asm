; =============================================================================
; data.asm - Data buffers for P-256 field arithmetic and point operations
; All field elements stored LITTLE-ENDIAN (byte 0 = LSB)
; =============================================================================

; --- Field arithmetic working buffers (32 bytes each for P-256) ---
fp_wide:
        !fill 64, 0            ; 512-bit product from multiply
fp_tmp1:
        !fill 32, 0            ; temporary field element 1
fp_tmp2:
        !fill 32, 0            ; temporary field element 2
fp_tmp3:
        !fill 32, 0            ; temporary field element 3
fp_tmp4:
        !fill 32, 0            ; temporary field element 4

; --- Result registers ---
fp_r0:      !fill 32, 0        ; primary result register
fp_r1:      !fill 32, 0
fp_r2:      !fill 32, 0
fp_r3:      !fill 32, 0

; --- Modular inverse working space ---
fp_inv_u:   !fill 32, 0
fp_inv_v:   !fill 32, 0
fp_inv_x1:  !fill 32, 0
fp_inv_x2:  !fill 32, 0
fp_inv_iter: !word 0

; --- Point storage (Jacobian: X,Y,Z each 32 bytes = 96 bytes) ---
ec_p1:  !fill 96, 0            ; working point (Jacobian)
ec_p2:  !fill 96, 0            ; second point (affine X,Y; Z unused)
ec_p3:  !fill 96, 0            ; result point (Jacobian)

; --- Point math temporaries ---
ec_t1:  !fill 32, 0
ec_t2:  !fill 32, 0
ec_t3:  !fill 32, 0
ec_t4:  !fill 32, 0
ec_t5:  !fill 32, 0
ec_t6:  !fill 32, 0

; --- Affine output ---
ec_affine_x:    !fill 32, 0
ec_affine_y:    !fill 32, 0

; --- Scalar multiply state ---
ec_sc_byte:     !byte 0
ec_sc_mask:     !byte 0

; --- fe_mul optimization buffers ---
; NOT RE-ENTRANT. The buffers below (mul_cached_a, mul_src2_buf, mul_dma_lo,
; mul_dma_hi) plus the fp_src1/fp_src2/fp_dst zero-page slots are SHARED
; between all P-256 and P-384 field operations. Sequential calls across
; curves are fine, but the host program MUST NOT interleave them - e.g.
; calling fp_mod_mul_384 from an IRQ handler while fp_mod_mul is running
; in mainline will corrupt the cached operand / DMA target state. Serialize
; all calls into the library (mask IRQs around field ops or keep crypto on
; a single thread of control).
mul_cached_a:
        !byte 0                ; cached src1[i] for inlined multiply
mul_src2_buf:
        !fill 35, 0            ; absolute copy of src2 for fast indexed access
                               ; (32 bytes + 3 pad zeros so fp_sqr 4x-unroll
                               ; can over-read past j=31 into zeros for fast-skip)

; --- REU DMA target buffers (page-aligned for LDA abs,Y without penalty) ---
; SHARED between P-256 and P-384 code paths - see re-entrancy note above.
        !align 255, 0          ; align to next page boundary
mul_dma_lo:
        !fill 256, 0           ; DMA target: lo bytes of a*b for current a
mul_dma_hi:
        !fill 256, 0           ; DMA target: hi bytes of a*b for current a

; --- Solinas reduction scratch (for P-256 fast reduction) ---
; 33 bytes to hold intermediate sum with carry byte
fp_red_tmp:
        !fill 33, 0

; --- P-384 field arithmetic working buffers (48 bytes each) ---
fp384_wide:
        !fill 96, 0            ; 768-bit product from multiply
fp384_tmp1:
        !fill 48, 0
fp384_tmp2:
        !fill 48, 0
fp384_tmp3:
        !fill 48, 0
fp384_tmp4:
        !fill 48, 0

; --- P-384 result registers ---
fp384_r0:
        !fill 48, 0
fp384_r1:
        !fill 48, 0
fp384_r2:
        !fill 48, 0
fp384_r3:
        !fill 48, 0

; --- P-384 modular inverse working space ---
fp384_inv_u:
        !fill 48, 0
fp384_inv_v:
        !fill 48, 0
fp384_inv_x1:
        !fill 48, 0
fp384_inv_x2:
        !fill 48, 0

; --- P-384 point storage (144 bytes: X=48 + Y=48 + Z=48 Jacobian) ---
ec384_p1:
        !fill 144, 0
ec384_p2:
        !fill 144, 0
ec384_p3:
        !fill 144, 0

; --- P-384 point math temporaries ---
ec384_t1: !fill 48, 0
ec384_t2: !fill 48, 0
ec384_t3: !fill 48, 0
ec384_t4: !fill 48, 0
ec384_t5: !fill 48, 0
ec384_t6: !fill 48, 0

; --- P-384 affine output ---
ec384_affine_x: !fill 48, 0
ec384_affine_y: !fill 48, 0

; --- P-384 scalar multiply state ---
ec384_sc_byte:  !byte 0
ec384_sc_mask:  !byte 0
ec384_sc_nibble: !byte 0          ; current nibble index (0..95)
ec384_sc_half:  !byte 0           ; 0=high nibble, 1=low nibble
ec384_precomp_i: !byte 0          ; precompute loop counter

; --- P-384 Solinas reduction scratch ---
fp384_red_tmp:
        !fill 49, 0

; --- Affine 2G storage used during Lim-Lee comb precompute for P-256
;     (persists across the anchor-doubling loop since ec_affine_x/
;     ec_affine_y is clobbered by each jacobian_to_affine call).
ec_aff2g_256_x: !fill 32, 0
ec_aff2g_256_y: !fill 32, 0

; --- Lim-Lee 8-way fixed-base comb anchors for P-256 (Wave 7a, h=8).
;     A_p (p in 1..8) = 2^(32*(p-1)) * G stored as affine (X then Y, each
;     32 bytes, contiguous so a single base pointer can index both halves).
ec_anchor1_x:   !fill 32, 0
ec_anchor1_y:   !fill 32, 0
ec_anchor2_x:   !fill 32, 0
ec_anchor2_y:   !fill 32, 0
ec_anchor3_x:   !fill 32, 0
ec_anchor3_y:   !fill 32, 0
ec_anchor4_x:   !fill 32, 0
ec_anchor4_y:   !fill 32, 0
ec_anchor5_x:   !fill 32, 0
ec_anchor5_y:   !fill 32, 0
ec_anchor6_x:   !fill 32, 0
ec_anchor6_y:   !fill 32, 0
ec_anchor7_x:   !fill 32, 0
ec_anchor7_y:   !fill 32, 0
ec_anchor8_x:   !fill 32, 0
ec_anchor8_y:   !fill 32, 0

; --- Lim-Lee comb working scalar (32 bytes, little-endian transpose of
;     the BE input scalar). Wave 7a h=8: 8 sub-scalars of 32 bits (4 bytes)
;     each. cm_k[0..3] = K0 (LSBs), cm_k[4..7] = K1, ..., cm_k[28..31] = K7.
cm_k:           !fill 32, 0

; --- Lim-Lee 8-way fixed-base comb anchors for P-384 (Wave 7a, h=8).
;     A_p (p in 1..8) = 2^(48*(p-1)) * G stored as affine (X then Y, each
;     48 bytes, contiguous so a single base pointer can index both halves).
ec_anchor1_384_x: !fill 48, 0
ec_anchor1_384_y: !fill 48, 0
ec_anchor2_384_x: !fill 48, 0
ec_anchor2_384_y: !fill 48, 0
ec_anchor3_384_x: !fill 48, 0
ec_anchor3_384_y: !fill 48, 0
ec_anchor4_384_x: !fill 48, 0
ec_anchor4_384_y: !fill 48, 0
ec_anchor5_384_x: !fill 48, 0
ec_anchor5_384_y: !fill 48, 0
ec_anchor6_384_x: !fill 48, 0
ec_anchor6_384_y: !fill 48, 0
ec_anchor7_384_x: !fill 48, 0
ec_anchor7_384_y: !fill 48, 0
ec_anchor8_384_x: !fill 48, 0
ec_anchor8_384_y: !fill 48, 0

; --- Lim-Lee comb working scalar for P-384 (48 bytes, LE transpose of
;     BE input). Wave 7a h=8: 8 sub-scalars of 48 bits (6 bytes) each.
;     cm_k_384[0..5] = K0 (LSBs), ..., cm_k_384[42..47] = K7 (MSBs).
cm_k_384:       !fill 48, 0
