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
mul_cached_a:
        !byte 0                ; cached src1[i] for inlined multiply
mul_src2_buf:
        !fill 35, 0            ; absolute copy of src2 for fast indexed access
                               ; (32 bytes + 3 pad zeros so fp_sqr 4x-unroll
                               ; can over-read past j=31 into zeros for fast-skip)

; --- REU DMA target buffers (page-aligned for LDA abs,Y without penalty) ---
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

; --- wNAF-5 scratch (shared between P-256 and P-384 scalar mul) ---
; ec_naf_k: working scalar, little-endian, with headroom byte.
;   P-256 uses bytes 0..32 (33 bytes); P-384 uses bytes 0..48 (49 bytes).
; ec_naf_digits: signed 5-bit wNAF digits in {-15,-13,...,-1,0,1,...,15}.
;   Stored as two's-complement bytes. Up to 385 digits for P-384.
; ec_naf_len: number of digits actually produced.
ec_naf_k:       !fill 52, 0
ec_naf_digits:  !fill 400, 0
ec_naf_len:     !word 0           ; 16-bit (can be up to 385)

; --- Affine 2G storage used during wNAF precompute (persists across the
;     precompute loop since ec_affine_x/ec_affine_y is clobbered by each
;     jacobian_to_affine call). P-384 still uses these; P-256 does not.
ec_aff2g_256_x: !fill 32, 0
ec_aff2g_256_y: !fill 32, 0
ec_aff2g_384_x: !fill 48, 0
ec_aff2g_384_y: !fill 48, 0

; --- Lim-Lee 4-way fixed-base comb anchors for P-256.
;     A_p (p in 1..4) = 2^(64*(p-1)) * G stored as affine (X then Y, each
;     32 bytes, contiguous so a single base pointer can index both halves).
ec_anchor1_x:   !fill 32, 0
ec_anchor1_y:   !fill 32, 0
ec_anchor2_x:   !fill 32, 0
ec_anchor2_y:   !fill 32, 0
ec_anchor3_x:   !fill 32, 0
ec_anchor3_y:   !fill 32, 0
ec_anchor4_x:   !fill 32, 0
ec_anchor4_y:   !fill 32, 0

; --- Lim-Lee comb working scalar (32 bytes, little-endian transpose of
;     the BE input scalar). cm_k[0..7]   = K0 (least significant 64 bits),
;                            cm_k[8..15]  = K1,
;                            cm_k[16..23] = K2,
;                            cm_k[24..31] = K3 (most significant 64 bits).
cm_k:           !fill 32, 0
