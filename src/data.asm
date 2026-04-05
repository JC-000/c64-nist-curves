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
        !fill 32, 0            ; absolute copy of src2 for fast indexed access

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

; --- P-384 Solinas reduction scratch ---
fp384_red_tmp:
        !fill 49, 0
