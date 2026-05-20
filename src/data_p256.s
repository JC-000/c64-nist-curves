.setcpu "6502"

; =============================================================================
; data_p256.s - RW buffers for P-256 field arithmetic, point ops, and ECDSA.
;
; Split from the monolithic data.s as part of #40 (SPEC §6 minimal-archive
; build targets). All field elements stored LITTLE-ENDIAN (byte 0 = LSB)
; unless noted; this matches 6502 carry propagation.
;
; EXCLUDES the Lim-Lee fixed-base comb anchors and the comb working scalar
; (those live in data_p256_limlee.s so the variable-base-verify-only archive
; lib-p256-verify can drop them).
; =============================================================================

.segment "LIB_NISTCURVES_P256_BSS"

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

; --- J+J point-add scratch (used by ec_point_add_jj, src/points256.s).
;     One additional 32-byte slot beyond ec_t1..t6 needed for the
;     add-2007-bl formula. Not touched by the mixed-add ec_point_add
;     or by ec_point_double, so safe to share across nested calls
;     within scalar_mul / verify pipelines (which serialize anyway).
.export ec_jj_tmp
ec_jj_tmp: .res 32, 0

; --- Affine output ---
.export ec_affine_x
ec_affine_x:    .res 32, 0
.export ec_affine_y
ec_affine_y:    .res 32, 0

; --- Variable-base scalar-mul input (affine, 32 bytes each, LE).
;     Consumed by ec_scalar_mul_var (ECDSA-verify building block).
.export ec_base_x
ec_base_x:      .res 32, 0
.export ec_base_y
ec_base_y:      .res 32, 0

; --- Scalar multiply state ---
.export ec_sc_byte
ec_sc_byte:     .byte 0
.export ec_sc_mask
ec_sc_mask:     .byte 0

; --- Solinas reduction scratch (for P-256 fast reduction) ---
; 33 bytes to hold intermediate sum with carry byte
.export fp_red_tmp
fp_red_tmp:
        .res 33, 0

; --- ECDSA verify scratch (P-256). All 32-byte little-endian unless noted.
;     Consumed only by ecdsa_verify_256 in src/ecdsa256.s.
.export ecdsa_r
ecdsa_r:        .res 32, 0      ; LE r (byte-reversed from BE input)
.export ecdsa_s
ecdsa_s:        .res 32, 0      ; LE s
.export ecdsa_h
ecdsa_h:        .res 32, 0      ; LE message hash
.export ecdsa_qx
ecdsa_qx:       .res 32, 0      ; LE public-key affine X
.export ecdsa_qy
ecdsa_qy:       .res 32, 0      ; LE public-key affine Y
.export ecdsa_w
ecdsa_w:        .res 32, 0      ; LE w = s^-1 mod n
.export ecdsa_u1
ecdsa_u1:       .res 32, 0      ; LE u1 = h*w mod n
.export ecdsa_u2
ecdsa_u2:       .res 32, 0      ; LE u2 = r*w mod n
.export ecdsa_u1_be
ecdsa_u1_be:    .res 32, 0      ; BE u1 (scalar_mul input)
.export ecdsa_u2_be
ecdsa_u2_be:    .res 32, 0      ; BE u2 (scalar_mul_var input)
.export ecdsa_u1g_jac
ecdsa_u1g_jac:  .res 96, 0      ; Jacobian u1*G (X@0, Y@32, Z@64), held
                                 ; across the u2*Q scalar_mul so that the
                                 ; u1*G + u2*Q join can use ec_point_add_jj
                                 ; instead of paying for j2a inversion.
                                 ; Replaces the previous ecdsa_u1g_x/y
                                 ; affine pair (and the @ev_r_from_u1g
                                 ; short-circuit branch they served);
                                 ; the cofactor compare handles the
                                 ; u2*Q=infinity case uniformly.

; --- fp_reverse32 staging buffer (one 32-byte scratch). Owned by ecdsa256.s.
.export fp_rev_buf
fp_rev_buf:     .res 32, 0
