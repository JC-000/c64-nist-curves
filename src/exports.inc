; =============================================================================
; exports.inc - Cross-module symbol dependency map for ca65 multi-object build
;
; Each module lists what it EXPORTS (defines) and IMPORTS (uses from others).
; Converter agents: add .export/.import declarations matching these lists.
; =============================================================================

; -----------------------------------------------------------------------------
; zp_config.s — Zero-page equates (shared via .exportzp / .importzp)
; EXPORTS (all are ZP equates):
;   proc_port, zp_tmp1, zp_tmp2, zp_ptr1, zp_ptr2,
;   fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_loop, fp_mul_i, fp_mul_j,
;   ec_scalar_ptr, poly_i, poly_j, poly_carry, poly_tmp
; IMPORTS: (none)
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; constants.s — Hardware equates (shared via .export / .import)
; EXPORTS:
;   chrout, getin, vic_ctrl1, vic_border, vic_bg,
;   cia1_ta_lo, cia1_ta_hi, cia1_cra,
;   screen_ram, color_ram, cassette_buf, jiffy_clock,
;   reu_status, reu_command, reu_c64_lo, reu_c64_hi,
;   reu_reu_lo, reu_reu_hi, reu_reu_bank,
;   reu_len_lo, reu_len_hi, reu_addr_ctrl,
;   FP256_SIZE, FP384_SIZE
; IMPORTS: (zp equates from zp_config)
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; mul_8x8.s
; EXPORTS: sqtab_init, mul_8x8, ct_mul_8x8 (alias), smc_sum_a_imm,
;          smc_diff_a_imm, poly_prod_lo, poly_prod_hi,
;          sqtab_lo, sqtab_hi, reu_fetch_mul_row
; IMPORTS:
;   ZP: poly_i, poly_j, poly_carry, poly_tmp (from zp_config)
;   data: mul_cached_a
;   constants: reu_reu_hi, reu_reu_bank, reu_command
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; data.s — All mutable data buffers
; EXPORTS:
;   fp_wide, fp_tmp1, fp_tmp2, fp_tmp3, fp_tmp4,
;   fp_r0, fp_r1, fp_r2, fp_r3,
;   fp_inv_u, fp_inv_v, fp_inv_x1, fp_inv_x2, fp_inv_iter,
;   ec_p1, ec_p2, ec_p3,
;   ec_t1, ec_t2, ec_t3, ec_t4, ec_t5, ec_t6, ec_jj_tmp,
;   ec_affine_x, ec_affine_y,
;   ec_base_x, ec_base_y,
;   ec_base384_x, ec_base384_y,
;   ec_sc_byte, ec_sc_mask,
;   mul_cached_a, mul_src2_buf, mul_dma_lo, mul_dma_hi,
;   fp_red_tmp,
;   fp384_wide, fp384_tmp1, fp384_tmp2, fp384_tmp3, fp384_tmp4,
;   fp384_r0, fp384_r1, fp384_r2, fp384_r3,
;   fp384_inv_u, fp384_inv_v, fp384_inv_x1, fp384_inv_x2,
;   ec384_p1, ec384_p2, ec384_p3,
;   ec384_t1, ec384_t2, ec384_t3, ec384_t4, ec384_t5, ec384_t6, ec384_jj_tmp,
;   ec384_affine_x, ec384_affine_y,
;   ec384_sc_byte, ec384_sc_mask, ec384_sc_nibble, ec384_sc_half,
;   ec384_precomp_i,
;   fp384_red_tmp,
;   ec_aff2g_256_x, ec_aff2g_256_y,
;   ec_anchor1_x..ec_anchor8_x, ec_anchor1_y..ec_anchor8_y,
;   cm_k,
;   ec_anchor1_384_x..ec_anchor8_384_x, ec_anchor1_384_y..ec_anchor8_384_y,
;   cm_k_384,
;   ecdsa_r, ecdsa_s, ecdsa_h, ecdsa_qx, ecdsa_qy,
;   ecdsa_w, ecdsa_u1, ecdsa_u2,
;   ecdsa_u1_be, ecdsa_u2_be,
;   ecdsa_u1g_jac,
;   fp_rev_buf,
;   ecdsa384_r, ecdsa384_s, ecdsa384_h, ecdsa384_qx, ecdsa384_qy,
;   ecdsa384_w, ecdsa384_u1, ecdsa384_u2,
;   ecdsa384_u1_be, ecdsa384_u2_be,
;   ecdsa384_u1g_jac,
;   fp_rev_buf_384,
;   ecdsa_inputs_256, ecdsa_result_256,
;   ecdsa_inputs_384, ecdsa_result_384,
;   ecdsa384_msg_struct_ptr, ecdsa_result_msg_384
; IMPORTS: (none — pure data)
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; fp256.s — 32-byte field arithmetic
; EXPORTS: fp_copy, fp_zero, fp_cmp, fp_add, fp_sub,
;          fp_is_zero, fp_rshift1, fp_mul, fp_sqr,
;          fp_sqr_pairs, fp_sqr_extra
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, fp_carry, fp_mul_i, fp_mul_j
;   data: fp_wide, mul_src2_buf, mul_dma_lo, mul_dma_hi,
;         mul_cached_a, poly_prod_lo, poly_prod_hi
;   constants: reu_reu_hi, reu_reu_bank, reu_command
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; mod256.s — P-256 modular operations
; EXPORTS: ec_p256, ec_n256,
;          fp_mod_add, fp_mod_sub, fp_mod_reduce256,
;          fp_mod_mul, fp_mod_mul_n, fp_mod_sqr, fp_mod_inv, fp_chk_one,
;          ec_set_modp, ec_set_modn, ec_mulp, ec_sqrp
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, fp_misc, fp_carry
;   fp256: fp_add, fp_sub, fp_cmp, fp_copy, fp_zero, fp_mul, fp_sqr,
;          fp_is_zero, fp_rshift1
;   data: fp_wide, fp_r0, fp_inv_u, fp_inv_v, fp_inv_x1, fp_inv_x2
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; curve256.s — P-256 curve parameters + test vectors (read-only data)
; EXPORTS: ec_a256, ec_b256, ec_gx256, ec_gy256,
;          ecdsa_test_privkey, ecdsa_test_k, ecdsa_test_hash,
;          ecdsa_test_r, ecdsa_test_s,
;          ecdsa_test_pubx, ecdsa_test_puby,
;          ecdsa_test_2gx, ecdsa_test_2gy
; IMPORTS: (none — pure data)
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; inv256.s — Fermat inversion (reference, 41x slower than binary GCD)
; EXPORTS: fp_mod_inv_fast
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_misc
;   mod256: ec_p256, fp_mod_sqr, fp_mod_mul
;   data: fp_tmp1, fp_r0
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; points256.s — P-256 point operations + scalar_mul + precompute
; EXPORTS: ec_point_double, ec_point_add, ec_point_add_jj,
;          ec_precompute_256, ec_scalar_mul, ec_scalar_mul_var,
;          ec_jacobian_to_affine
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, fp_misc, ec_scalar_ptr
;   fp256: fp_is_zero, fp_copy
;   mod256: ec_set_modp, ec_mulp, ec_sqrp,
;           fp_mod_add, fp_mod_sub, fp_mod_inv, ec_p256
;   curve256: ec_gx256, ec_gy256
;   data: ec_p1, ec_p2, ec_p3,
;         ec_t1..ec_t6, ec_affine_x, ec_affine_y,
;         ec_base_x, ec_base_y,
;         fp_r0, fp_tmp1,
;         ec_aff2g_256_x, ec_aff2g_256_y,
;         ec_anchor1_x..ec_anchor8_x, ec_anchor1_y..ec_anchor8_y,
;         cm_k, mul_dma_lo
;   constants: reu_c64_lo, reu_c64_hi, reu_reu_lo, reu_reu_hi,
;              reu_reu_bank, reu_len_lo, reu_len_hi,
;              reu_addr_ctrl, reu_command
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; ecdsa256.s — Packaged ECDSA verify for P-256 (FIPS 186-4)
; EXPORTS: ecdsa_verify_256, fp_reverse32
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, fp_misc, zp_ptr2, ec_scalar_ptr
;   fp256:  fp_copy, fp_zero, fp_cmp, fp_add, fp_sub, fp_is_zero
;   mod256: fp_mod_mul_n, fp_mod_inv, ec_set_modp, ec_set_modn, ec_n256
;   points256: ec_scalar_mul, ec_scalar_mul_var,
;              ec_point_add, ec_jacobian_to_affine
;   data:   fp_r0, ec_p1, ec_p2, ec_p3,
;           ec_affine_x, ec_affine_y,
;           ec_base_x, ec_base_y,
;           ecdsa_r, ecdsa_s, ecdsa_h, ecdsa_qx, ecdsa_qy,
;           ecdsa_w, ecdsa_u1, ecdsa_u2,
;           ecdsa_u1_be, ecdsa_u2_be,
;           ecdsa_u1g_jac, fp_rev_buf
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; ecdsa384.s — Packaged ECDSA verify for P-384 (FIPS 186-4)
; EXPORTS: ecdsa_verify_384, ecdsa_verify_with_message_384,
;          ecdsa_verify_with_msg_384_tramp, fp_reverse48
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, fp_misc, zp_ptr2, ec_scalar_ptr,
;       sha_src, sha_len
;   fp384:  fp_copy_384, fp_zero_384, fp_cmp_384, fp_sub_384, fp_is_zero_384
;   mod384: fp_mod_mul_n_384, fp_mod_inv_384,
;           ec_set_modp_384, ec_set_modn_384, ec_n384
;   points384: ec_scalar_mul_384, ec_scalar_mul_var_384,
;              ec_point_add_384, ec_jacobian_to_affine_384
;   sha384: sha384_init, sha384_update, sha384_final,
;           sha384_digest, sha384_msg_buf
;   data:   fp384_r0, ec384_p1, ec384_p2, ec384_p3,
;           ec384_affine_x, ec384_affine_y,
;           ec_base384_x, ec_base384_y,
;           ecdsa384_r, ecdsa384_s, ecdsa384_h, ecdsa384_qx, ecdsa384_qy,
;           ecdsa384_w, ecdsa384_u1, ecdsa384_u2,
;           ecdsa384_u1_be, ecdsa384_u2_be,
;           ecdsa384_u1g_jac, fp_rev_buf_384,
;           ecdsa384_msg_struct_ptr, ecdsa_inputs_384, ecdsa_result_msg_384
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; fp384.s — 48-byte field arithmetic
; EXPORTS: fp_copy_384, fp_zero_384, fp_cmp_384, fp_add_384, fp_sub_384,
;          fp_is_zero_384, fp_rshift1_384, fp_mul_384, fp_sqr_384
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, fp_carry, fp_mul_i, fp_mul_j
;   data: fp384_wide, mul_cached_a, poly_prod_lo, poly_prod_hi,
;         mul_dma_lo, mul_dma_hi
;   mul_8x8: reu_fetch_mul_row
;   constants: reu_reu_hi, reu_reu_bank, reu_command
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; mod384.s — P-384 modular operations
; EXPORTS: ec_p384, ec_n384,
;          fp_mod_add_384, fp_mod_sub_384, fp_mod_reduce384,
;          fp_mod_mul_384, fp_mod_mul_n_384,
;          fp_mod_sqr_384, fp_mod_inv_384, fp_chk_one_384,
;          ec_set_modp_384, ec_set_modn_384, ec_mulp_384, ec_sqrp_384
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, fp_misc, fp_carry
;   fp384: fp_add_384, fp_sub_384, fp_cmp_384, fp_copy_384, fp_zero_384,
;          fp_mul_384, fp_sqr_384
;   data: fp384_wide, fp384_r0,
;         fp384_inv_u, fp384_inv_v, fp384_inv_x1, fp384_inv_x2
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; curve384.s — P-384 curve parameters + test vectors (read-only data)
; EXPORTS: ec_a384, ec_b384, ec_gx384, ec_gy384,
;          ecdsa_test_2gx_384, ecdsa_test_2gy_384
; IMPORTS: (none — pure data)
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; points384.s — P-384 point operations + scalar_mul + precompute
; EXPORTS: ec_point_double_384, ec_point_add_384, ec_point_add_jj_384,
;          ec_precompute_384, ec_scalar_mul_384, ec_scalar_mul_var_384,
;          ec_jacobian_to_affine_384
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, fp_misc, ec_scalar_ptr
;   fp384: fp_is_zero_384, fp_copy_384
;   mod384: ec_set_modp_384, ec_mulp_384, ec_sqrp_384,
;           fp_mod_add_384, fp_mod_sub_384, fp_mod_inv_384, ec_p384
;   curve384: ec_gx384, ec_gy384
;   data: ec384_p1, ec384_p2, ec384_p3,
;         ec384_t1..ec384_t6, ec384_affine_x, ec384_affine_y,
;         ec_base384_x, ec_base384_y,
;         fp384_r0, fp384_tmp1,
;         ec_anchor1_384_x..ec_anchor8_384_x,
;         ec_anchor1_384_y..ec_anchor8_384_y,
;         cm_k_384, mul_dma_lo
;   constants: reu_c64_lo, reu_c64_hi, reu_reu_lo, reu_reu_hi,
;              reu_reu_bank, reu_len_lo, reu_len_hi,
;              reu_addr_ctrl, reu_command
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; sha384.s — Streaming SHA-384 (FIPS 180-4) hash
; EXPORTS: sha384_init, sha384_update, sha384_final,
;          sha384_digest, sha384_msg_buf
; IMPORTS:
;   ZP: sha_src, sha_len
;   data: sha_state, sha_w, sha_abcdefgh, sha_t,
;         sha_block_buf, sha_block_len, sha_total_len,
;         sha384_digest, sha384_msg_buf
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; main.s — Entry point, init, REU DMA routines, strings
; EXPORTS: reu_mul_init, bench_start, bench_stop,
;          bench_ticks, vic_blank, vic_unblank,
;          clrscr, print_string, print_hex_byte,
;          ecdsa_verify_256_tramp, ecdsa_verify_384_tramp
; IMPORTS:
;   ZP: proc_port, zp_ptr1, fp_misc
;   constants: chrout, screen_ram, jiffy_clock, vic_ctrl1,
;              reu_c64_lo, reu_c64_hi, reu_reu_lo, reu_reu_hi,
;              reu_reu_bank, reu_len_lo, reu_len_hi,
;              reu_addr_ctrl, reu_command
;   mul_8x8: sqtab_init, mul_8x8, poly_prod_lo, poly_prod_hi,
;            smc_sum_a_imm, smc_diff_a_imm
;   data: mul_dma_lo, mul_dma_hi, mul_cached_a,
;         ecdsa_inputs_256, ecdsa_result_256,
;         ecdsa_inputs_384, ecdsa_result_384
;   points256: ec_precompute_256
;   points384: ec_precompute_384
;   ecdsa256: ecdsa_verify_256
;   ecdsa384: ecdsa_verify_384
; -----------------------------------------------------------------------------
