.setcpu "6502"

; =============================================================================
; data_p384.s - RW buffers for P-384 field arithmetic, point ops, and ECDSA.
;
; Split from the monolithic data.s as part of #40 (SPEC §6 minimal-archive
; build targets). All field elements stored LITTLE-ENDIAN (byte 0 = LSB)
; unless noted; this matches 6502 carry propagation.
;
; EXCLUDES the P-384 Lim-Lee fixed-base comb anchors and working scalar
; (those live in data_p384_limlee.s so the variable-base-verify-only
; archive lib-p384-verify can drop them). Also note: the small fp384
; BSS block hosted by fp384.s (mul_src2_buf_384) is NOT in this file --
; it lives in LIB_NISTCURVES_P384_BSS via fp384.s.
; =============================================================================

.segment "LIB_NISTCURVES_P384_DATA_BSS"

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

; --- P-384 J+J point-add scratch (mirrors ec_jj_tmp; see note above). ---
.export ec384_jj_tmp
ec384_jj_tmp: .res 48, 0

; --- P-384 affine output ---
.export ec384_affine_x
ec384_affine_x: .res 48, 0
.export ec384_affine_y
ec384_affine_y: .res 48, 0

; --- P-384 variable-base scalar-mul input (affine, 48 bytes each, LE).
;     Consumed by ec_scalar_mul_var_384 (ECDSA-verify building block).
.export ec_base384_x
ec_base384_x:   .res 48, 0
.export ec_base384_y
ec_base384_y:   .res 48, 0

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

; --- ECDSA verify scratch (P-384). All 48-byte little-endian unless noted.
;     Consumed only by ecdsa_verify_384 in src/ecdsa384.s.
.export ecdsa384_r
ecdsa384_r:     .res 48, 0      ; LE r (byte-reversed from BE input)
.export ecdsa384_s
ecdsa384_s:     .res 48, 0      ; LE s
.export ecdsa384_h
ecdsa384_h:     .res 48, 0      ; LE message hash
.export ecdsa384_qx
ecdsa384_qx:    .res 48, 0      ; LE public-key affine X
.export ecdsa384_qy
ecdsa384_qy:    .res 48, 0      ; LE public-key affine Y
.export ecdsa384_w
ecdsa384_w:     .res 48, 0      ; LE w = s^-1 mod n
.export ecdsa384_u1
ecdsa384_u1:    .res 48, 0      ; LE u1 = h*w mod n
.export ecdsa384_u2
ecdsa384_u2:    .res 48, 0      ; LE u2 = r*w mod n
.export ecdsa384_u1_be
ecdsa384_u1_be: .res 48, 0      ; BE u1 (scalar_mul input)
.export ecdsa384_u2_be
ecdsa384_u2_be: .res 48, 0      ; BE u2 (scalar_mul_var input)
.export ecdsa384_u1g_jac
ecdsa384_u1g_jac: .res 144, 0   ; Jacobian u1*G (X@0, Y@48, Z@96); see
                                 ; ecdsa_u1g_jac for the rationale.

; --- fp_reverse48 staging buffer (one 48-byte scratch). Owned by ecdsa384.s.
.export fp_rev_buf_384
fp_rev_buf_384: .res 48, 0

; --- ecdsa_verify_with_message_384 scratch (P-384 hash-then-verify wrapper).
;     Saves the caller's struct base pointer across sha384_init/update/final,
;     since A/X are clobbered by every SHA call. Owned by ecdsa384.s and
;     non-re-entrant (matches the rest of the library's calling contract).
.export ecdsa384_msg_struct_ptr
ecdsa384_msg_struct_ptr: .res 2, 0
