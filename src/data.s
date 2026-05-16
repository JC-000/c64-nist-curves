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

; --- Variable-base scalar-mul input (affine, 32 bytes each, LE).
;     Consumed by ec_scalar_mul_var (ECDSA-verify building block).
.export ec_base_x
ec_base_x:      .res 32, 0
.export ec_base_y
ec_base_y:      .res 32, 0

; --- P-384 variable-base scalar-mul input (affine, 48 bytes each, LE).
;     Consumed by ec_scalar_mul_var_384 (ECDSA-verify building block).
.export ec_base384_x
ec_base384_x:   .res 48, 0
.export ec_base384_y
ec_base384_y:   .res 48, 0

; --- Scalar multiply state ---
.export ec_sc_byte
ec_sc_byte:     .byte 0
.export ec_sc_mask
ec_sc_mask:     .byte 0

; --- w-NAF (width 4) variable-base scalar-mul scratch (P-256).
;     ec_scalar_mul_var uses a 4-bit signed w-NAF recoding:
;       digits[i] in {-7,-5,-3,-1,0,1,3,5,7}, stored as two's complement bytes.
;     A 256-bit scalar can recode to up to 257 digits (one final carry bit).
;     The precompute table holds {Q, 3Q, 5Q, 7Q} as affine (X,Y) pairs,
;     stored contiguously at var_tbl_base; entry index (|d|-1)/2 in 0..3
;     lives at offset index*64 with X at +0 and Y at +32. Mixed-add fetches
;     the table entry into ec_p2 and (if d<0) negates Y into var_neg_y.
;     The Jacobian "running accumulator" used during 3/5/7 precompute steps
;     is saved in var_jac_save between jacobian_to_affine and the next add.
.export var_wnaf
var_wnaf:       .res 257, 0
.export var_wnaf_len
var_wnaf_len:   .byte 0           ; low byte of 16-bit length (max 257)
.export var_wnaf_len_hi
var_wnaf_len_hi: .byte 0          ; high byte (effectively a 0/1 flag)
.export var_tbl_base
var_tbl_base:   .res 256, 0       ; 4 entries x (32 X + 32 Y) = 256 B
.export var_jac_save
var_jac_save:   .res 96, 0        ; 96-B Jacobian (X|Y|Z) staging
.export var_neg_y
var_neg_y:      .res 32, 0        ; -Y mod p for digit<0 mixed-add
.export var_zero32
var_zero32:     .res 32, 0        ; permanent 32-B zero (subtract source)

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

; --- w-NAF (width 4) variable-base scalar-mul scratch (P-384).
;     Same layout as the P-256 var_* buffers, scaled to 48-byte fields.
;     A 384-bit scalar can recode to up to 385 digits.
.export var384_wnaf
var384_wnaf:    .res 385, 0
.export var384_wnaf_len
var384_wnaf_len: .byte 0          ; low byte of length (256..385 needs hi=1)
.export var384_wnaf_len_hi
var384_wnaf_len_hi: .byte 0
.export var384_tbl_base
var384_tbl_base: .res 384, 0      ; 4 entries x (48 X + 48 Y) = 384 B
.export var384_jac_save
var384_jac_save: .res 144, 0      ; 144-B Jacobian staging
.export var384_neg_y
var384_neg_y:   .res 48, 0        ; -Y mod p for digit<0 mixed-add
.export var384_zero48
var384_zero48:  .res 48, 0        ; permanent 48-B zero
; --- 2Q affine staging used during v384_precompute. ec_point_double_384
;     and ec_point_add_384 clobber ec384_t1..t6, so the 2Q affine
;     coordinates can't live there across the precompute sequence.
.export var384_2q_x
var384_2q_x:    .res 48, 0
.export var384_2q_y
var384_2q_y:    .res 48, 0

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
.export ecdsa_u1g_x
ecdsa_u1g_x:    .res 32, 0      ; LE affine X of u1*G
.export ecdsa_u1g_y
ecdsa_u1g_y:    .res 32, 0      ; LE affine Y of u1*G

; --- fp_reverse32 staging buffer (one 32-byte scratch). Owned by ecdsa256.s.
.export fp_rev_buf
fp_rev_buf:     .res 32, 0

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
.export ecdsa384_u1g_x
ecdsa384_u1g_x: .res 48, 0      ; LE affine X of u1*G
.export ecdsa384_u1g_y
ecdsa384_u1g_y: .res 48, 0      ; LE affine Y of u1*G

; --- fp_reverse48 staging buffer (one 48-byte scratch). Owned by ecdsa384.s.
.export fp_rev_buf_384
fp_rev_buf_384: .res 48, 0

; --- ECDSA verify test-driver staging buffers.
;     The c64-test-harness jsr() helper cannot pass register arguments, so
;     the 160-/240-byte BE input struct for ecdsa_verify_{256,384} is
;     staged here by the Python test driver; the trampoline in main.s
;     loads A/X with a pointer to the buffer and invokes the verify
;     routine, capturing the returned C flag into the matching result
;     byte (0 = valid, 1 = invalid). Buffers are test-only; production
;     consumers pass their own pointer directly to ecdsa_verify_*.
.export ecdsa_inputs_256
ecdsa_inputs_256:       .res 160, 0     ; r|s|h|Qx|Qy each 32 B BE
.export ecdsa_result_256
ecdsa_result_256:       .byte 0

.export ecdsa_inputs_384
ecdsa_inputs_384:       .res 240, 0     ; r|s|h|Qx|Qy each 48 B BE
.export ecdsa_result_384
ecdsa_result_384:       .byte 0

; --- ecdsa_verify_with_message_384 scratch (P-384 hash-then-verify wrapper).
;     Saves the caller's struct base pointer across sha384_init/update/final,
;     since A/X are clobbered by every SHA call. Owned by ecdsa384.s and
;     non-re-entrant (matches the rest of the library's calling contract).
.export ecdsa384_msg_struct_ptr
ecdsa384_msg_struct_ptr: .res 2, 0

; --- ecdsa_verify_with_message_384 test driver result byte (mirrors
;     ecdsa_result_384). Test-only: the harness peeks this after invoking
;     the test trampoline; production consumers branch on C directly.
.export ecdsa_result_msg_384
ecdsa_result_msg_384:   .byte 0

; =============================================================================
; SHA-384 streaming hash state (FIPS 180-4 §6.4)
;
; Storage convention: each 64-bit word is held LITTLE-ENDIAN-WITHIN-WORD,
; matching 6502 ADC carry propagation. Wire SHA-512 byte order is BE-within-
; word; the byte-reverse happens at the boundary between sha_block_buf
; (wire order, BE) and sha_w (on-chip order, LE). The final digest is
; written BE in sha384_digest to match the FIPS spec output format.
; All buffers are owned exclusively by sha384.s.
; =============================================================================
.export sha_state
sha_state:        .res 64, 0     ; H[0..7], 8 bytes each LE-within-word
.export sha_w
sha_w:            .res 640, 0    ; W[0..79] message schedule, 8 B each LE
.export sha_abcdefgh
sha_abcdefgh:     .res 64, 0     ; working a..h, 8 B each LE
.export sha_t
sha_t:            .res 16, 0     ; T1 (8 B) + T2 (8 B), LE
.export sha_scratch
sha_scratch:      .res 64, 0     ; 8x 8-byte scratch slots for round helpers
.export sha_block_buf
sha_block_buf:    .res 128, 0    ; current 1024-bit block (wire order)
.export sha_block_len
sha_block_len:    .byte 0        ; bytes used in sha_block_buf, 0..127
.export sha_total_len
sha_total_len:    .res 16, 0     ; 128-bit total bit count, LE on-chip
.export sha384_digest
sha384_digest:    .res 48, 0     ; final BE digest output
.export sha384_msg_buf
sha384_msg_buf:   .res 1024, 0   ; test scratch buffer (poked by harness)
