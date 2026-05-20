.setcpu "6502"

; =============================================================================
; data_p256_limlee.s - P-256 Lim-Lee fixed-base comb anchors + working scalar.
;
; Split from the monolithic data.s as part of #40 (SPEC §6 minimal-archive
; build targets). Excluded from lib-p256-verify because variable-base ECDSA
; verify (the only operation that archive ships) never touches the comb
; precompute path.
; =============================================================================

.segment "LIB_NISTCURVES_P256_LIMLEE_BSS"

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
