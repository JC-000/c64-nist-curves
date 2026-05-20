.setcpu "6502"

; =============================================================================
; data_p384_limlee.s - P-384 Lim-Lee fixed-base comb anchors + working scalar.
;
; Split from the monolithic data.s as part of #40 (SPEC §6 minimal-archive
; build targets). Excluded from lib-p384-verify because variable-base ECDSA
; verify (the only operation that archive ships) never touches the comb
; precompute path.
; =============================================================================

.segment "LIB_NISTCURVES_P384_LIMLEE_BSS"

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
