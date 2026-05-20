.setcpu "6502"

; =============================================================================
; reu_config.s - c64-nist-curves REU layout contract (c64-lib-contract SPEC §3)
;
; This file publishes every REU bank and within-bank offset claimed by the
; library as `.ifndef`-guarded, `.export`-ed integer equates. Downstream
; consumers (c64-https, c64-wireguard, ...) override these via
;
;   ca65 --asm-define LIB_NISTCURVES_REU_BANK_COMB=$05 ...
;
; to relocate the library's REU footprint when sharing an REU with sibling
; libraries (e.g., c64-x25519). The aggregate manifest equate
; LIB_NISTCURVES_REU_BANKS_USED (SPEC §3) is published separately.
;
; Banks claimed at the default layout:
;
;   Bank $00 + $01 : 128 KB multiply-table cache (mul_8x8 row LUT).
;                    Indexed by mul_cached_a 0..255 → 512-byte rows;
;                    rows 0..127 land in bank $00, rows 128..255 in bank $01.
;                    Built once at boot by `reu_mul_init` (main.s).
;
;   Bank $02       : Lim-Lee fixed-base comb anchor tables.
;                    P-256 at offset $0000 (256 × 64 B = 16 KB).
;                    P-384 at offset $4000 (256 × 96 B = 24 KB).
;                    Built once at boot by `ec_precompute_256` /
;                    `ec_precompute_384`. Remaining $A000..$FFFF (24 KB) of
;                    bank $02 is free for consumer scratch.
;
; A consumer that overrides LIB_NISTCURVES_REU_BANK_MUL to $03 claims banks
; $03 and $04 for multiply tables. A consumer that overrides
; LIB_NISTCURVES_REU_BANK_COMB to $05 claims bank $05 for the comb anchors.
;
; The variable-base scalar mul (`ec_scalar_mul_var_384`) does NOT use any REU
; storage; it operates entirely in main RAM. No equate is needed for it.
; =============================================================================

; --- Multiply-table cache (2 contiguous banks) ---
.ifndef LIB_NISTCURVES_REU_BANK_MUL
  LIB_NISTCURVES_REU_BANK_MUL = $00
.endif

; --- Lim-Lee comb anchor tables (one bank, two within-bank regions) ---
.ifndef LIB_NISTCURVES_REU_BANK_COMB
  LIB_NISTCURVES_REU_BANK_COMB = $02
.endif

.ifndef LIB_NISTCURVES_REU_OFFSET_COMB_P256
  LIB_NISTCURVES_REU_OFFSET_COMB_P256 = $0000
.endif

.ifndef LIB_NISTCURVES_REU_OFFSET_COMB_P384
  LIB_NISTCURVES_REU_OFFSET_COMB_P384 = $4000
.endif

; --- Exports ---
; Force absolute address-size on the exports: the integer-equate values can
; fit in zero-page so ca65 would otherwise tag them as `zeropage` and ld65
; would warn at every `.import ... ; lda #<sym` import site. These symbols
; are scalar parameters, not actual addresses, so absolute is correct.
.export LIB_NISTCURVES_REU_BANK_MUL:abs
.export LIB_NISTCURVES_REU_BANK_COMB:abs
.export LIB_NISTCURVES_REU_OFFSET_COMB_P256:abs
.export LIB_NISTCURVES_REU_OFFSET_COMB_P384:abs
