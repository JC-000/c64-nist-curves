.setcpu "6502"

; =============================================================================
; data_p256_invref.s - Scratch for the Fermat-inversion reference path.
;
; Split from data_p256.s by issue #54 (SPEC §6 minimal-archive build
; targets, slot-level trim). fp_tmp1 is referenced only by inv256.s
; (fp_mod_inv_fast, the addition-chain Fermat inverse kept for reference;
; production uses the binary-GCD path in mod256.s). inv256.o is excluded
; from lib-p256-verify, so its data rides in this separate object the
; same way data_p256_limlee.s carries the comb-only slots.
; =============================================================================

.segment "LIB_NISTCURVES_P256_INVREF_BSS"

.export fp_tmp1
fp_tmp1:
        .res 32, 0            ; Fermat-inverse working element
