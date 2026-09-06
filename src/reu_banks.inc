; =============================================================================
; reu_banks.inc — the SPEC §3 REU bank equates, single shared include.
;
; Included by BOTH src/reu_config.s (which exports them) and
; src/lib_manifest.s (which derives LIB_NISTCURVES_REU_BANKS_USED from them).
;
; Why they had to move out of reu_config.s
; ----------------------------------------
; §5's `LIB_<X>_REU_BANKS_USED` is the symbol §3 tells consumers to compose:
;
;   .assert (LIB_NISTCURVES_REU_BANKS_USED & LIB_X25519_REU_BANKS_USED) = 0, ...
;
; Through v0.12.0 that mask was a per-variant LITERAL in lib_manifest.s ($07,
; $04, $03, $00), because ca65 cannot evaluate arithmetic over `.import`ed
; symbols at assembly time and the bank equates lived in another TU. The
; source comment told the consumer to override the mask by hand whenever they
; relocated a bank.
;
; That is a documented hazard, not a resolved one, and it is the same class of
; defect as the `< $FE` bound this release tightened. A consumer who relocates
; our mul table to banks 3/4 and links a sibling also at 3/4 gets
;
;   $07 & $18 = 0   ->  assert PASSES
;
; while both libraries DMA into the same two banks: corrupted multiply tables,
; wrong field results, no diagnostic at any stage. The bound fix protected the
; mask that was already truthful (`LIB_NISTCURVES_SHARED_REU_MUL_BANKS_USED`,
; derived in reu_config.s) and left the untruthful one in place.
;
; An `.include` is the way out: both TUs see the same guarded equates at
; assembly time, so the mask can be COMPUTED per variant instead of asserted,
; and a `-D` reaching every TU (which `CONTRACT_DEFINES` guarantees, §6.2)
; moves the mask and the code together. Same mechanism as sqtab_base.inc.
;
; Do not define these anywhere else. Two copies of a default can silently
; disagree, which is exactly what this file exists to prevent.
; =============================================================================

.ifndef REU_BANKS_INC_INCLUDED
REU_BANKS_INC_INCLUDED = 1

; --- Multiply-table cache: two contiguous banks (base and base + 1) ---
; SPEC §8.2 names LIB_SHARED_REU_MUL_BANK as the consumer-facing placement
; equate; LIB_NISTCURVES_REU_BANK_MUL is the pre-§8.2 spelling, kept as an
; alias so both override paths reach the value the code reads.
.ifndef LIB_SHARED_REU_MUL_BANK
  LIB_SHARED_REU_MUL_BANK = $00
.endif

.ifndef LIB_SHARED_REU_MUL_OFFSET
  LIB_SHARED_REU_MUL_OFFSET = $0000
.endif

.ifndef LIB_NISTCURVES_REU_BANK_MUL
  LIB_NISTCURVES_REU_BANK_MUL = LIB_SHARED_REU_MUL_BANK
.endif

; --- Lim-Lee comb anchor tables: one bank, two within-bank regions ---
.ifndef LIB_NISTCURVES_REU_BANK_COMB
  LIB_NISTCURVES_REU_BANK_COMB = $02
.endif

.ifndef LIB_NISTCURVES_REU_OFFSET_COMB_P256
  LIB_NISTCURVES_REU_OFFSET_COMB_P256 = $0000
.endif

.ifndef LIB_NISTCURVES_REU_OFFSET_COMB_P384
  LIB_NISTCURVES_REU_OFFSET_COMB_P384 = $4000
.endif

; --- SPEC §8.2 assemble-time guards ---
;   offset $0000: row-stride constraint (start-of-bank required).
;   base < 31:    the hi-half bank lives at base + 1, and BOTH must be
;                 nameable in the 32-bit §5 mask. SPEC 1.0.0 tightened this
;                 from the `< $FE` this library shipped through v0.12.0:
;                 `1 .shl 32` exports 0, so a base of 31 or more contributed a
;                 zero bit and a consumer's collision assert passed FALSELY --
;                 the loosest possible failure, since it certifies that two
;                 libraries do not overlap when they may.
;   comb < 32:    one bank, so the last nameable index is 31.
.assert LIB_SHARED_REU_MUL_OFFSET = $0000, error, "reu_mul must start at offset 0 within its bank pair (SPEC §8.2)"
.assert LIB_SHARED_REU_MUL_BANK < 31,      error, "reu_mul base bank must leave room for the hi-half bank at base+1 inside the 32-bit §5 bank mask (SPEC §8.2)"
.assert LIB_NISTCURVES_REU_BANK_MUL < 31,  error, "LIB_NISTCURVES_REU_BANK_MUL must leave room for the hi-half bank at base+1 inside the 32-bit §5 bank mask (SPEC §8.2)"
.assert LIB_NISTCURVES_REU_BANK_COMB < 32, error, "LIB_NISTCURVES_REU_BANK_COMB must be nameable in the 32-bit §5 bank mask (SPEC §3/§5: bit n = bank n, banks 0-31)"

; --- Derived masks, from the values the CODE reads ---
; fp256.s / fp384.s load LIB_NISTCURVES_REU_BANK_MUL into the REU bank
; register, and the comb helpers load LIB_NISTCURVES_REU_BANK_COMB, so these
; two terms describe where DMA actually goes -- not where a knob says it
; should. lib_manifest.s ORs the terms its variant actually claims.
LIB_NISTCURVES_REU_MASK_MUL  = (1 .shl LIB_NISTCURVES_REU_BANK_MUL) | (1 .shl (LIB_NISTCURVES_REU_BANK_MUL + 1))
LIB_NISTCURVES_REU_MASK_COMB = (1 .shl LIB_NISTCURVES_REU_BANK_COMB)

.endif
