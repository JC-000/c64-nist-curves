.setcpu "6502"

; =============================================================================
; reu_config.s - c64-nist-curves REU layout contract (c64-lib-contract SPEC §3)
;
; This file publishes every REU bank and within-bank offset claimed by the
; library as `.ifndef`-guarded, `.export`-ed integer equates. Downstream
; consumers (c64-https, c64-wireguard, ...) override these via
;
;   ca65 -D LIB_NISTCURVES_REU_BANK_COMB=$05 ...
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
;
; SPEC §8.2 adoption: the 128 KB 8x8->16 REU multiplication table is now
; the shared `reu_mul` primitive. The consumer-facing placement equates
; are `LIB_SHARED_REU_MUL_BANK` (base bank) and `LIB_SHARED_REU_MUL_OFFSET`
; (within-bank base offset, pinned to $0000 by the v0.x.0 spec
; constraint). The legacy `LIB_NISTCURVES_REU_BANK_MUL` name remains
; exported for backwards compatibility but is now defined as an alias of
; `LIB_SHARED_REU_MUL_BANK` so the canonical shared equate is the single
; source of truth at all in-tree callsites.

.ifndef LIB_SHARED_REU_MUL_BANK
  LIB_SHARED_REU_MUL_BANK = $00
.endif

.ifndef LIB_SHARED_REU_MUL_OFFSET
  LIB_SHARED_REU_MUL_OFFSET = $0000
.endif

; Derived two-bank mask per SPEC §8.2 (the table claims `base` and
; `base + 1`). Consumers compose it directly into REU-region collision
; `.assert`s instead of rewriting `(1 .shl bank) | (1 .shl (bank+1))`
; at every callsite. Libraries OR it into their own
; `LIB_<X>_REU_BANKS_USED` (§5) when they consume the canonical primitive.
LIB_SHARED_REU_MUL_BANKS_USED = (1 .shl LIB_SHARED_REU_MUL_BANK) | (1 .shl (LIB_SHARED_REU_MUL_BANK + 1))

; SPEC §8.2 assemble-time guards:
;   - offset $0000:  v0.x.0 row-stride constraint (start-of-bank required)
;   - base < $FE:    the hi-half bank lives at base+1, so $FF has no successor
.assert LIB_SHARED_REU_MUL_OFFSET = $0000, error, "reu_mul must start at offset 0 within its bank pair (SPEC §8.2 v0.x.0)"
.assert LIB_SHARED_REU_MUL_BANK < $FE,     error, "reu_mul base bank must leave room for the hi-half bank at base+1 (SPEC §8.2)"

; Backwards-compatible alias. `LIB_NISTCURVES_REU_BANK_MUL` is the
; pre-SPEC-§8.2 name; in-tree callsites (main.s, mul_8x8.s) still
; .import it. Aliasing to the canonical shared equate keeps one source
; of truth without breaking any callsite. The `.ifndef` guard preserves
; the consumer-override path that already existed for the legacy name.
.ifndef LIB_NISTCURVES_REU_BANK_MUL
  LIB_NISTCURVES_REU_BANK_MUL = LIB_SHARED_REU_MUL_BANK
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

; --- SPEC v0.13.0 §8.2 post-execute settle (issue #130) ---
; Iterations of the 9-cycle settle loop in nistcurves_reu_dma_wait
; (src/mul_8x8.s) after every REU execute at a tight site. Default 8 ->
; ~106 cycles execute-to-next-register-write (34 + 9*ITER; the loop is
; 9*ITER-1 because the final bne falls through), 2.16x the measured floor
; (>= 49 cy @ 48 MHz, U64E fw 3.15, c64-lib-contract#144). 64 MHz is
; unbracketed as of SPEC v0.13.0: a consumer claiming that clock raises
; this (`ca65 -D LIB_NISTCURVES_REU_SETTLE_ITER=<n>`, 1..255) until a
; FAIL/PASS bracket exists. Exported as the code-read symbol so a
; consumer can assert what the archive actually settles for.
.ifndef LIB_NISTCURVES_REU_SETTLE_ITER
  LIB_NISTCURVES_REU_SETTLE_ITER = 8
.endif
.assert LIB_NISTCURVES_REU_SETTLE_ITER >= 1 && LIB_NISTCURVES_REU_SETTLE_ITER <= 255, error, "LIB_NISTCURVES_REU_SETTLE_ITER must be 1..255 (one-byte settle counter)"
.export LIB_NISTCURVES_REU_SETTLE_ITER:abs

; --- Exports ---
; Force absolute address-size on the exports: the integer-equate values can
; fit in zero-page so ca65 would otherwise tag them as `zeropage` and ld65
; would warn at every `.import ... ; lda #<sym` import site. These symbols
; are scalar parameters, not actual addresses, so absolute is correct.
.export LIB_NISTCURVES_REU_BANK_MUL:abs
.export LIB_NISTCURVES_REU_BANK_COMB:abs
.export LIB_NISTCURVES_REU_OFFSET_COMB_P256:abs
.export LIB_NISTCURVES_REU_OFFSET_COMB_P384:abs

; -----------------------------------------------------------------------------
; SPEC §8.2 export discipline (contract v0.8.5) -- prefixed OUTPUT counterparts
; -----------------------------------------------------------------------------
; The clause has two halves. The consumer-INPUT equates above must not be
; exported (they are shared names; see the block below). Each §8.2-consuming
; library must instead export library-prefixed OUTPUTS "whose values are the
; values the code reads", so a consumer can read back where the table actually
; landed and assert agreement with a co-linked sibling.
;
; The "values the code reads" wording is load-bearing, and the reason is a real
; bug: c64-x25519's pre-#92 export published a number nothing consumed, so a
; consumer `-D` override succeeded silently and relocated nothing. To avoid
; that here these alias LIB_NISTCURVES_REU_BANK_MUL -- the symbol
; fp256.s/fp384.s actually load into the REU bank register -- NOT the
; LIB_SHARED_REU_MUL_BANK knob. Both spellings move the code-read value:
;
;   ca65 -D LIB_SHARED_REU_MUL_BANK=3      -> code reads 3 (through the alias)
;   ca65 -D LIB_NISTCURVES_REU_BANK_MUL=3  -> code reads 3 (direct override)
;
; so aliasing the knob would be decorative under the second spelling, which is
; exactly the failure the clause names. Aliasing the code-read symbol tracks
; both.
;
; OFFSET has no runtime reader: the row fetch writes reu_reu_lo = 0 directly,
; and the .assert above pins the equate to $0000, so equate and code agree by
; construction rather than by aliasing. BANKS_USED is derived here from the
; code-read bank for the same reason the BANK output is.
LIB_NISTCURVES_SHARED_REU_MUL_BANK   = LIB_NISTCURVES_REU_BANK_MUL
LIB_NISTCURVES_SHARED_REU_MUL_OFFSET = LIB_SHARED_REU_MUL_OFFSET
LIB_NISTCURVES_SHARED_REU_MUL_BANKS_USED = (1 .shl LIB_NISTCURVES_REU_BANK_MUL) | (1 .shl (LIB_NISTCURVES_REU_BANK_MUL + 1))

.export LIB_NISTCURVES_SHARED_REU_MUL_BANK:abs
.export LIB_NISTCURVES_SHARED_REU_MUL_OFFSET:abs
.export LIB_NISTCURVES_SHARED_REU_MUL_BANKS_USED:abs

; SPEC §8.2 canonical equates are deliberately NOT exported
; (c64-lib-contract #82). They are consumer-supplied placement values:
; `.ifndef`-guarded here and overridden with `ca65 -D`, exactly like §8.1's
; LIB_SHARED_SQTAB_BASE, which no adopter exports either. Exporting them
; put three unprefixed names into the link namespace, and because every §8.2
; consumer defines the same three, a consumer linking two REU adopters got
;
;   ld65: Error: Duplicate external identifier: 'LIB_SHARED_REU_MUL_BANKS_USED'
;
; -- reproduced against c64-x25519 v0.10.1, the pair c64-https actually ships.
; Nothing imported them: no in-tree importer, no object import, no archive pin.
;
; Note the contrast with the §3 equates above, which ARE exported and SHOULD
; be: those carry this library's LIB_NISTCURVES_ prefix, so they are in our
; namespace and cannot collide. The §8.2 names are shared by construction.
;
; If the contract later rules that §8.2 placement should be published rather
; than library-local, the form will be prefixed (LIB_NISTCURVES_SHARED_REU_MUL_*)
; per the #43 family; adding that is additive, whereas keeping the bare names
; would have to be undone. Dropping is the reversible direction.
