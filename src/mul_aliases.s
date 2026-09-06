.setcpu "6502"

; =============================================================================
; mul_aliases.s — the deprecated bare `mul_dma_*` spellings, alone.
;
; Same shape and the same reason as src/zp_aliases.s: SPEC §6.1 member
; isolation, at the frozen v1.2.2 wording —
;
;   "A symbol a consumer may displace -- suppress under LIB_NO_BARE_EXPORTS, or
;    define itself under APP_OWNED (§8.0) -- MUST live in a translation unit
;    that exports nothing else a consumer may import -- other displaceable
;    names included, their own prefixed counterparts excepted -- and defines
;    nothing else the library's own code references."
;
; `mul_dma_lo`/`_hi` are displaceable twice over: gated under
; LIB_NO_BARE_EXPORTS, and definable by a consumer under APP_OWNED. Their
; prefixed counterparts `nistcurves_mul_dma_lo`/`_hi` may sit beside them —
; 1.2.1 added that exception precisely so a bare/prefixed pair can share a TU.
;
; What may NOT sit beside them is `LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO` /
; `_HI`. Those are §8.2 output equates a consumer is *told* to import to check
; that two co-linked §8.2 libraries agree on the landing page, and they are not
; a prefixed counterpart of anything displaceable — they are a different name
; with a different meaning that happens to hold the same address. Keeping them
; in data_mul_stage.s beside the bare aliases meant a consumer importing only
; `LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO` pulled that member and its bare
; names with it, and against c64-x25519 — which exports `mul_dma_lo`,
; `mul_dma_hi` and `mul_dma_carry` from its own `src/mul_stage.s` — ld65
; refused the link:
;
;   ld65: Error: Duplicate external identifier: 'mul_dma_hi'
;
; Same failure class, same symbol family, as the c64-https v0.12.0 outage the
; clause exists for. Found by adversarial review, reproduced against a stand-in
; for x25519's TU, and worth recording as a cautionary shape: the previous
; commit moved these equates INTO data_mul_stage.s to stop reu_config.o
; dragging the buffers in, and in doing so traded one member-isolation defect
; for another. Splitting is the fix; moving is not.
;
; Do not add anything to this file, and do not merge it back.
; =============================================================================

; §6.5 rename window: `mul_` is registered to c64-x25519 in the §2 registry, so
; this library's canonical spelling carries its own prefix. These bare forms are
; same-address aliases kept for consumers that predate the rename; they are
; suppressed by -D LIB_NO_BARE_EXPORTS=1 and go at the next MAJOR.
;
; Derived by import rather than restated, so the two spellings cannot drift:
; ld65 resolves the export from the import, and the alias has no address of its
; own to disagree with.
.ifndef LIB_NO_BARE_EXPORTS

.import nistcurves_mul_dma_lo
.import nistcurves_mul_dma_hi

.export mul_dma_lo
.export mul_dma_hi

mul_dma_lo = nistcurves_mul_dma_lo
mul_dma_hi = nistcurves_mul_dma_hi

.endif
