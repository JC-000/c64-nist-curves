.setcpu "6502"

; =============================================================================
; data_reu_wait.s - SPEC §8.2 REU DMA completion-confirm state (issue #130).
;
; Split out of data_shared.s by issue #149. These two cells are library-private
; plumbing for `nistcurves_reu_dma_wait` (src/mul_8x8.s); the multiply-row
; landing buffers that used to share this translation unit
; (`nistcurves_mul_dma_lo` / `_hi`) are an APP_OWNED surface a consumer may
; provide itself under §8.0/§8.3.
;
; Keeping them in one TU made those two facts inseparable at link time. ld65
; pulls in whole archive members, so a consumer that supplies its own
; multiply-row buffers still dragged data_shared.o into the link the moment
; anything referenced this settle state -- and then ld65 saw two definitions of
; `nistcurves_mul_dma_lo/hi` and refused the link outright:
;
;   ld65: Error: Duplicate external identifier: 'nistcurves_mul_dma_hi'
;
; That is what c64-https hit on every one of its three shipped configurations
; when moving from v0.11.2 to v0.12.0, and why it could not take the §8.2
; settle at all. Resolving the settle state must not drag an APP_OWNED buffer
; definition along with it, so the settle state lives here, alone.
;
; Do not add anything to this file that a consumer might legitimately want to
; own. Its whole purpose is to be safe to pull into any link.
; =============================================================================

.segment "LIB_NISTCURVES_BSS"

; nistcurves_reu_wait_cnt: 16-bit bounded-spin / settle counter used by
;   nistcurves_reu_dma_wait (src/mul_8x8.s). Scratch; no init needed.
; nistcurves_reu_dma_timeout: sticky, 1 once any bounded spin on $DF00
;   bit 6 has expired without END OF BLOCK. Zero at load because this
;   segment is `type = rw` (in the image); a consumer whose cfg makes it
;   `bss` must zero it before init and may test it after (the clause's
;   SHOULD: surface a bounded-spin failure like a missing REU at init).
.export nistcurves_reu_wait_cnt
.export nistcurves_reu_dma_timeout

nistcurves_reu_wait_cnt:
        .res 2, 0
nistcurves_reu_dma_timeout:
        .byte 0
