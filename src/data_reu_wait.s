.setcpu "6502"

; =============================================================================
; data_reu_wait.s - SPEC §8.2 REU DMA completion-confirm state (issue #130).
;
; Split out of data_shared.s by issue #149. These two cells are library-private
; plumbing for `nistcurves_reu_dma_wait`, which since issue #155 lives in this
; same TU (below); the multiply-row
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
; own. Its whole purpose is to be safe to pull into any link -- which is also
; why issue #155 moved `nistcurves_reu_dma_wait` INTO it (below): fp256.o and
; fp384.o import that routine, so wherever it lives is pulled by every field
; operation, and in `mul_8x8.s` it arrived carrying displaceable names.
; Library-private plumbing is welcome here; anything ownable is not.
; =============================================================================

.segment "LIB_NISTCURVES_BSS"

; nistcurves_reu_wait_cnt: 16-bit bounded-spin / settle counter used by
;   nistcurves_reu_dma_wait (below). Scratch; no init needed.
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


.segment "LIB_NISTCURVES_MUL_CODE"

; =============================================================================
; nistcurves_reu_dma_wait - SPEC v0.13.0 §8.2 DMA completion confirm (a) +
;   post-execute settle (b). c64-lib-contract#144/#146, issue #130.
;   Full rationale and the per-site form choice: src/reu_dma_done.inc.
;
; Call after `sta reu_command` and before the next REU register access.
; Clobbers: A, flags. X/Y preserved (hot sites enter via REU_DMA_CONFIRM's
;   slow path with the row index live).
;
; (a) Spin on $DF00 bit 6 (END OF BLOCK), bounded at 65 536 reads via a
;     16-bit counter (~0.9 s at 1 MHz; §13.4-style bound). BIT copies bit 6
;     into V without touching A; each read clears bits 5-7, which is why
;     the test is on the register just read and never re-read. Bit 5
;     (VERIFY ERROR) can only be raised by the VERIFY command, which this
;     library never issues, so it is not tested. On expiry the sticky
;     `nistcurves_reu_dma_timeout` is set to 1 and execution proceeds --
;     the primitive has no error channel (clause: SHOULD surface as a
;     missing REU at init does; consumers test the byte after init).
; (b) LIB_NISTCURVES_REU_SETTLE_ITER iterations of `dec abs / bne`
;     (9 cycles each) after the confirm. With the default 8 the execute ->
;     next-register-write distance through this routine is
;     jsr 6 + lda/sta/sta 10 + bit/bvs 7 + lda/sta 6 + (9*8 - 1) + rts 6
;     = 106 cycles -- the loop is 9*ITER - 1, not 9*ITER, because the FINAL
;     `bne` falls through at 2 cycles rather than branching at 3. The
;     general form is 34 + 9*ITER. (This comment said 35 + 9*ITER / 107
;     through v0.12.0; the error was optimistic, so every margin quoted
;     against the floor was one cycle smaller than documented.) That is
;     2.16x the measured 48 MHz floor (>= 49 cy, U64E fw 3.15) and
;     it is a FLOOR in a second sense too: it omits the caller's own
;     instructions between this `rts` and its next REU register write, and
;     it measures execute -> next REGISTER WRITE, which is NOT the axis on
;     which the hazard has actually been observed (that is execute -> first
;     read of the landing buffer; see src/reu_dma_done.inc).
;     covering a 1 us floor at 64 MHz (~65 cy) should the settle turn out
;     to be time-anchored -- 64 MHz is UNBRACKETED as of SPEC v0.13.0; a
;     consumer claiming that clock raises the knob (`ca65 -D`) until the
;     bracket exists.
; Not gated: the routine is library-private plumbing, not part of the §8.2
;   provider surface, and every REU-touching archive (including the
;   comb-onchip pair, which still DMAs the anchor table) needs it.
; =============================================================================
.import reu_status
; SPEC §3/§6.2 consumer override (issue #143). CONTRACT_DEFINES reaches
; EVERY TU, so under `-D LIB_NISTCURVES_REU_SETTLE_ITER=<v>` ca65 defines the symbol here too and an
; unconditional `.import` of the same name is "Symbol ... is already defined"
; -- i.e. the documented override does not assemble at all. Guarding makes
; both arms work: no override -> import reu_config.s's exported default;
; override -> use the -D value, which is the same value reu_config.s exports,
; because the one -D reaches both TUs. Same shape as src/sqtab_base.inc's
; "included, not imported" note.
.ifndef LIB_NISTCURVES_REU_SETTLE_ITER
.import LIB_NISTCURVES_REU_SETTLE_ITER
.endif
; (nistcurves_reu_wait_cnt / nistcurves_reu_dma_timeout are defined above in
; this same TU since issue #155 -- no import, and none possible.)
.export nistcurves_reu_dma_wait
nistcurves_reu_dma_wait:
        lda #0
        sta nistcurves_reu_wait_cnt
        sta nistcurves_reu_wait_cnt+1
@spin:
        bit reu_status               ; V = bit 6 END OF BLOCK; read clears 5-7
        bvs @settle
        inc nistcurves_reu_wait_cnt
        bne @spin
        inc nistcurves_reu_wait_cnt+1
        bne @spin
        lda #1                       ; bounded spin expired: sticky flag, proceed
        sta nistcurves_reu_dma_timeout
@settle:
        lda #<LIB_NISTCURVES_REU_SETTLE_ITER
        sta nistcurves_reu_wait_cnt
@settle_loop:
        dec nistcurves_reu_wait_cnt  ; 6 + 3 = 9 cycles per iteration
        bne @settle_loop
        rts
