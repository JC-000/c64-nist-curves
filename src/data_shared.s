.setcpu "6502"

; =============================================================================
; data_shared.s - RW buffers shared between all curve / SHA code paths.
;
; Split from the monolithic data.s as part of #40 (SPEC §6 minimal-archive
; build targets). The split keeps per-curve / per-feature buffers in their
; own modules so an archive that excludes (e.g.) the P-384 code path does
; not drag in 1 KB of P-384 RW state.
;
; Contents:
;   mul_cached_a / mul_src2_buf - operand cache for the 4x-unrolled inner
;       multiply loop. Shared between P-256 and P-384 fp_mul / fp_sqr.
;   mul_dma_lo / mul_dma_hi     - 256-byte REU DMA target pages for the
;       per-row multiply-table fetch. Must remain page-aligned; placed in
;       LIB_NISTCURVES_TABLES which has align = $100 in c64.cfg.
;
; All buffers are LITTLE-ENDIAN (byte 0 = LSB) where applicable, matching
; 6502 ADC carry propagation.
; =============================================================================

.segment "LIB_NISTCURVES_BSS"

; --- fe_mul optimization buffers ---
; NOT RE-ENTRANT. The buffers below (mul_cached_a, mul_src2_buf, mul_dma_lo,
; mul_dma_hi) plus the fp_src1/fp_src2/fp_dst zero-page slots are SHARED
; between all P-256 and P-384 field operations. Sequential calls across
; curves are fine, but the host program MUST NOT interleave them - e.g.
; calling fp_mod_mul_384 from an IRQ handler while fp_mod_mul is running
; in mainline will corrupt the cached operand / DMA target state. Serialize
; all calls into the library (mask IRQs around field ops or keep crypto on
; a single thread of control).
; §6.5 rename window (contract v0.9.0/v0.9.1): the `mul_` prefix is registered
; to c64-x25519 in the §2 registry, so these four labels take this library's
; prefix. Canonical names are the definitions; the bare names are same-address
; aliases, export-gated (suppressed under -D LIB_NO_BARE_EXPORTS=1) and removed
; at the next MAJOR. Every in-library reference uses the canonical name, so
; gated archives stay link-complete.
.export nistcurves_mul_cached_a
.ifndef LIB_NO_BARE_EXPORTS
.export mul_cached_a
.endif
mul_cached_a = nistcurves_mul_cached_a
nistcurves_mul_cached_a:
        .byte 0                ; cached src1[i] for inlined multiply
.export nistcurves_mul_src2_buf
.ifndef LIB_NO_BARE_EXPORTS
.export mul_src2_buf
.endif
mul_src2_buf = nistcurves_mul_src2_buf
nistcurves_mul_src2_buf:
        .res 35, 0            ; absolute copy of src2 for fast indexed access
                               ; (32 bytes + 3 pad zeros so fp_sqr 4x-unroll
                               ; can over-read past j=31 into zeros for fast-skip)

; --- SPEC v0.13.0 §8.2 DMA completion confirm state (issue #130) ---
; nistcurves_reu_wait_cnt: 16-bit bounded-spin / settle counter used by
;   nistcurves_reu_dma_wait (src/mul_8x8.s). Scratch; no init needed.
; nistcurves_reu_dma_timeout: sticky, 1 once any bounded spin on $DF00
;   bit 6 has expired without END OF BLOCK. Zero at load because this
;   segment is `type = rw` (in the image); a consumer whose cfg makes it
;   `bss` must zero it before init and may test it after (the clause's
;   SHOULD: surface a bounded-spin failure like a missing REU at init).
nistcurves_reu_wait_cnt:
        .res 2, 0
.export nistcurves_reu_wait_cnt
.export nistcurves_reu_dma_timeout
nistcurves_reu_dma_timeout:
        .byte 0

; --- REU DMA target buffers (page-aligned for LDA abs,Y without penalty) ---
; SHARED between P-256 and P-384 code paths - see re-entrancy note above.
.segment "LIB_NISTCURVES_TABLES"
.export nistcurves_mul_dma_lo
.ifndef LIB_NO_BARE_EXPORTS
.export mul_dma_lo
.endif
mul_dma_lo = nistcurves_mul_dma_lo
nistcurves_mul_dma_lo:
        .res 256, 0           ; DMA target: lo bytes of a*b for current a
.export nistcurves_mul_dma_hi
.ifndef LIB_NO_BARE_EXPORTS
.export mul_dma_hi
.endif
mul_dma_hi = nistcurves_mul_dma_hi
nistcurves_mul_dma_hi:
        .res 256, 0           ; DMA target: hi bytes of a*b for current a
