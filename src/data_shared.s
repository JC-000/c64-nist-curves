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
.export mul_cached_a
mul_cached_a:
        .byte 0                ; cached src1[i] for inlined multiply
.export mul_src2_buf
mul_src2_buf:
        .res 35, 0            ; absolute copy of src2 for fast indexed access
                               ; (32 bytes + 3 pad zeros so fp_sqr 4x-unroll
                               ; can over-read past j=31 into zeros for fast-skip)

; --- REU DMA target buffers (page-aligned for LDA abs,Y without penalty) ---
; SHARED between P-256 and P-384 code paths - see re-entrancy note above.
.segment "LIB_NISTCURVES_TABLES"
.export mul_dma_lo
mul_dma_lo:
        .res 256, 0           ; DMA target: lo bytes of a*b for current a
.export mul_dma_hi
mul_dma_hi:
        .res 256, 0           ; DMA target: hi bytes of a*b for current a
