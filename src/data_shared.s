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

; The SPEC §8.2 DMA completion-confirm state (nistcurves_reu_wait_cnt /
; nistcurves_reu_dma_timeout) used to live here. Issue #149 moved it to
; src/data_reu_wait.s: it is library-private plumbing, whereas the
; mul_dma_lo/hi buffers below are an APP_OWNED surface a consumer may define
; itself. Sharing one TU meant referencing the settle state pulled this member
; into the link and duplicated those buffer definitions. Do not merge them back.

; The §8.2 staging buffers (nistcurves_mul_dma_lo / _hi) used to live here too.
; They are in src/data_mul_stage.s now, and must stay there: they are an
; APP_OWNED surface, the two cells above are library-private and imported by
; fp256.o / fp384.o / mul_8x8.o, and SPEC §6.1 member isolation forbids the combination (clause added at
; contract 1.2.0, wording amended at 1.2.1 and 1.2.2; frozen at v1.2.2) --
; ld65 links whole members, so a consumer owning the buffers and calling any
; field op pulled this member and collided. Splitting the settle state out
; (issue #149, src/data_reu_wait.s) fixed only half of that. Do not merge them
; back.
