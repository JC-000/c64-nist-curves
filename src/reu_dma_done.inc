; =============================================================================
; reu_dma_done.inc - SPEC v0.13.0 §8.2: REU DMA completion confirm (a) and
;   post-execute settle (b), c64-lib-contract#144 / #146, this repo's #130.
;
; After EVERY REU execute (`sta reu_command` with the execute bit) and
; BEFORE the next access to any REU register, the implementation MUST
;   (a) read $DF00 and confirm bit 6 (END OF BLOCK), spinning bounded if
;       it is not set -- insurance against a device that does not hold
;       the CPU for the transfer (never observed; 0 of 19 416 calls on
;       U64E fw 3.15 @ 48 MHz needed a second read), and
;   (b) leave a post-execute settle meeting the empirically bracketed
;       floor -- the hazard that WAS observed: on U64E fw 3.15 at 48 MHz
;       the REU's post-transfer autoload/restore outlasts the turbo CPU,
;       and the very next REU register write lands on a busy controller
;       (wrong row -> wrong products -> silent wrong crypto). Measured
;       floor: >= 49 cycles @ 48 MHz, U64E fw 3.15. UNBRACKETED at 64 MHz.
;
; Two forms, chosen per site by how soon the NEXT REU register access is:
;
;   REU_DMA_CONFIRM   -- hot sites (the six fp_mul / fp_sqr row fetches).
;       Inline `bit reu_status / bvs done` (7 cycles, A/X/Y preserved --
;       BIT copies bit 6 into V without touching A; the read clears bits
;       5-7 as the clause notes). Only if bit 6 is clear does it fall into
;       the bounded spin + settle routine. Obligation (b) is met
;       STRUCTURALLY at these sites: the next REU register write is the
;       next row fetch, and the accumulate body between them is >= ~80
;       cycles even on the shortest path (fp_sqr diagonal), i.e. above the
;       48 MHz floor with margin. If a 64 MHz bracket ever exceeds that
;       distance, switch these sites to the jsr form.
;
;   jsr nistcurves_reu_dma_wait  -- tight sites, where the next REU register
;       write follows within a few instructions: both stashes in
;       reu_mul_init (back-to-back), the four comb stash/fetch routines
;       (their `*_restore` rewrites five registers immediately), and the
;       exported reu_fetch_mul_row (caller behaviour unknown). Full
;       bounded confirm, then LIB_NISTCURVES_REU_SETTLE_ITER iterations of
;       settle (src/reu_config.s; consumer-overridable with `ca65 -D` so a
;       64 MHz bracket raises the floor without a code change).
;
; Expiry of the bounded spin has no error channel in the primitive (the
; clause: SHOULD surface like a missing REU at init). We set the sticky
; byte `nistcurves_reu_dma_timeout` (src/data_shared.s) to 1 and proceed;
; a consumer that wants fail-closed behaviour tests it after init.
; =============================================================================

; SPEC v0.14.1 (non-normative, written against this file's #131 shape): a
; STRUCTURALLY met settle is the easiest one to lose -- the constraint lives
; in instructions unrelated to the REU, the natural optimisation shortens
; exactly that path, and no emulator reproduces the failure. So each hot
; site ASSERTS its distance rather than describing it. Byte distance along a
; straight-line 6502 path is a conservative cycle floor (every instruction
; costs at least as many cycles as it has bytes: 1 B -> 2 cy, 2 B -> >= 2 cy,
; 3 B -> >= 4 cy; a taken branch is 2 B / 3 cy), so `bytes >= floor` implies
; `cycles >= floor` on that path. The floor asserted is the 48 MHz one; the
; clock is in the name because 64 MHz is unbracketed (SPEC v0.13.0 §8.2) --
; if a 64 MHz bracket exceeds the hot sites' distance, switch them to the
; jsr form rather than raising this constant.
; Measured margins (2026-08-28, negative test by inflating the floor): the
; diagonal-squaring sites trip between 60 and 70 B (tightest), fp_mul's
; between 100 and 120, fp_sqr's between 120 and 140 -- in both curves.
; `.ifndef` so the negative test (ca65 -D REU_SETTLE_FLOOR_CYCLES_48MHZ=<n>)
; can prove the asserts fire and measure each site's margin; NOT a consumer
; knob -- the floor is a measurement, not a preference.
.ifndef REU_SETTLE_FLOOR_CYCLES_48MHZ
REU_SETTLE_FLOOR_CYCLES_48MHZ = 49
.endif

.macro REU_SETTLE_ASSERT_BYTES dist
        .assert (dist) >= REU_SETTLE_FLOOR_CYCLES_48MHZ, error, "SPEC v0.13.0 §8.2 (b): structural post-execute settle shorter than the 48 MHz floor (49 cy) -- use the jsr nistcurves_reu_dma_wait form at this site"
.endmacro

.macro REU_DMA_CONFIRM
.local @reu_done
        bit reu_status              ; V = bit 6 (END OF BLOCK); clears 5-7
        bvs @reu_done
        jsr nistcurves_reu_dma_wait ; not set: bounded spin + settle
@reu_done:
.endmacro
