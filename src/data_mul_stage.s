.setcpu "6502"

; =============================================================================
; data_mul_stage.s — the SPEC §8.2 staging buffers, alone.
;
; `nistcurves_mul_dma_lo` / `_hi` are the page-aligned pair the per-row REU
; fetch lands in. They are an APP_OWNED surface: a consumer that supplies the
; multiply tables itself under §8.0/§8.3 defines and places these two pages in
; its own tree, and §8.2 lets it place them here instead via
; LIB_SHARED_REU_MUL_STAGE_LO/_HI.
;
; SPEC §6.1 (member isolation) is why they are alone. Quoting the CURRENT text,
; as of the frozen v1.2.2 tag, because the wording moved twice after the clause
; landed at 1.2.0 and the differences decide this file:
;
;   "A symbol a consumer may displace -- suppress under LIB_NO_BARE_EXPORTS, or
;    define itself under APP_OWNED (§8.0) -- MUST live in a translation unit
;    that exports nothing else a consumer may import -- other displaceable
;    names included, their own prefixed counterparts excepted -- and defines
;    nothing else the library's own code references."
;
; Both amendments matter here, which is why the tag is worth stating:
;   1.2.1 added "their own prefixed counterparts excepted". Without it this
;         file would be non-conformant against its own header comment, since it
;         exports bare `mul_dma_lo`/`_hi` beside the prefixed names they alias.
;   1.2.2 added "or with the identical bare name a sibling library exports" to
;         the rationale, naming the library-versus-library direction as well as
;         the consumer-versus-library one. That is the direction that applies to
;         the bare `mul_` aliases below: `mul_` is registered to c64-x25519 in
;         the §2 registry, so a sibling can export the identical names with no
;         consumer definition involved anywhere.
;
; ld65 links whole members, so any library-private symbol sharing this TU
; drags it into a link that already has the consumer's own definitions, and
; ld65 refuses:
;
;   ld65: Error: Duplicate external identifier: 'nistcurves_mul_dma_hi'
;
; That failure cost c64-https every one of its shipped configurations on
; v0.12.0 (issue #149), where the culprit was the §8.2 settle state; splitting
; that into src/data_reu_wait.s was necessary but NOT sufficient. The multiply
; operand cache (`nistcurves_mul_cached_a` / `_src2_buf`) stayed behind in the
; same TU, and fp256.o / fp384.o / mul_8x8.o all import it -- so a consumer
; that owned the buffers AND called any field operation still pulled the
; member and still hit the identical error. It now lives in data_shared.s and
; this file holds the displaceable pair and nothing else.
;
; `make check-archives` links a stand-in consumer -- one that defines both
; buffers AND calls a field op -- against the app-owned and onchip archives to
; keep it that way.
;
; Do not add anything to this file.
; =============================================================================

; --- SPEC §8.2 staging-buffer placement ---
; A consumer supplying LIB_SHARED_REU_MUL_STAGE_LO/_HI through
; CONTRACT_DEFINES places these two pages: the labels become equates at the
; consumer's addresses and this TU allocates nothing, so the override moves the
; bytes the fetch writes and the bytes fp_mul/fp_sqr read -- not merely the
; number reu_config.s exports. That distinction is what §8.2's "the exported
; value MUST be the value the code reads" is about. Without the knobs the
; library allocates them itself, page-aligned via LIB_NISTCURVES_TABLES.
;
; NOT RE-ENTRANT: shared between the P-256 and P-384 field paths. See the
; re-entrancy note in data_shared.s.
;
; §6.5 rename window: `mul_` is registered to c64-x25519 in the §2 registry, so
; the canonical names carry this library's prefix. The bare names are
; same-address aliases, export-gated under -D LIB_NO_BARE_EXPORTS=1, and go at
; the next MAJOR.
.export nistcurves_mul_dma_lo
.export nistcurves_mul_dma_hi
.ifndef LIB_NO_BARE_EXPORTS
.export mul_dma_lo
.export mul_dma_hi
.endif

.ifdef LIB_SHARED_REU_MUL_STAGE_LO
nistcurves_mul_dma_lo = LIB_SHARED_REU_MUL_STAGE_LO
nistcurves_mul_dma_hi = LIB_SHARED_REU_MUL_STAGE_HI
.else
.segment "LIB_NISTCURVES_TABLES"
nistcurves_mul_dma_lo:
        .res 256, 0           ; DMA target: lo bytes of a*b for current a
nistcurves_mul_dma_hi:
        .res 256, 0           ; DMA target: hi bytes of a*b for current a
.endif

mul_dma_lo = nistcurves_mul_dma_lo
mul_dma_hi = nistcurves_mul_dma_hi

; --- SPEC §8.2 prefixed OUTPUT counterparts ---
; The bare LIB_SHARED_REU_MUL_STAGE_* knobs are consumer INPUT and must not be
; exported (§8.2 export discipline: every adopter derives the same names, so an
; export is a collision in any composed link). These prefixed counterparts
; publish where the row actually lands, so a consumer can assert that two
; co-linked §8.2 libraries agree on the landing page.
;
; Defined HERE rather than in reu_config.s deliberately. Deriving them there
; needed `.global nistcurves_mul_dma_lo`, which gave reu_config.o -- previously
; a pure equate TU with zero imports -- a link-time dependency on this member.
; A consumer importing nothing but a §3 bank equate then pulled 512 B of
; buffers and four `mul_*` names registered to another library, uninvited. The
; labels live in this file, so the aliases belong in this file.
LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO := nistcurves_mul_dma_lo
LIB_NISTCURVES_SHARED_REU_MUL_STAGE_HI := nistcurves_mul_dma_hi
.export LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO
.export LIB_NISTCURVES_SHARED_REU_MUL_STAGE_HI

; Asserted on the LABELS, so they hold for the library's own allocation and for
; a consumer override alike. `lderror`: with an override these are constants
; and ca65 could fold them, but without one they are link-time addresses.
;
; These catch a malformed pair. They CANNOT catch a well-formed pair pointed at
; occupied memory -- see the placement warning in src/nistcurves.inc and
; cfg/nistcurves-example.cfg. ld65 does not know this window exists, exactly as
; it does not know about the sqtab window.
.assert (nistcurves_mul_dma_lo & $00ff) = 0, lderror, "reu_mul stage_lo must be page-aligned (SPEC §8.2)"
.assert nistcurves_mul_dma_hi = nistcurves_mul_dma_lo + $0100, lderror, "reu_mul stage_hi must follow stage_lo by $0100 (SPEC §8.2)"
